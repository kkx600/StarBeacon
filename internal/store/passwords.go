package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/accounts"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/model"
	"golang.org/x/crypto/bcrypt"
)

func validPasswordActor(u model.Principal) bool {
	return contract.ValidID(u.ID) && contract.ValidID(u.TenantID) && accounts.ValidRole(u.Role) && u.CredentialRevision >= 1 && u.CredentialRevision <= accounts.MaxRevision
}

func (p *Postgres) PasswordAccount(ctx context.Context, u model.Principal) (accounts.Record, error) {
	var record accounts.Record
	if !validPasswordActor(u) {
		return record, accounts.ErrUnavailable
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		var err error
		record, err = userRow(tx.QueryRow(ctx, `SELECT u.id,u.username,u.role,u.active,u.revision,u.created_at,u.updated_at FROM users u JOIN tenants t ON t.id=u.tenant_id WHERE u.tenant_id=$1 AND u.id=$2 AND u.active AND t.active AND u.role=$3 AND u.revision=$4`, u.TenantID, u.ID, u.Role, u.CredentialRevision))
		if errors.Is(err, pgx.ErrNoRows) {
			return accounts.ErrUnavailable
		}
		return err
	})
	return record, err
}

// 验证预算独立提交，错误密码和后续事务失败都不能撤销已消耗的次数。
func (p *Postgres) passwordAttempt(ctx context.Context, u model.Principal) (string, error) {
	var hash string
	var attempts int
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT u.password_hash FROM users u JOIN tenants t ON t.id=u.tenant_id WHERE u.tenant_id=$1 AND u.id=$2 AND u.active AND t.active AND u.role=$3 AND u.revision=$4`, u.TenantID, u.ID, u.Role, u.CredentialRevision).Scan(&hash); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return accounts.ErrUnavailable
			}
			return err
		}
		return tx.QueryRow(ctx, `INSERT INTO password_attempts(tenant_id,user_id,attempts) VALUES($1,$2,1) ON CONFLICT(tenant_id,user_id) DO UPDATE SET attempts=CASE WHEN password_attempts.window_started<=clock_timestamp()-interval '60 seconds' THEN 1 ELSE LEAST(password_attempts.attempts+1,11) END,window_started=CASE WHEN password_attempts.window_started<=clock_timestamp()-interval '60 seconds' THEN clock_timestamp() ELSE password_attempts.window_started END RETURNING attempts`, u.TenantID, u.ID).Scan(&attempts)
	})
	if err != nil {
		return "", err
	}
	if attempts > 10 {
		return "", accounts.ErrPasswordRate
	}
	return hash, nil
}

func (p *Postgres) ChangePassword(ctx context.Context, u model.Principal, id, key string, input accounts.PasswordChange) (accounts.Record, error) {
	var result accounts.Record
	if input.Validate() != nil || !contract.ValidID(id) || !contract.ValidID(key) {
		return result, accounts.ErrInput
	}
	if !validPasswordActor(u) || u.ID != id && u.Role != "admin" {
		return result, accounts.ErrUnavailable
	}
	actorHash, err := p.passwordAttempt(ctx, u)
	if err != nil {
		return result, err
	}
	if bcrypt.CompareHashAndPassword([]byte(actorHash), []byte(input.CurrentPassword)) != nil {
		if err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
			meta := model.RequestMetadataFrom(ctx)
			_, err := tx.Exec(ctx, `INSERT INTO operation_audits(tenant_id,user_id,action,object_id,request_id,source_ip,user_agent,expires_at) VALUES($1,$2,'users.password.denied',$2,$3,$4,$5,now()+make_interval(days=>COALESCE((SELECT days FROM retention_policies WHERE tenant_id=$1 AND category='operations'),180)))`, u.TenantID, u.ID, meta.RequestID, meta.SourceIP, meta.UserAgent)
			return err
		}); err != nil {
			return result, err
		}
		return result, accounts.ErrPassword
	}
	inputHash := Hash(id + "\x00" + strconv.FormatInt(input.ExpectedRevision, 10))
	var encoded []byte
	// 摘要计算不持有用户资源锁。原回执仅比较摘要，不重复生成；
	// 并发原键提交改变快照时最多重读三次，不将未知结果当作新操作。
	for attempt := 0; attempt < 3; attempt++ {
		snapshot, err := p.passwordSnapshot(ctx, u, id, key, inputHash, input.ExpectedRevision)
		if err != nil {
			return result, err
		}
		if snapshot.hasReceipt {
			if bcrypt.CompareHashAndPassword([]byte(snapshot.targetHash), []byte(input.NewPassword)) != nil {
				return result, ErrConflict
			}
		} else if u.ID == id {
			// 当前密码已验证且参数禁止新旧密码相同，同一身份无需再比较同一摘要。
			if snapshot.targetHash != actorHash {
				return result, ErrConflict
			}
			if len(encoded) == 0 {
				encoded, err = bcrypt.GenerateFromPassword([]byte(input.NewPassword), bcrypt.DefaultCost)
				if err != nil {
					return result, err
				}
			}
		} else {
			var encodeErr error
			done := make(chan struct{})
			// 重置他人密码的两项独立摘要计算同时完成，仍使用既定加密强度。
			// 等待两项计算结束后才进入事务，凭据不进入幂等材料或审计。
			go func() {
				defer close(done)
				if len(encoded) == 0 {
					encoded, encodeErr = bcrypt.GenerateFromPassword([]byte(input.NewPassword), bcrypt.DefaultCost)
				}
			}()
			reused := bcrypt.CompareHashAndPassword([]byte(snapshot.targetHash), []byte(input.NewPassword)) == nil
			<-done
			if encodeErr != nil {
				return result, encodeErr
			}
			if reused {
				return result, accounts.ErrInput
			}
		}
		err = p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, u.TenantID+"/users"); err != nil {
				return err
			}
			var currentActorHash string
			if err := tx.QueryRow(ctx, `SELECT u.password_hash FROM users u JOIN tenants t ON t.id=u.tenant_id WHERE u.tenant_id=$1 AND u.id=$2 AND u.active AND t.active AND u.role=$3 AND u.revision=$4`, u.TenantID, u.ID, u.Role, u.CredentialRevision).Scan(&currentActorHash); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return accounts.ErrUnavailable
				}
				return err
			}
			if actorHash != currentActorHash {
				return ErrConflict
			}
			var previousHash string
			var raw []byte
			var expires time.Time
			err := tx.QueryRow(ctx, `SELECT input_hash,record,expires_at FROM user_management_requests WHERE tenant_id=$1 AND created_by=$2 AND operation='password' AND key_hash=$3`, u.TenantID, u.ID, Hash(key)).Scan(&previousHash, &raw, &expires)
			if err == nil {
				if previousHash != inputHash {
					return ErrConflict
				}
				if !expires.After(time.Now()) {
					return accounts.ErrExpired
				}
				if json.Unmarshal(raw, &result) != nil || result.Validate() != nil || result.ID != id || result.Revision != input.ExpectedRevision+1 {
					return errors.New("密码操作回执校验失败")
				}
				var hash string
				if err := tx.QueryRow(ctx, `SELECT password_hash FROM users WHERE tenant_id=$1 AND id=$2`, u.TenantID, id).Scan(&hash); err != nil {
					return err
				}
				if !snapshot.hasReceipt || hash != snapshot.targetHash || previousHash != snapshot.receiptHash || !bytes.Equal(raw, snapshot.receipt) || !expires.Equal(snapshot.expires) {
					return errPasswordSnapshotChanged
				}
				return nil
			}
			if !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
			if snapshot.hasReceipt {
				return accounts.ErrExpired
			}
			var count int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM user_management_requests WHERE tenant_id=$1 AND created_at>=date_trunc('day',now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'`, u.TenantID).Scan(&count); err != nil {
				return err
			}
			if count >= 1000 {
				return accounts.ErrQuota
			}
			var targetHash string
			var targetRevision int64
			if err := tx.QueryRow(ctx, `SELECT password_hash,revision FROM users WHERE tenant_id=$1 AND id=$2`, u.TenantID, id).Scan(&targetHash, &targetRevision); err != nil {
				return err
			}
			if targetHash != snapshot.targetHash || targetRevision != snapshot.targetRevision {
				return ErrConflict
			}
			meta := model.RequestMetadataFrom(ctx)
			auditContext, _ := json.Marshal(map[string]string{"request_id": meta.RequestID, "source_ip": meta.SourceIP, "user_agent": meta.UserAgent})
			result, err = userRow(tx.QueryRow(ctx, `SELECT id,username,role,active,revision,created_at,updated_at FROM public.change_tenant_password($1,$2,$3,$4,$5,$6,$7,$8)`, u.ID, u.CredentialRevision, actorHash, id, input.ExpectedRevision, string(encoded), key, auditContext))
			if err != nil {
				return userWriteError(err)
			}
			raw, err = json.Marshal(result)
			if err != nil {
				return err
			}
			_, err = tx.Exec(ctx, `INSERT INTO user_management_requests(tenant_id,created_by,operation,key_hash,input_hash,user_id,record,expires_at) VALUES($1,$2,'password',$3,$4,$5,$6,now()+make_interval(days=>COALESCE((SELECT days FROM retention_policies WHERE tenant_id=$1 AND category='operations'),180)))`, u.TenantID, u.ID, Hash(key), inputHash, result.ID, raw)
			return userWriteError(err)
		})
		if !errors.Is(err, errPasswordSnapshotChanged) {
			return result, err
		}
	}
	return accounts.Record{}, ErrConflict
}

var errPasswordSnapshotChanged = errors.New("密码操作快照已变化")

type passwordChangeSnapshot struct {
	targetHash     string
	targetRevision int64
	hasReceipt     bool
	receiptHash    string
	receipt        []byte
	expires        time.Time
}

func (p *Postgres) passwordSnapshot(ctx context.Context, u model.Principal, id, key, inputHash string, revision int64) (passwordChangeSnapshot, error) {
	var snapshot passwordChangeSnapshot
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		// 目标与原回执在同一个语句快照读取，不能混用并发提交前后的修订。
		err := tx.QueryRow(ctx, `SELECT u.password_hash,u.revision,r.key_hash IS NOT NULL,COALESCE(r.input_hash,''),COALESCE(r.record,'null'::jsonb),COALESCE(r.expires_at,'epoch'::timestamptz) FROM users u LEFT JOIN user_management_requests r ON r.tenant_id=u.tenant_id AND r.created_by=$2 AND r.operation='password' AND r.key_hash=$4 WHERE u.tenant_id=$1 AND u.id=$3`, u.TenantID, u.ID, id, Hash(key)).Scan(&snapshot.targetHash, &snapshot.targetRevision, &snapshot.hasReceipt, &snapshot.receiptHash, &snapshot.receipt, &snapshot.expires)
		if err != nil {
			return err
		}
		if snapshot.hasReceipt {
			if snapshot.receiptHash != inputHash {
				return ErrConflict
			}
			if !snapshot.expires.After(time.Now()) {
				return accounts.ErrExpired
			}
			var record accounts.Record
			if json.Unmarshal(snapshot.receipt, &record) != nil || record.Validate() != nil || record.ID != id || record.Revision != revision+1 {
				return errors.New("密码操作回执校验失败")
			}
		}
		if !snapshot.hasReceipt && snapshot.targetRevision != revision {
			return ErrConflict
		}
		return nil
	})
	return snapshot, err
}
