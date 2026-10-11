package store

import (
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
	// bcrypt 计算在资源锁之前完成，密码不进入公开幂等材料或审计。
	encoded, err := bcrypt.GenerateFromPassword([]byte(input.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return result, err
	}
	inputHash := Hash(id + "\x00" + strconv.FormatInt(input.ExpectedRevision, 10))
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
			if bcrypt.CompareHashAndPassword([]byte(hash), []byte(input.NewPassword)) != nil {
				return ErrConflict
			}
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		var count int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM user_management_requests WHERE tenant_id=$1 AND created_at>=date_trunc('day',now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'`, u.TenantID).Scan(&count); err != nil {
			return err
		}
		if count >= 1000 {
			return accounts.ErrQuota
		}
		var targetHash string
		if err := tx.QueryRow(ctx, `SELECT password_hash FROM users WHERE tenant_id=$1 AND id=$2`, u.TenantID, id).Scan(&targetHash); err != nil {
			return err
		}
		if bcrypt.CompareHashAndPassword([]byte(targetHash), []byte(input.NewPassword)) == nil {
			return accounts.ErrInput
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
	return result, err
}
