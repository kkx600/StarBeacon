package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/accounts"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/store"
	"golang.org/x/crypto/bcrypt"
)

type RecoveryInput struct {
	TenantID, UserID, RequestID, Reason, NewPassword string
	ExpectedRevision                                 int64
}

func (r RecoveryInput) Validate() error {
	if !contract.ValidID(r.TenantID) || !contract.ValidID(r.UserID) || !contract.ValidID(r.RequestID) || r.ExpectedRevision < 1 || r.ExpectedRevision >= accounts.MaxRevision || !accounts.ValidPassword(r.NewPassword) || !utf8.ValidString(r.Reason) || len(r.Reason) < 3 || len(r.Reason) > 512 || strings.TrimSpace(r.Reason) != r.Reason || strings.Contains(r.Reason, r.NewPassword) || strings.IndexFunc(r.Reason, func(v rune) bool { return unicode.IsControl(v) || unicode.Is(unicode.Cf, v) }) >= 0 {
		return accounts.ErrInput
	}
	return nil
}

type RecoveryResult struct {
	Account       accounts.Record `json:"account"`
	RequestID     string          `json:"request_id"`
	DatabaseActor string          `json:"database_actor"`
	Reason        string          `json:"reason"`
	Confirmed     bool            `json:"confirmed"`
}

func recoveryActor(ctx context.Context, tx pgx.Tx) (string, error) {
	var actor string
	var allowed bool
	err := tx.QueryRow(ctx, `SELECT session_user::text,
 current_user<> 'starbeacon_app' AND session_user<> 'starbeacon_app'
 AND pg_has_role(current_user,c.relowner,'USAGE') AND pg_has_role(session_user,c.relowner,'USAGE')
 AND has_table_privilege(current_user,'public.users','UPDATE')
 AND has_table_privilege(current_user,'public.sessions','DELETE')
 AND has_table_privilege(current_user,'public.operation_audits','INSERT')
 FROM pg_class c WHERE c.oid='public.users'::regclass`).Scan(&actor, &allowed)
	if err != nil {
		return "", err
	}
	if !allowed {
		return "", accounts.ErrUnavailable
	}
	return actor, nil
}

// 离线核对只返回指定有效管理员的公开记录，不读取或显示凭据摘要。
func InspectAdministrator(ctx context.Context, db *store.Postgres, tenant, username string) (accounts.Record, error) {
	var record accounts.Record
	if !contract.ValidID(tenant) || !accounts.ValidUsername(username) {
		return record, accounts.ErrInput
	}
	err := db.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		if _, err := recoveryActor(ctx, tx); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT u.id,u.username,u.role,u.active,u.revision,u.created_at,u.updated_at FROM users u JOIN tenants t ON t.id=u.tenant_id WHERE u.tenant_id=$1 AND u.username=$2 AND u.active AND u.role='admin' AND t.active`, tenant, username).Scan(&record.ID, &record.Username, &record.Role, &record.Active, &record.Revision, &record.CreatedAt, &record.UpdatedAt); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return accounts.ErrUnavailable
			}
			return err
		}
		return record.Validate()
	})
	if err != nil {
		return accounts.Record{}, err
	}
	return record, nil
}

// 恢复凭据只从私有普通文件或环境读取，不支持命令行参数或终端回显。
func RecoveryPassword(value, path string) (string, error) {
	invalid := errors.New("恢复密码须由 SB_RECOVERY_PASSWORD 或权限为 0400／0600 的 SB_RECOVERY_PASSWORD_FILE 单独提供")
	if value != "" && path != "" {
		return "", invalid
	}
	if path != "" {
		before, err := os.Lstat(path)
		if err != nil || !before.Mode().IsRegular() || before.Mode().Perm() != 0400 && before.Mode().Perm() != 0600 || before.Size() > 74 {
			return "", invalid
		}
		file, err := os.Open(path)
		if err != nil {
			return "", invalid
		}
		defer file.Close()
		after, err := file.Stat()
		if err != nil || !os.SameFile(before, after) || !after.Mode().IsRegular() || after.Mode().Perm() != before.Mode().Perm() || after.Size() > 74 {
			return "", invalid
		}
		raw, err := io.ReadAll(io.LimitReader(file, 75))
		defer clear(raw)
		if err != nil || len(raw) > 74 {
			return "", invalid
		}
		value = strings.TrimSuffix(strings.TrimSuffix(string(raw), "\n"), "\r")
	}
	if !accounts.ValidPassword(value) {
		return "", invalid
	}
	return value, nil
}

// 该入口要求实际数据库所有者权限。运行角色的受控函数权限不能用于离线恢复。
func RecoverAdministrator(ctx context.Context, db *store.Postgres, input RecoveryInput) (RecoveryResult, error) {
	var result RecoveryResult
	if err := input.Validate(); err != nil {
		return result, err
	}
	public, _ := json.Marshal(struct {
		UserID, RequestID, Reason string
		ExpectedRevision          int64
	}{input.UserID, input.RequestID, input.Reason, input.ExpectedRevision})
	fingerprint := store.Hash(string(public))
	err := db.TenantTx(ctx, input.TenantID, func(tx pgx.Tx) error {
		actor, err := recoveryActor(ctx, tx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, input.TenantID+"/users"); err != nil {
			return err
		}
		var account accounts.Record
		var priorHash string
		if err := tx.QueryRow(ctx, `SELECT u.id,u.username,u.role,u.active,u.revision,u.created_at,u.updated_at,u.password_hash FROM users u JOIN tenants t ON t.id=u.tenant_id WHERE u.tenant_id=$1 AND u.id=$2 AND u.active AND u.role='admin' AND t.active FOR UPDATE OF u,t`, input.TenantID, input.UserID).Scan(&account.ID, &account.Username, &account.Role, &account.Active, &account.Revision, &account.CreatedAt, &account.UpdatedAt, &priorHash); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return accounts.ErrUnavailable
			}
			return err
		}
		if err := account.Validate(); err != nil {
			return err
		}
		var savedHash string
		var receipt []byte
		var expired bool
		creator := "database:" + actor
		err = tx.QueryRow(ctx, `SELECT input_hash,record,expires_at<=now() FROM user_management_requests WHERE tenant_id=$1 AND created_by=$2 AND operation='password' AND key_hash=$3`, input.TenantID, creator, store.Hash(input.RequestID)).Scan(&savedHash, &receipt, &expired)
		if err == nil {
			if expired {
				return accounts.ErrExpired
			}
			if savedHash != fingerprint || contract.JSONFields(string(receipt), []string{"account", "request_id", "database_actor", "reason", "confirmed", "id", "username", "role", "active", "revision", "created_at", "updated_at"}, 8192) != nil || json.Unmarshal(receipt, &result) != nil || result.Account.Validate() != nil || result.Account.ID != input.UserID || result.Account.Revision != input.ExpectedRevision+1 || result.DatabaseActor != actor || result.RequestID != input.RequestID || result.Reason != input.Reason || result.Confirmed || account.ID != result.Account.ID || account.Username != result.Account.Username || account.Role != result.Account.Role || account.Active != result.Account.Active || account.Revision != result.Account.Revision || !account.CreatedAt.Equal(result.Account.CreatedAt) || !account.UpdatedAt.Equal(result.Account.UpdatedAt) || bcrypt.CompareHashAndPassword([]byte(priorHash), []byte(input.NewPassword)) != nil {
				return store.ErrConflict
			}
			result.Confirmed = true
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if account.Revision != input.ExpectedRevision {
			return store.ErrConflict
		}
		if bcrypt.CompareHashAndPassword([]byte(priorHash), []byte(input.NewPassword)) == nil {
			return accounts.ErrInput
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(input.NewPassword), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `UPDATE users SET password_hash=$1,revision=revision+1,updated_at=clock_timestamp() WHERE tenant_id=$2 AND id=$3 AND revision=$4 RETURNING revision,updated_at`, string(hash), input.TenantID, input.UserID, input.ExpectedRevision).Scan(&account.Revision, &account.UpdatedAt); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM sessions WHERE user_id=$1`, input.UserID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO operation_audits(tenant_id,user_id,action,object_id,request_id,source_ip,user_agent,reason,expires_at) VALUES($1,$2,'users.password.recover',$3,$4,'','starbeaconctl',$5,now()+make_interval(days=>COALESCE((SELECT days FROM retention_policies WHERE tenant_id=$1 AND category='operations'),180)))`, input.TenantID, creator, input.UserID, input.RequestID, input.Reason); err != nil {
			return err
		}
		result = RecoveryResult{Account: account, RequestID: input.RequestID, DatabaseActor: actor, Reason: input.Reason}
		raw, _ := json.Marshal(result)
		_, err = tx.Exec(ctx, `INSERT INTO user_management_requests(tenant_id,created_by,operation,key_hash,input_hash,user_id,record,expires_at) VALUES($1,$2,'password',$3,$4,$5,$6,now()+make_interval(days=>COALESCE((SELECT days FROM retention_policies WHERE tenant_id=$1 AND category='operations'),180)))`, input.TenantID, creator, store.Hash(input.RequestID), fingerprint, input.UserID, raw)
		return err
	})
	if err != nil {
		return RecoveryResult{}, err
	}
	return result, nil
}

func RecoveryFailure(err error) error {
	// 数据库或文件诊断不得随管理入口错误回显连接凭据、密码及内部查询参数。
	if errors.Is(err, accounts.ErrInput) || errors.Is(err, accounts.ErrUnavailable) || errors.Is(err, accounts.ErrExpired) || errors.Is(err, store.ErrConflict) {
		return err
	}
	return fmt.Errorf("管理员恢复未确认，请核对同一请求的账号修订与审计记录")
}
