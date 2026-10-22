package store

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/model"
)

// 配置读写在当前事务回读身份，并与用户权限变更使用同一租户锁。
func configurationActor(ctx context.Context, tx pgx.Tx, u model.Principal, write bool, permission error) error {
	if !contract.ValidID(u.TenantID) || !contract.ValidID(u.ID) || u.Role != "admin" && u.Role != "viewer" || write && u.Role != "admin" {
		return permission
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared(hashtextextended($1,0))`, u.TenantID+"/users"); err != nil {
		return err
	}
	var active, tenantActive bool
	var role string
	var revision int64
	if err := tx.QueryRow(ctx, `SELECT u.active,u.role,u.revision,t.active FROM users u JOIN tenants t ON t.id=u.tenant_id WHERE u.tenant_id=$1 AND u.id=$2`, u.TenantID, u.ID).Scan(&active, &role, &revision, &tenantActive); err != nil {
		return err
	}
	if !active || !tenantActive || role != u.Role || u.CredentialRevision > 0 && revision != u.CredentialRevision {
		return permission
	}
	return nil
}
