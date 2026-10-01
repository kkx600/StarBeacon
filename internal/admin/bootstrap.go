package admin

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/store"
	"golang.org/x/crypto/bcrypt"
)

func Bootstrap(ctx context.Context, p *store.Postgres, tenant, name, username, password, role string) error {
	if !contract.ValidID(tenant) || len(username) < 3 || len(username) > 64 || len(password) < 12 || len(password) > 72 || (role != "admin" && role != "viewer") {
		return fmt.Errorf("租户、账号或密码格式不合法")
	}
	hash, e := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if e != nil {
		return e
	}
	return p.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, "INSERT INTO tenants(id,name) VALUES($1,$2) ON CONFLICT(id) DO NOTHING", tenant, name); e != nil {
			return e
		}
		if _, e := tx.Exec(ctx, "INSERT INTO users(id,tenant_id,username,password_hash,role) VALUES($1,$2,$3,$4,$5)", store.RandomID("user_"), tenant, username, string(hash), role); e != nil {
			return e
		}
		for _, category := range []string{"alerts", "pcap", "network", "operations", "logins", "notifications", "reports", "files"} {
			if _, e := tx.Exec(ctx, "INSERT INTO retention_policies(tenant_id,category,days) VALUES($1,$2,180) ON CONFLICT DO NOTHING", tenant, category); e != nil {
				return e
			}
		}
		return nil
	})
}
func BootstrapIfMissing(ctx context.Context, p *store.Postgres, tenant, name, username, password, role string) error {
	u, hash, e := p.Password(ctx, username)
	if e == nil {
		if u.TenantID != tenant || u.Role != role || bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
			return fmt.Errorf("账号已经存在且配置不匹配；不会重置密码")
		}
		return nil
	}
	if !errors.Is(e, model.ErrUnauthenticated) {
		return e
	}
	return Bootstrap(ctx, p, tenant, name, username, password, role)
}
func CreateRuntimeRole(ctx context.Context, p *store.Postgres, password string) error {
	if len(password) < 24 {
		return fmt.Errorf("运行账号密码长度不足")
	}
	tx, e := p.Pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	var exists bool
	if e = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='starbeacon_app')").Scan(&exists); e != nil {
		return e
	}
	if !exists {
		// 由 PostgreSQL format 的 %L 转义密码，避免将输入拼入角色 DDL。
		var ddl string
		if e = tx.QueryRow(ctx, "SELECT format('CREATE ROLE starbeacon_app LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD %L', $1::text)", password).Scan(&ddl); e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, ddl); e != nil {
			return e
		}
	}
	if _, e = tx.Exec(ctx, `GRANT CONNECT ON DATABASE starbeacon TO starbeacon_app;
		GRANT USAGE ON SCHEMA public TO starbeacon_app;
		GRANT SELECT ON tenants,users,retention_policies TO starbeacon_app;
		GRANT SELECT,INSERT,DELETE ON sessions TO starbeacon_app;
		GRANT SELECT,UPDATE ON sensors TO starbeacon_app;
		GRANT SELECT,INSERT,UPDATE ON routes TO starbeacon_app;
		GRANT SELECT,INSERT ON operation_audits TO starbeacon_app;
		GRANT INSERT ON login_audits TO starbeacon_app;
		GRANT USAGE ON SEQUENCE operation_audits_id_seq,login_audits_id_seq TO starbeacon_app`); e != nil {
		return e
	}
	return tx.Commit(ctx)
}
