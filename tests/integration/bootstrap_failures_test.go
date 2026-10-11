//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/admin"
	"github.com/kkx600/StarBeacon/internal/store"
)

func TestBootstrapAndPrivilegeTransactionsRollbackOnDisconnect(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f := newIsolatedDatabase(t, ctx)
	password := store.Token()
	for _, prefix := range []string{"INSERT INTO tenants", "INSERT INTO users", "INSERT INTO retention_policies"} {
		t.Run("bootstrap/"+prefix, func(t *testing.T) {
			tenant := store.RandomID("it_bootstrap_fault_")
			db, tracer := disconnectedStore(t, ctx, f.OwnerDSN, prefix)
			if e := admin.Bootstrap(ctx, db, tenant, "初始化验收", tenant, password, "admin"); e == nil || !tracer.fired.Load() {
				t.Fatal("初始化事务故障被当作成功", e)
			}
			var tenants, users, policies int
			require(t, f.Owner.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
				return tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM tenants WHERE id=$1),(SELECT count(*) FROM users WHERE tenant_id=$1),(SELECT count(*) FROM retention_policies WHERE tenant_id=$1)`, tenant).Scan(&tenants, &users, &policies)
			}))
			if tenants != 0 || users != 0 || policies != 0 {
				t.Fatal("初始化留下半成品租户、账号或留存策略")
			}
		})
	}
	db, tracer := disconnectedStore(t, ctx, f.OwnerDSN, "SELECT u.id,u.tenant_id")
	if e := admin.BootstrapIfMissing(ctx, db, "tenant_owned", "初始化验收", "user_owned", password, "admin"); e == nil || !tracer.fired.Load() {
		t.Fatal("账号读取失败被当作不存在并覆盖", e)
	}
	for _, prefix := range []string{
		"begin", "SELECT EXISTS(SELECT 1 FROM pg_roles", "SELECT current_database()", "GRANT CONNECT ON DATABASE",
		"GRANT USAGE ON SCHEMA public", "GRANT SELECT,INSERT,UPDATE ON sensor_tasks", "GRANT SELECT,INSERT,UPDATE ON inventory_objects",
		"GRANT SELECT,INSERT,UPDATE ON notification_channels", "GRANT SELECT,INSERT,UPDATE ON model_providers",
		"GRANT SELECT,INSERT,UPDATE ON analysis_threads", "GRANT UPDATE ON retention_policies", "GRANT SELECT,INSERT,UPDATE,DELETE ON mcp_bindings",
		"GRANT DELETE ON operation_audits", "commit",
	} {
		t.Run("privilege/"+prefix, func(t *testing.T) {
			fault, tracer := disconnectedStore(t, ctx, f.OwnerDSN, prefix)
			if e := admin.CreateRuntimeRole(ctx, fault, password); e == nil || !tracer.fired.Load() {
				t.Fatal("权限初始化故障未执行或被隐藏", e)
			}
			require(t, f.Runtime.VerifyRuntimeRole(ctx))
		})
	}
	if e := admin.CreateRuntimeRole(ctx, f.Owner, "short"); e == nil {
		t.Fatal("过短运行凭据未拒绝")
	}
	// 恢复后可完整初始化；不中断或轮换共享运行账号。
	tenant := store.RandomID("it_bootstrap_recovered_")
	require(t, admin.BootstrapIfMissing(ctx, f.Owner, tenant, "初始化恢复验收", tenant, password, "admin"))
	require(t, admin.BootstrapIfMissing(ctx, f.Owner, tenant, "初始化恢复验收", tenant, password, "admin"))
	if e := admin.BootstrapIfMissing(ctx, f.Owner, tenant, "初始化恢复验收", tenant, password, "viewer"); e == nil {
		t.Fatal("已有管理员被不同角色覆盖")
	}
}
