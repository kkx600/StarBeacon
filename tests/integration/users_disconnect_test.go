//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/accounts"
	"github.com/kkx600/StarBeacon/internal/store"
)

func accountState(t *testing.T, ctx context.Context, owner *store.Postgres, tenant string) string {
	t.Helper()
	state := map[string]json.RawMessage{}
	for _, table := range []string{"users", "user_management_requests", "operation_audits"} {
		var raw []byte
		require(t, owner.Pool.QueryRow(ctx, `SELECT COALESCE(jsonb_agg(to_jsonb(v) ORDER BY to_jsonb(v)::text),'[]'::jsonb) FROM `+pgx.Identifier{table}.Sanitize()+` v WHERE tenant_id=$1`, tenant).Scan(&raw))
		state[table] = raw
	}
	var sessions []byte
	require(t, owner.Pool.QueryRow(ctx, `SELECT COALESCE(jsonb_agg(to_jsonb(s) ORDER BY to_jsonb(s)::text),'[]'::jsonb) FROM sessions s JOIN users u ON u.id=s.user_id WHERE u.tenant_id=$1`, tenant).Scan(&sessions))
	state["sessions"] = sessions
	raw, err := json.Marshal(state)
	require(t, err)
	return string(raw)
}

// 断开专属运行连接，让真实 PostgreSQL 回滚身份、会话、回执与审计的所有前缀写入。
func TestUserManagementDisconnectRollsBackIdentityAndSessions(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f, user, _, _ := accountFixture(t, ctx)
	active := true
	input := accounts.Create{Username: "disconnect_owned", Password: store.Token(), Role: "viewer", Active: &active}
	seed, err := f.Runtime.CreateUser(ctx, user, "seed_disconnect", input)
	require(t, err)
	principal, _, err := f.Runtime.Password(ctx, seed.Username)
	require(t, err)
	_, _, err = f.Runtime.CreateSession(ctx, principal)
	require(t, err)
	create := input
	create.Username = "disconnect_creation"
	inactive := false
	change := accounts.Change{ExpectedRevision: 1, Role: "viewer", Active: &inactive}
	for _, op := range []struct {
		name     string
		prefixes []string
		run      func(*store.Postgres) error
	}{
		{"list", []string{"SELECT EXISTS(SELECT 1 FROM users u", "SELECT EXISTS(SELECT 1 FROM users WHERE", "SELECT id,username,role,active"}, func(db *store.Postgres) error {
			_, e := db.Users(ctx, user, accounts.Query{Before: seed.ID})
			return e
		}},
		{"detail", []string{"SELECT EXISTS(SELECT 1 FROM users u", "SELECT id,username,role,active"}, func(db *store.Postgres) error {
			_, e := db.User(ctx, user, seed.ID)
			return e
		}},
		{"create", []string{"SELECT pg_advisory_xact_lock", "SELECT EXISTS(SELECT 1 FROM users u", "SELECT input_hash,user_id", "SELECT count(*) FROM user_management_requests", "SELECT count(*) FROM users WHERE", "SELECT id,username,role,active,revision,created_at,updated_at FROM public.save_tenant_user", "INSERT INTO user_management_requests"}, func(db *store.Postgres) error {
			_, e := db.CreateUser(ctx, user, "disconnect_create", create)
			return e
		}},
		{"change", []string{"SELECT id,username,role,active,revision,created_at,updated_at FROM public.save_tenant_user", "INSERT INTO user_management_requests"}, func(db *store.Postgres) error {
			_, e := db.ChangeUser(ctx, user, seed.ID, "disconnect_change", change)
			return e
		}},
		{"confirm_create", []string{"SELECT password_hash FROM users WHERE"}, func(db *store.Postgres) error {
			_, e := db.CreateUser(ctx, user, "seed_disconnect", input)
			return e
		}},
	} {
		for i, prefix := range op.prefixes {
			t.Run(fmt.Sprintf("%s/%02d", op.name, i), func(t *testing.T) {
				before := accountState(t, ctx, f.Owner, user.TenantID)
				db, tracer := disconnectedStore(t, ctx, f.RuntimeDSN, prefix)
				if e := op.run(db); e == nil || !tracer.fired.Load() {
					t.Fatal("专属连接故障没有阻止用户操作", e)
				}
				if accountState(t, ctx, f.Owner, user.TenantID) != before {
					t.Fatal("失败用户事务留下身份、会话、回执或审计变更")
				}
			})
		}
	}
	// 管理列表不能把损坏的身份字段静默呈现为有效账号。
	_, err = f.Owner.Pool.Exec(ctx, `UPDATE users SET username=$2 WHERE id=$1`, seed.ID, "invalid\u200didentity")
	require(t, err)
	if _, err := f.Runtime.User(ctx, user, seed.ID); err == nil {
		t.Fatal("用户详情接受了损坏的身份记录")
	}
	if _, err := f.Runtime.Users(ctx, user, accounts.Query{}); err == nil {
		t.Fatal("用户列表接受了损坏的身份记录")
	}
}
