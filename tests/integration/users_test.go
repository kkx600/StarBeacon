//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/kkx600/StarBeacon/internal/accounts"
	"github.com/kkx600/StarBeacon/internal/admin"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/platform"
	"github.com/kkx600/StarBeacon/internal/store"
	"golang.org/x/crypto/bcrypt"
)

func accountFixture(t *testing.T, ctx context.Context) (*isolatedDatabase, model.Principal, model.Principal, string) {
	t.Helper()
	f := newIsolatedDatabase(t, ctx)
	password := store.Token()
	for _, tenant := range []string{"users_owned_a", "users_owned_b"} {
		require(t, admin.Bootstrap(ctx, f.Owner, tenant, "用户权限验收", tenant, password, "admin"))
	}
	u, _, err := f.Runtime.Password(ctx, "users_owned_a")
	require(t, err)
	b, _, err := f.Runtime.Password(ctx, "users_owned_b")
	require(t, err)
	return f, u, b, password
}

// 真实登录、角色变更与会话撤销均在专属数据库中验证；账号不属于生产或人工用户。
func TestUserManagementHTTPRolesSessionsAndTenantIsolation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f, u, b, password := accountFixture(t, ctx)
	active := true
	a := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime}, u.Username, password)
	other := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime}, b.Username, password)
	input := accounts.Create{Username: "值班观察员", Password: store.Token(), Role: "viewer", Active: &active}
	var first, retry accounts.Record
	a.request("POST", "/users", "user_owned_create", input, &first, 200)
	if first.Validate() != nil || first.Revision != 1 {
		t.Fatal("创建用户回执无效")
	}
	a.request("POST", "/users", "user_owned_create", input, &retry, 200)
	if retry.ID != first.ID || !retry.CreatedAt.Equal(first.CreatedAt) {
		t.Fatal("重复创建或回执不稳定")
	}
	altered := input
	altered.Password = store.Token()
	a.request("POST", "/users", "user_owned_create", altered, nil, 409)
	altered = input
	altered.Role = "admin"
	a.request("POST", "/users", "user_owned_create", altered, nil, 409)
	a.request("POST", "/users", "user_duplicate_name", input, nil, 409)
	principal, hash, err := f.Runtime.Password(ctx, input.Username)
	require(t, err)
	require(t, bcrypt.CompareHashAndPassword([]byte(hash), []byte(input.Password)))
	if strings.Contains(hash, input.Password) {
		t.Fatal("密码未经过不可逆摘要")
	}
	viewer := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime}, input.Username, input.Password)
	for _, path := range []string{"/users", "/users/" + first.ID} {
		viewer.request("GET", path, "", nil, nil, 403)
	}
	viewer.request("PATCH", "/users/"+first.ID, "viewer_denied", accounts.Change{ExpectedRevision: 1, Role: "admin", Active: &active}, nil, 403)
	other.request("GET", "/users/"+first.ID, "", nil, nil, 404)
	other.request("PATCH", "/users/"+first.ID, "foreign_denied", accounts.Change{ExpectedRevision: 1, Role: "admin", Active: &active}, nil, 404)
	a.request("GET", "/users?before="+b.ID, "", nil, nil, 404)
	noCSRF := *a
	noCSRF.csrf = ""
	noCSRF.request("POST", "/users", "csrf_denied", input, nil, 403)
	a.request("POST", "/users", "", input, nil, 400)
	token, _, err := f.Runtime.CreateSession(ctx, principal)
	require(t, err)
	change := accounts.Change{ExpectedRevision: 1, Role: "admin", Active: &active}
	a.request("PATCH", "/users/"+first.ID, "user_promote", change, &retry, 200)
	if retry.Revision != 2 || retry.Role != "admin" {
		t.Fatal("角色变更没有生效")
	}
	if _, err := f.Runtime.Session(ctx, token); !errors.Is(err, model.ErrUnauthenticated) {
		t.Fatal("旧会话没有撤销", err)
	}
	viewer.request("GET", "/auth/me", "", nil, nil, 401)
	a.request("PATCH", "/users/"+first.ID, "user_promote", change, &retry, 200)
	if retry.Revision != 2 {
		t.Fatal("原请求确认产生重复变更")
	}
	a.request("PATCH", "/users/"+first.ID, "user_stale", change, nil, 409)
	change.ExpectedRevision = 2
	a.request("PATCH", "/users/"+first.ID, "user_no_change", change, nil, 400)
	active = false
	change.Active = &active
	a.request("PATCH", "/users/"+first.ID, "user_disable", change, &retry, 200)
	if retry.Active || retry.Revision != 3 {
		t.Fatal("停用状态没有生效")
	}
	if _, _, err := f.Runtime.Password(ctx, input.Username); !errors.Is(err, model.ErrUnauthenticated) {
		t.Fatal("停用用户仍能登录")
	}
	active = true
	change.ExpectedRevision = 3
	a.request("PATCH", "/users/"+first.ID, "user_enable", change, &retry, 200)
	if _, err := f.Runtime.Session(ctx, token); !errors.Is(err, model.ErrUnauthenticated) {
		t.Fatal("重新启用复活旧会话")
	}
	a.request("PATCH", "/users/"+u.ID, "user_demote_self", accounts.Change{ExpectedRevision: 1, Role: "viewer", Active: &active}, nil, 409)
	active = false
	a.request("PATCH", "/users/"+u.ID, "user_disable_self", accounts.Change{ExpectedRevision: 1, Role: "admin", Active: &active}, nil, 409)
	active = true
	var page accounts.Page
	a.request("GET", "/users?role=admin&active=true", "", nil, &page, 200)
	if len(page.Items) != 2 {
		t.Fatal("筛选或租户范围无效", len(page.Items))
	}
	var audits, receipts int
	var days float64
	var raw string
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT count(*),min(extract(epoch FROM expires_at-created_at)/86400),string_agg(record::text,'') FROM user_management_requests WHERE tenant_id=$1`, u.TenantID).Scan(&receipts, &days, &raw))
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT count(*) FROM operation_audits WHERE tenant_id=$1 AND action LIKE 'users.%'`, u.TenantID).Scan(&audits))
	if audits != 4 || receipts != 4 || days < 179 || strings.Contains(raw, "password") || strings.Contains(raw, input.Password) {
		t.Fatal("用户审计、默认留存或凭据隔离不正确", audits, receipts, days)
	}
	// 既有创建回执保持公开配置快照，后续角色变化不改写原请求的结果。
	a.request("POST", "/users", "user_owned_create", input, &retry, 200)
	if retry.Role != "viewer" || retry.Revision != 1 {
		t.Fatal("创建回执被当前用户覆盖")
	}
	_, err = f.Owner.Pool.Exec(ctx, `UPDATE retention_policies SET days=9 WHERE tenant_id=$1 AND category='operations'`, u.TenantID)
	require(t, err)
	input.Username = "自定义留存账号"
	a.request("POST", "/users", "user_custom_days", input, &retry, 200)
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT extract(epoch FROM expires_at-created_at)/86400 FROM user_management_requests WHERE tenant_id=$1 AND key_hash=$2`, u.TenantID, store.Hash("user_custom_days")).Scan(&days))
	if days < 8 || days > 10 {
		t.Fatal("用户管理留存未使用操作数据配置")
	}
	_, err = f.Owner.Pool.Exec(ctx, `UPDATE user_management_requests SET expires_at=now()-interval '1 second' WHERE tenant_id=$1 AND key_hash=$2`, u.TenantID, store.Hash("user_custom_days"))
	require(t, err)
	a.request("POST", "/users", "user_custom_days", input, nil, 410)
}

func TestUserManagementAtomicRollbackPrivilegesAndConcurrentAdministrators(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f, u, b, _ := accountFixture(t, ctx)
	active := true
	input := accounts.Create{Username: "rollback_owned", Password: store.Token(), Role: "viewer", Active: &active}
	var writable, executable, publicExecute bool
	var path string
	require(t, f.Runtime.Pool.QueryRow(ctx, `SELECT has_table_privilege(current_user,'public.users','INSERT,UPDATE,DELETE'),has_function_privilege(current_user,'public.save_tenant_user(text,text,text,text,text,boolean,bigint,text,jsonb)','EXECUTE')`).Scan(&writable, &executable))
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_proc p CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a WHERE p.oid='public.save_tenant_user(text,text,text,text,text,boolean,bigint,text,jsonb)'::regprocedure AND a.grantee=0 AND a.privilege_type='EXECUTE')`).Scan(&publicExecute))
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT array_to_string(proconfig,',') FROM pg_proc WHERE oid='public.save_tenant_user(text,text,text,text,text,boolean,bigint,text,jsonb)'::regprocedure`).Scan(&path))
	if writable || !executable || publicExecute || !strings.Contains(path, "pg_catalog, public, pg_temp") {
		t.Fatal("身份写入权限过宽或函数搜索路径不安全", writable, executable, publicExecute, path)
	}
	for _, table := range []string{"operation_audits", "user_management_requests"} {
		t.Run("rollback_"+table, func(t *testing.T) {
			_, err := f.Owner.Pool.Exec(ctx, `CREATE FUNCTION public.account_fault() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'owned_failure'; END$$;CREATE TRIGGER account_fault BEFORE INSERT ON `+table+` FOR EACH ROW EXECUTE FUNCTION public.account_fault()`)
			require(t, err)
			if _, err := f.Runtime.CreateUser(ctx, u, "rollback_"+table, input); err == nil {
				t.Fatal("持久化失败返回成功")
			}
			_, err = f.Owner.Pool.Exec(ctx, `DROP TRIGGER account_fault ON `+table+`;DROP FUNCTION public.account_fault()`)
			require(t, err)
			var n int
			require(t, f.Owner.Pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE username=$1`, input.Username).Scan(&n))
			if n != 0 {
				t.Fatal("前缀写入没有回滚")
			}
		})
	}
	target, err := f.Runtime.CreateUser(ctx, u, "rollback_target", input)
	require(t, err)
	principal, _, err := f.Runtime.Password(ctx, target.Username)
	require(t, err)
	token, _, err := f.Runtime.CreateSession(ctx, principal)
	require(t, err)
	_, err = f.Owner.Pool.Exec(ctx, `CREATE FUNCTION public.account_fault() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'owned_failure'; END$$;CREATE TRIGGER account_fault BEFORE INSERT ON user_management_requests FOR EACH ROW EXECUTE FUNCTION public.account_fault()`)
	require(t, err)
	active = false
	if _, err := f.Runtime.ChangeUser(ctx, u, target.ID, "rollback_revoke", accounts.Change{ExpectedRevision: 1, Role: "viewer", Active: &active}); err == nil {
		t.Fatal("回执失败返回成功")
	}
	_, err = f.Owner.Pool.Exec(ctx, `DROP TRIGGER account_fault ON user_management_requests;DROP FUNCTION public.account_fault()`)
	require(t, err)
	if _, err := f.Runtime.Session(ctx, token); err != nil {
		t.Fatal("事务失败仍撤销了原会话", err)
	}
	current, err := f.Runtime.User(ctx, u, target.ID)
	require(t, err)
	if !current.Active || current.Revision != 1 {
		t.Fatal("权限变更前缀未回滚")
	}
	active = true
	var stolen string
	err = f.Runtime.TenantTx(ctx, b.TenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT record::text FROM user_management_requests WHERE user_id=$1`, target.ID).Scan(&stolen)
	})
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("回执 RLS 穿透租户", err)
	}
	second, err := f.Runtime.CreateUser(ctx, u, "second_admin", accounts.Create{Username: "second_admin_owned", Password: store.Token(), Role: "admin", Active: &active})
	require(t, err)
	other, _, err := f.Runtime.Password(ctx, second.Username)
	require(t, err)
	results := make(chan error, 2)
	var group sync.WaitGroup
	for i, pair := range []struct {
		actor  model.Principal
		target string
	}{{u, other.ID}, {other, u.ID}} {
		group.Add(1)
		go func(i int, pair struct {
			actor  model.Principal
			target string
		}) {
			defer group.Done()
			_, err := f.Runtime.ChangeUser(ctx, pair.actor, pair.target, fmt.Sprintf("concurrent_admin_%d", i), accounts.Change{ExpectedRevision: 1, Role: "viewer", Active: &active})
			results <- err
		}(i, pair)
	}
	group.Wait()
	close(results)
	success, denied := 0, 0
	for err := range results {
		if err == nil {
			success++
		} else if errors.Is(err, accounts.ErrUnavailable) {
			denied++
		} else {
			t.Fatal("并发权限结果无效", err)
		}
	}
	if success != 1 || denied != 1 {
		t.Fatal("并发降权没有重新核验操作者", success, denied)
	}
	var admins int
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE tenant_id=$1 AND active AND role='admin'`, u.TenantID).Scan(&admins))
	if admins != 1 {
		t.Fatal("并发管理丢失最后一名管理员", admins)
	}
}

func TestUserManagementPaginationQuotasCorruptReceiptsAndFailureBoundaries(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f, u, _, _ := accountFixture(t, ctx)
	active := true
	input := accounts.Create{Username: "boundary_owned", Password: store.Token(), Role: "viewer", Active: &active}
	r, err := f.Runtime.CreateUser(ctx, u, "boundary_create", input)
	require(t, err)
	for _, patch := range []string{`jsonb_set(record,'{id}','"user_wrong"')`, `jsonb_set(record,'{role}','"admin"')`, `jsonb_set(record,'{revision}','2')`, `'{}'::jsonb`} {
		original, _ := json.Marshal(r)
		_, err = f.Owner.Pool.Exec(ctx, `UPDATE user_management_requests SET record=`+patch+` WHERE tenant_id=$1 AND key_hash=$2`, u.TenantID, store.Hash("boundary_create"))
		require(t, err)
		if _, err := f.Runtime.CreateUser(ctx, u, "boundary_create", input); err == nil {
			t.Fatal("损坏回执被信任", patch)
		}
		_, err = f.Owner.Pool.Exec(ctx, `UPDATE user_management_requests SET record=$3 WHERE tenant_id=$1 AND key_hash=$2`, u.TenantID, store.Hash("boundary_create"), original)
		require(t, err)
	}
	for _, principal := range []model.Principal{{ID: u.ID, TenantID: u.TenantID, Role: "viewer"}, {ID: "user_missing", TenantID: u.TenantID, Role: "admin"}} {
		if _, err := f.Runtime.Users(ctx, principal, accounts.Query{}); !errors.Is(err, accounts.ErrUnavailable) {
			t.Fatal("无权或失效用户读取身份", err)
		}
	}
	if _, err := f.Runtime.Users(ctx, u, accounts.Query{Active: "yes"}); !errors.Is(err, accounts.ErrInput) {
		t.Fatal("非法筛选通过")
	}
	if _, err := f.Runtime.User(ctx, u, "bad/id"); !errors.Is(err, accounts.ErrInput) {
		t.Fatal("非法用户标识通过")
	}
	if _, err := f.Runtime.CreateUser(ctx, u, "bad/key", input); !errors.Is(err, accounts.ErrInput) {
		t.Fatal("非法请求标识通过")
	}
	if _, err := f.Runtime.CreateUser(ctx, u, "invalid_input", accounts.Create{}); !errors.Is(err, accounts.ErrInput) {
		t.Fatal("非法创建通过")
	}
	if _, err := f.Runtime.ChangeUser(ctx, u, r.ID, "invalid_change", accounts.Change{}); !errors.Is(err, accounts.ErrInput) {
		t.Fatal("非法变更通过")
	}
	// 批量目录夹具仅验证分页和硬上限，不作为并发或吞吐量证据。
	_, err = f.Owner.Pool.Exec(ctx, `INSERT INTO users(id,tenant_id,username,password_hash,role) SELECT 'account_'||lpad(n::text,3,'0'),$1,'fixture_'||n,'not_login_credential','viewer' FROM generate_series(1,23) n`, u.TenantID)
	require(t, err)
	p, err := f.Runtime.Users(ctx, u, accounts.Query{Role: "viewer"})
	require(t, err)
	if len(p.Items) != 20 || p.Next == "" {
		t.Fatal("目录分页无界")
	}
	next, err := f.Runtime.Users(ctx, u, accounts.Query{Role: "viewer", Before: p.Next})
	require(t, err)
	if len(next.Items) != 4 || next.Next != "" {
		t.Fatal("目录续点遗漏或重复用户", len(next.Items))
	}
	seen := map[string]bool{}
	for _, row := range append(p.Items, next.Items...) {
		if seen[row.ID] {
			t.Fatal("分页重复")
		}
		seen[row.ID] = true
	}
	_, err = f.Owner.Pool.Exec(ctx, `INSERT INTO user_management_requests(tenant_id,created_by,operation,key_hash,input_hash,user_id,record,expires_at) SELECT $1,$2,'create','budget_'||n,'fixture','fixture','{}',now()+interval '1 day' FROM generate_series(1,999) n`, u.TenantID, u.ID)
	require(t, err)
	input.Username = "day_quota_owned"
	if _, err := f.Runtime.CreateUser(ctx, u, "day_quota_owned", input); !errors.Is(err, accounts.ErrQuota) {
		t.Fatal("日额度没有限制", err)
	}
	input.Username = r.Username
	if _, err := f.Runtime.CreateUser(ctx, u, "boundary_create", input); err != nil {
		t.Fatal("已确认请求被日额度阻止", err)
	}
	_, err = f.Owner.Pool.Exec(ctx, `DELETE FROM user_management_requests WHERE key_hash LIKE 'budget_%'`)
	require(t, err)
	_, err = f.Owner.Pool.Exec(ctx, `INSERT INTO users(id,tenant_id,username,password_hash,role) SELECT 'quota_'||n,$1,'quota_name_'||n,'not_login_credential','viewer' FROM generate_series(1,475) n`, u.TenantID)
	require(t, err)
	input.Username = "user_quota_owned"
	if _, err := f.Runtime.CreateUser(ctx, u, "user_quota_owned", input); !errors.Is(err, accounts.ErrQuota) {
		t.Fatal("用户硬上限没有限制", err)
	}
	// 固定写入函数自身也拒绝空角色、无效身份和超过配额，不能依赖 HTTP 校验。
	for _, item := range []struct {
		id   string
		role any
		code string
	}{{"bad/id", "admin", "22023"}, {"user_sql_null", nil, "22023"}, {"user_sql_quota", "viewer", "P0003"}} {
		err := f.Runtime.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `SELECT * FROM public.save_tenant_user($1,$2,'sql_owned',$3,$4,true,0,'sql_owned')`, u.ID, item.id, "$2a$10$"+strings.Repeat("a", 53), item.role)
			return err
		})
		var p *pgconn.PgError
		if !errors.As(err, &p) || p.Code != item.code {
			t.Fatal("SQL 函数边界未关闭", item.id, err)
		}
	}
	_, err = f.Owner.Pool.Exec(ctx, `UPDATE user_management_requests SET expires_at=now()-interval '1 second' WHERE tenant_id=$1`, u.TenantID)
	require(t, err)
	for range 6 {
		_, err = f.Runtime.SweepHistory(ctx)
		require(t, err)
	}
	var left int
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT count(*) FROM user_management_requests WHERE tenant_id=$1`, u.TenantID).Scan(&left))
	if left != 0 {
		t.Fatal("到期用户管理回执未按分类回收")
	}
}
