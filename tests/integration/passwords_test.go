//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/accounts"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/platform"
	"github.com/kkx600/StarBeacon/internal/store"
	"golang.org/x/crypto/bcrypt"
)

func TestPasswordManagementHTTPChangeResetAndSessionRevocation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f, u, b, password := accountFixture(t, ctx)
	a := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime}, u.Username, password)
	other := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime}, b.Username, password)
	active := true
	created, err := f.Runtime.CreateUser(ctx, u, "password_create", accounts.Create{Username: "password_owned_viewer", Password: store.Token(), Role: "viewer", Active: &active})
	require(t, err)
	// 初始密码通过管理工具保存；验收不读取或打印人类账号的凭据。
	initial := store.Token()
	hash, err := bcrypt.GenerateFromPassword([]byte(initial), bcrypt.DefaultCost)
	require(t, err)
	_, err = f.Owner.Pool.Exec(ctx, `UPDATE users SET password_hash=$1 WHERE id=$2`, string(hash), created.ID)
	require(t, err)
	viewerPrincipal, _, err := f.Runtime.Password(ctx, created.Username)
	require(t, err)
	viewer := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime}, created.Username, initial)
	var current accounts.Record
	viewer.request("GET", "/auth/account", "", nil, &current, 200)
	if current.ID != created.ID || current.Revision != 1 {
		t.Fatal("当前账号范围或修订不正确")
	}
	newPassword := store.Token()
	reset := accounts.PasswordChange{ExpectedRevision: 1, CurrentPassword: password, NewPassword: newPassword}
	viewer.request("POST", "/users/"+u.ID+"/password", "viewer_password_denied", reset, nil, 403)
	other.request("POST", "/users/"+created.ID+"/password", "foreign_password_denied", reset, nil, 404)
	wrong := reset
	wrong.CurrentPassword = "wrong-password-owned"
	a.request("POST", "/users/"+created.ID+"/password", "password_stepup_denied", wrong, nil, 403)
	noCSRF := *a
	noCSRF.csrf = ""
	noCSRF.request("POST", "/users/"+created.ID+"/password", "password_csrf_denied", reset, nil, 403)
	a.request("POST", "/users/"+u.ID+"/password", "password_self_endpoint", reset, nil, 400)
	a.request("POST", "/users/"+created.ID+"/password", "password_reset", reset, &current, 200)
	if current.Revision != 2 || !current.Active || current.Role != "viewer" {
		t.Fatal("重置修改了权限或使用状态")
	}
	viewer.request("GET", "/auth/me", "", nil, nil, 401)
	if _, _, err = f.Runtime.CreateSession(ctx, viewerPrincipal); !errors.Is(err, model.ErrUnauthenticated) {
		t.Fatal("旧验证结果创建了会话", err)
	}
	a.request("POST", "/users/"+created.ID+"/password", "password_reset", reset, &current, 200)
	altered := reset
	altered.NewPassword = store.Token()
	a.request("POST", "/users/"+created.ID+"/password", "password_reset", altered, nil, 409)
	a.request("POST", "/users/"+created.ID+"/password", "password_stale", altered, nil, 409)
	newViewer := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime}, created.Username, newPassword)
	second := store.Token()
	own := accounts.PasswordChange{ExpectedRevision: 2, CurrentPassword: newPassword, NewPassword: second}
	newViewer.request("POST", "/auth/password", "password_change_self", own, &current, 200)
	if current.Revision != 3 || current.ID != created.ID {
		t.Fatal("自身密码回执不正确")
	}
	newViewer.request("GET", "/auth/me", "", nil, nil, 401)
	verified, stored, err := f.Runtime.Password(ctx, created.Username)
	require(t, err)
	require(t, bcrypt.CompareHashAndPassword([]byte(stored), []byte(second)))
	if bcrypt.CompareHashAndPassword([]byte(stored), []byte(newPassword)) == nil {
		t.Fatal("旧密码仍然有效")
	}
	data, err := json.Marshal(verified)
	require(t, err)
	if strings.Contains(string(data), "revision") {
		t.Fatal("内部登录修订暴露给浏览器")
	}
	active = false
	_, err = f.Runtime.ChangeUser(ctx, u, created.ID, "password_disable", accounts.Change{ExpectedRevision: 3, Role: "viewer", Active: &active})
	require(t, err)
	reset.ExpectedRevision = 4
	reset.NewPassword = store.Token()
	a.request("POST", "/users/"+created.ID+"/password", "password_disabled_reset", reset, &current, 200)
	if current.Active || current.Revision != 5 {
		t.Fatal("重置复活了停用账号")
	}
	if _, _, err = f.Runtime.Password(ctx, created.Username); !errors.Is(err, model.ErrUnauthenticated) {
		t.Fatal("停用账号可以登录")
	}
	var raw string
	var days float64
	var count int
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT jsonb_agg(record)::text,min(extract(epoch FROM expires_at-created_at)/86400),count(*) FROM user_management_requests WHERE operation='password'`).Scan(&raw, &days, &count))
	var publicRecords []map[string]json.RawMessage
	require(t, json.Unmarshal([]byte(raw), &publicRecords))
	for _, record := range publicRecords {
		for _, field := range []string{"password", "password_hash", "current_password", "new_password"} {
			if _, present := record[field]; present {
				t.Fatal("公开回执包含凭据字段")
			}
		}
	}
	if count != 3 || days < 179 || strings.Contains(raw, newPassword) || strings.Contains(raw, second) {
		t.Fatal("密码回执泄漏凭据或留存不正确")
	}
	var resets, changes, denials int
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT count(*) FILTER(WHERE action='users.password.reset'),count(*) FILTER(WHERE action='users.password.change'),count(*) FILTER(WHERE action='users.password.denied') FROM operation_audits`).Scan(&resets, &changes, &denials))
	if resets != 2 || changes != 1 || denials != 1 {
		t.Fatal("密码审计重复或缺失", resets, changes, denials)
	}
}

func TestPasswordManagementAtomicRollbackAndCredentialRevision(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f, u, b, password := accountFixture(t, ctx)
	active := true
	initial := store.Token()
	target, err := f.Runtime.CreateUser(ctx, u, "password_atomic_create", accounts.Create{Username: "password_atomic_viewer", Password: initial, Role: "viewer", Active: &active})
	require(t, err)
	before, oldHash, err := f.Runtime.Password(ctx, target.Username)
	require(t, err)
	token, _, err := f.Runtime.CreateSession(ctx, before)
	require(t, err)
	input := accounts.PasswordChange{ExpectedRevision: 1, CurrentPassword: password, NewPassword: store.Token()}
	_, err = f.Owner.Pool.Exec(ctx, `CREATE FUNCTION public.password_receipt_fault() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.operation='password' THEN RAISE EXCEPTION 'owned_password_receipt_failure'; END IF;RETURN NEW;END$$;CREATE TRIGGER password_receipt_fault BEFORE INSERT ON user_management_requests FOR EACH ROW EXECUTE FUNCTION public.password_receipt_fault()`)
	require(t, err)
	if _, err = f.Runtime.ChangePassword(ctx, u, target.ID, "password_atomic_reset", input); err == nil {
		t.Fatal("回执失败提交了密码")
	}
	current, currentHash, err := f.Runtime.Password(ctx, target.Username)
	require(t, err)
	if current.CredentialRevision != 1 || currentHash != oldHash {
		t.Fatal("密码与回执没有原子回滚")
	}
	if _, err = f.Runtime.Session(ctx, token); err != nil {
		t.Fatal("事务回滚撤销了会话", err)
	}
	_, err = f.Owner.Pool.Exec(ctx, `DROP TRIGGER password_receipt_fault ON user_management_requests;DROP FUNCTION public.password_receipt_fault()`)
	require(t, err)
	result, err := f.Runtime.ChangePassword(ctx, u, target.ID, "password_atomic_reset", input)
	require(t, err)
	if result.Revision != 2 {
		t.Fatal("同一请求在回滚后没有正确提交")
	}
	if _, err = f.Runtime.Session(ctx, token); !errors.Is(err, model.ErrUnauthenticated) {
		t.Fatal("旧会话没有撤销")
	}
	if _, _, err = f.Runtime.CreateSession(ctx, before); !errors.Is(err, model.ErrUnauthenticated) {
		t.Fatal("密码变化后旧验证创建会话")
	}
	forged := u
	forged.TenantID = b.TenantID
	if _, _, err = f.Runtime.CreateSession(ctx, forged); !errors.Is(err, model.ErrUnauthenticated) {
		t.Fatal("异租户会话创建未拒绝")
	}
	if _, err = f.Runtime.ChangePassword(ctx, before, u.ID, "password_viewer_direct", input); !errors.Is(err, accounts.ErrUnavailable) {
		t.Fatal("直接持久调用绕过权限")
	}
	var publicExecute bool
	var searchPath string
	for _, function := range []string{"public.create_tenant_session(text,text,bigint,text,text)", "public.change_tenant_password(text,bigint,text,text,bigint,text,text,jsonb)"} {
		require(t, f.Owner.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_proc p CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a WHERE p.oid=$1::regprocedure AND a.grantee=0 AND a.privilege_type='EXECUTE')`, function).Scan(&publicExecute))
		require(t, f.Owner.Pool.QueryRow(ctx, `SELECT array_to_string(proconfig,',') FROM pg_proc WHERE oid=$1::regprocedure`, function).Scan(&searchPath))
		if publicExecute || !strings.Contains(searchPath, "pg_catalog, public, pg_temp") {
			t.Fatal("固定身份函数权限或搜索路径不安全")
		}
	}
	var writable bool
	require(t, f.Runtime.Pool.QueryRow(ctx, `SELECT has_table_privilege(current_user,'public.users','INSERT,UPDATE,DELETE')`).Scan(&writable))
	if writable {
		t.Fatal("运行账号取得身份表写入权限")
	}
	// 原回执已到期时不能凭原键重新设置密码。
	_, err = f.Owner.Pool.Exec(ctx, `UPDATE user_management_requests SET expires_at=now()-interval '1 second' WHERE operation='password'`)
	require(t, err)
	if _, err = f.Runtime.ChangePassword(ctx, u, target.ID, "password_atomic_reset", input); !errors.Is(err, accounts.ErrExpired) {
		t.Fatal("到期请求被重复执行", err)
	}
}

func TestPasswordAttemptBudgetAndUnavailablePrincipals(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f, u, _, password := accountFixture(t, ctx)
	input := accounts.PasswordChange{ExpectedRevision: 1, CurrentPassword: "password-wrong-owned", NewPassword: store.Token()}
	for i := 0; i < 10; i++ {
		if _, err := f.Runtime.ChangePassword(ctx, u, u.ID, "password_attempt_owned", input); !errors.Is(err, accounts.ErrPassword) {
			t.Fatal("错误密码尝试未按预算执行", err)
		}
	}
	input.CurrentPassword = password
	if _, err := f.Runtime.ChangePassword(ctx, u, u.ID, "password_after_budget", input); !errors.Is(err, accounts.ErrPasswordRate) {
		t.Fatal("跨请求密码预算没有生效", err)
	}
	var count int
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT attempts FROM password_attempts WHERE tenant_id=$1 AND user_id=$2`, u.TenantID, u.ID).Scan(&count))
	if count != 11 {
		t.Fatal("错误或成功尝试未持久计数")
	}
	_, err := f.Owner.Pool.Exec(ctx, `UPDATE password_attempts SET window_started=clock_timestamp()-interval '61 seconds' WHERE tenant_id=$1`, u.TenantID)
	require(t, err)
	result, err := f.Runtime.ChangePassword(ctx, u, u.ID, "password_after_window", input)
	require(t, err)
	if result.Revision != 2 {
		t.Fatal("验证窗口恢复后修改失败")
	}
	if _, err = f.Runtime.PasswordAccount(ctx, u); !errors.Is(err, accounts.ErrUnavailable) {
		t.Fatal("旧身份修订仍能读当前账号")
	}
	current, _, err := f.Runtime.Password(ctx, u.Username)
	require(t, err)
	input.ExpectedRevision = 2
	input.CurrentPassword = input.NewPassword
	input.NewPassword = store.Token()
	if _, err = f.Runtime.ChangePassword(ctx, u, u.ID, "password_old_identity", input); !errors.Is(err, accounts.ErrUnavailable) {
		t.Fatal("旧身份修订仍能修改密码")
	}
	if _, err = f.Runtime.ChangePassword(ctx, current, "invalid/id", "password_invalid_target", input); !errors.Is(err, accounts.ErrInput) {
		t.Fatal("非法目标被接受")
	}
	if _, err = f.Runtime.ChangePassword(ctx, current, current.ID, "invalid/key", input); !errors.Is(err, accounts.ErrInput) {
		t.Fatal("非法幂等键被接受")
	}
	bad := current
	bad.CredentialRevision = 0
	if _, err = f.Runtime.PasswordAccount(ctx, bad); !errors.Is(err, accounts.ErrUnavailable) {
		t.Fatal("无修订身份被接受")
	}
	if _, err = f.Runtime.ChangePassword(ctx, bad, bad.ID, "password_invalid_principal", input); !errors.Is(err, accounts.ErrUnavailable) {
		t.Fatal("无修订身份进入验证")
	}
	broken, err := store.Open(ctx, f.RuntimeDSN)
	require(t, err)
	broken.Close()
	if _, err = broken.PasswordAccount(ctx, current); err == nil {
		t.Fatal("账号存储关闭返回成功")
	}
	if _, err = broken.ChangePassword(ctx, current, current.ID, "password_unavailable", input); err == nil {
		t.Fatal("密码存储关闭返回成功")
	}
}

func TestPasswordQuotaReceiptsAndReusedPasswords(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f, u, _, password := accountFixture(t, ctx)
	active := true
	initial := store.Token()
	target, err := f.Runtime.CreateUser(ctx, u, "password_quota_create", accounts.Create{Username: "password_quota_viewer", Password: initial, Role: "viewer", Active: &active})
	require(t, err)
	input := accounts.PasswordChange{ExpectedRevision: 1, CurrentPassword: password, NewPassword: initial}
	if _, err = f.Runtime.ChangePassword(ctx, u, target.ID, "password_reuse", input); !errors.Is(err, accounts.ErrInput) {
		t.Fatal("原密码重复设置被接受", err)
	}
	input.NewPassword = store.Token()
	result, err := f.Runtime.ChangePassword(ctx, u, target.ID, "password_receipt", input)
	require(t, err)
	_, err = f.Owner.Pool.Exec(ctx, `UPDATE user_management_requests SET record='{}' WHERE operation='password'`)
	require(t, err)
	if _, err = f.Runtime.ChangePassword(ctx, u, target.ID, "password_receipt", input); err == nil {
		t.Fatal("损坏回执返回正常记录")
	}
	raw, err := json.Marshal(result)
	require(t, err)
	_, err = f.Owner.Pool.Exec(ctx, `UPDATE user_management_requests SET record=$1 WHERE operation='password'`, raw)
	require(t, err)
	changed := input
	changed.ExpectedRevision = 2
	if _, err = f.Runtime.ChangePassword(ctx, u, target.ID, "password_receipt", changed); !errors.Is(err, store.ErrConflict) {
		t.Fatal("原键修订变化未拒绝")
	}
	_, err = f.Owner.Pool.Exec(ctx, `INSERT INTO user_management_requests(tenant_id,created_by,operation,key_hash,input_hash,user_id,record,expires_at) SELECT $1,$2,'change','owned_budget_'||i,'owned',$3,$4,now()+interval '180 days' FROM generate_series(1,998) i`, u.TenantID, u.ID, target.ID, raw)
	require(t, err)
	changed.NewPassword = store.Token()
	if _, err = f.Runtime.ChangePassword(ctx, u, target.ID, "password_daily_budget", changed); !errors.Is(err, accounts.ErrQuota) {
		t.Fatal("密码变更未共享用户操作日额度", err)
	}
	_, err = f.Owner.Pool.Exec(ctx, `UPDATE tenants SET active=false WHERE id=$1`, u.TenantID)
	require(t, err)
	if _, _, err = f.Runtime.CreateSession(ctx, u); !errors.Is(err, model.ErrUnauthenticated) {
		t.Fatal("停用租户创建了会话")
	}
	if _, err = f.Runtime.ChangePassword(ctx, u, target.ID, "password_inactive_tenant", changed); !errors.Is(err, accounts.ErrUnavailable) {
		t.Fatal("停用租户修改了密码")
	}
	if _, err = f.Runtime.PasswordAccount(ctx, u); !errors.Is(err, accounts.ErrUnavailable) {
		t.Fatal("停用租户读取了账号")
	}
}

func TestPasswordConcurrentResetAndRevokedActorCannotCommit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f, u, _, password := accountFixture(t, ctx)
	active := true
	target, err := f.Runtime.CreateUser(ctx, u, "password_concurrent_create", accounts.Create{Username: "password_concurrent_viewer", Password: store.Token(), Role: "viewer", Active: &active})
	require(t, err)
	viewer, _, err := f.Runtime.Password(ctx, target.Username)
	require(t, err)
	session, _, err := f.Runtime.CreateSession(ctx, viewer)
	require(t, err)
	input := accounts.PasswordChange{ExpectedRevision: 1, CurrentPassword: password, NewPassword: store.Token()}
	type outcome struct {
		record accounts.Record
		err    error
	}
	results := make(chan outcome, 3)
	start := make(chan struct{})
	var workers sync.WaitGroup
	for range 3 {
		workers.Go(func() {
			<-start
			record, err := f.Runtime.ChangePassword(ctx, u, target.ID, "password_concurrent_reset", input)
			results <- outcome{record, err}
		})
	}
	close(start)
	workers.Wait()
	close(results)
	for result := range results {
		require(t, result.err)
		if result.record.ID != target.ID || result.record.Revision != 2 {
			t.Fatal("并发原键没有返回同一密码回执")
		}
	}
	var revision int64
	var receipts, audits int
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT revision FROM users WHERE id=$1`, target.ID).Scan(&revision))
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT count(*) FROM user_management_requests WHERE operation='password'`).Scan(&receipts))
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT count(*) FROM operation_audits WHERE action='users.password.reset'`).Scan(&audits))
	if revision != 2 || receipts != 1 || audits != 1 {
		t.Fatal("并发原键重复修改密码或审计", revision, receipts, audits)
	}
	if _, err := f.Runtime.Session(ctx, session); !errors.Is(err, model.ErrUnauthenticated) {
		t.Fatal("并发重置未撤销旧会话", err)
	}
	wrong := input
	wrong.NewPassword = store.Token()
	if _, err := f.Runtime.ChangePassword(ctx, u, target.ID, "password_concurrent_reset", wrong); !errors.Is(err, store.ErrConflict) {
		t.Fatal("同键不同密码沿用了原回执", err)
	}

	// 真实资源锁使已计算完成的请求等待提交，在此期间撤回账号修订。
	lock, err := f.Owner.Pool.Begin(ctx)
	require(t, err)
	defer lock.Rollback(context.WithoutCancel(ctx))
	_, err = lock.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, u.TenantID+"/users")
	require(t, err)
	input.ExpectedRevision = 2
	input.NewPassword = store.Token()
	finished := make(chan error, 1)
	go func() {
		_, err := f.Runtime.ChangePassword(ctx, u, target.ID, "password_revoked_actor", input)
		finished <- err
	}()
	eventually(t, ctx, "密码请求等待提交锁", func() bool {
		var waiting bool
		err := f.Owner.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND NOT granted)`).Scan(&waiting)
		return err == nil && waiting
	})
	_, err = f.Owner.Pool.Exec(ctx, `UPDATE users SET role='viewer',revision=revision+1 WHERE id=$1`, u.ID)
	require(t, err)
	require(t, lock.Commit(ctx))
	if err := <-finished; !errors.Is(err, accounts.ErrUnavailable) {
		t.Fatal("计算期间撤回的账号仍提交密码", err)
	}
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT revision FROM users WHERE id=$1`, target.ID).Scan(&revision))
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT count(*) FROM user_management_requests WHERE operation='password'`).Scan(&receipts))
	if revision != 2 || receipts != 1 {
		t.Fatal("拒绝提交后仍改变目标密码或回执")
	}
}
