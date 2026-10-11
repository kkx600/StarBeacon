//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/accounts"
	"github.com/kkx600/StarBeacon/internal/admin"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/platform"
	"github.com/kkx600/StarBeacon/internal/store"
	"golang.org/x/crypto/bcrypt"
)

func TestAdministratorRecoveryCLIPrivateCredentialsAndConfirmation(t *testing.T) {
	binary := os.Getenv("SB_TEST_MANAGEMENT_BINARY")
	if binary == "" {
		t.Skip("需要管理入口制品")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f, u, b, original := accountFixture(t, ctx)
	oldHTTP := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime}, u.Username, original)
	secondSession, _, err := f.Runtime.CreateSession(ctx, u)
	require(t, err)
	password := store.Token()
	secret := filepath.Join(t.TempDir(), "recovery-password")
	require(t, os.WriteFile(secret, []byte(password+"\n"), 0600))
	base := []string{"recover-admin", "--tenant", u.TenantID, "--user-id", u.ID, "--expected-revision", "1", "--request-id", "recovery_cli_owned", "--reason", "值班管理员凭据遗失"}
	run := func(want int, environment []string, args ...string) []byte {
		t.Helper()
		command := exec.CommandContext(ctx, binary, args...)
		command.Env = append(os.Environ(), "SB_MIGRATION_DATABASE_URL="+f.OwnerDSN, "SB_RECOVERY_PASSWORD=", "SB_RECOVERY_PASSWORD_FILE="+secret, "GOCOVERDIR="+os.Getenv("SB_TEST_BINARY_COVERDIR"))
		command.Env = append(command.Env, environment...)
		output, err := command.CombinedOutput()
		actual := 0
		if err != nil {
			exit, ok := err.(*exec.ExitError)
			if !ok {
				t.Fatal("恢复进程没有完成")
			}
			actual = exit.ExitCode()
		}
		if actual != want || bytes.Contains(output, []byte(password)) || bytes.Contains(output, []byte(original)) || bytes.Contains(output, []byte(f.OwnerDSN)) {
			t.Fatal("恢复入口退出状态不正确或泄漏凭据")
		}
		return output
	}
	var inspected accounts.Record
	require(t, json.Unmarshal(run(0, nil, "inspect-admin", "--tenant", u.TenantID, "--username", u.Username), &inspected))
	if inspected.ID != u.ID || inspected.Revision != 1 || !inspected.Active || inspected.Role != "admin" {
		t.Fatal("离线公开核对错误")
	}
	run(1, []string{"SB_MIGRATION_DATABASE_URL=" + f.RuntimeDSN}, "inspect-admin", "--tenant", u.TenantID, "--username", u.Username)
	run(1, nil, "inspect-admin", "--tenant", b.TenantID, "--username", u.Username)
	run(1, []string{"SB_RECOVERY_PASSWORD=" + password}, base...)
	run(1, []string{"SB_RECOVERY_PASSWORD_FILE=" + secret + "-missing"}, base...)
	run(1, nil, append(append([]string{}, base...), "unexpected")...)
	run(1, []string{"SB_MIGRATION_DATABASE_URL=" + f.RuntimeDSN}, base...)
	var result admin.RecoveryResult
	require(t, json.Unmarshal(run(0, nil, base...), &result))
	if result.Account.ID != u.ID || result.Account.Revision != 2 || result.Confirmed || !result.Account.Active || result.Account.Role != "admin" || result.DatabaseActor == "" {
		t.Fatal("管理员恢复回执不正确")
	}
	oldHTTP.request("GET", "/auth/me", "", nil, nil, 401)
	if _, err = f.Runtime.Session(ctx, secondSession); !errors.Is(err, model.ErrUnauthenticated) {
		t.Fatal("另一个旧会话仍然有效")
	}
	if _, _, err = f.Runtime.CreateSession(ctx, u); !errors.Is(err, model.ErrUnauthenticated) {
		t.Fatal("旧验证结果在恢复后创建了会话")
	}
	current, hash, err := f.Runtime.Password(ctx, u.Username)
	require(t, err)
	require(t, bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)))
	if current.CredentialRevision != 2 || bcrypt.CompareHashAndPassword([]byte(hash), []byte(original)) == nil {
		t.Fatal("恢复密码没有生效")
	}
	newHTTP := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime}, u.Username, password)
	newHTTP.request("GET", "/auth/me", "", nil, nil, 200)
	require(t, json.Unmarshal(run(0, nil, base...), &result))
	if !result.Confirmed || result.Account.Revision != 2 {
		t.Fatal("同一请求确认产生重复变更")
	}
	_, _, err = f.Runtime.Password(ctx, b.Username)
	require(t, err)
	bad := append([]string{}, base...)
	bad[4] = b.ID
	run(1, nil, bad...)
	bad = append([]string{}, base...)
	bad[len(bad)-1] = "另一个恢复原因"
	run(1, nil, bad...)
	run(1, []string{"SB_RECOVERY_PASSWORD_FILE=", "SB_RECOVERY_PASSWORD=" + store.Token()}, base...)
	var audits int
	var days float64
	var reason, actor, receipt string
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT count(*),min(extract(epoch FROM expires_at-created_at)/86400),min(reason),min(user_id) FROM operation_audits WHERE tenant_id=$1 AND action='users.password.recover'`, u.TenantID).Scan(&audits, &days, &reason, &actor))
	if audits != 1 || days < 179 || reason != "值班管理员凭据遗失" || !strings.HasPrefix(actor, "database:") {
		t.Fatal("恢复审计重复、缺失或期限错误")
	}
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT record::text FROM user_management_requests WHERE tenant_id=$1 AND created_by=$2`, u.TenantID, actor).Scan(&receipt))
	if strings.Contains(receipt, password) || strings.Contains(receipt, "password_hash") || strings.Contains(receipt, "new_password") {
		t.Fatal("恢复确认记录保存凭据")
	}
	page, err := f.Runtime.Audits(ctx, u.TenantID, "operations", store.AuditQuery{Start: time.Now().Add(-time.Hour), End: time.Now().Add(time.Second), Limit: 20, Username: actor, Action: "users.password.recover"})
	require(t, err)
	if len(page.Items) != 1 || page.Items[0].Reason != reason || page.Items[0].Username != actor {
		t.Fatal("平台审计目录遗漏离线操作和原因")
	}
	foreign, err := f.Runtime.Audits(ctx, b.TenantID, "operations", store.AuditQuery{Start: time.Now().Add(-time.Hour), End: time.Now().Add(time.Second), Limit: 20})
	require(t, err)
	if len(foreign.Items) != 0 {
		t.Fatal("恢复审计跨租户可见")
	}
}

func TestAdministratorRecoveryAtomicRollbackRevisionAndReceiptBoundaries(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f, u, b, original := accountFixture(t, ctx)
	input := admin.RecoveryInput{TenantID: u.TenantID, UserID: u.ID, RequestID: "recovery_atomic_owned", ExpectedRevision: 1, Reason: "授权恢复管理员凭据", NewPassword: store.Token()}
	token, _, err := f.Runtime.CreateSession(ctx, u)
	require(t, err)
	_, oldHash, err := f.Runtime.Password(ctx, u.Username)
	require(t, err)
	for _, prefix := range []string{"begin", "SELECT session_user::text", "SELECT pg_advisory_xact_lock", "SELECT u.id,u.username", "SELECT input_hash,record", "UPDATE users SET password_hash", "DELETE FROM sessions", "INSERT INTO operation_audits", "INSERT INTO user_management_requests", "commit"} {
		t.Run(prefix, func(t *testing.T) {
			db, tracer := disconnectedStore(t, ctx, f.OwnerDSN, prefix)
			if _, err := admin.RecoverAdministrator(ctx, db, input); err == nil || !tracer.fired.Load() {
				t.Fatal("连接中断被当作恢复成功")
			}
			current, hash, err := f.Runtime.Password(ctx, u.Username)
			require(t, err)
			if current.CredentialRevision != 1 || hash != oldHash {
				t.Fatal("恢复事务未完整回滚")
			}
			if _, err := f.Runtime.Session(ctx, token); err != nil {
				t.Fatal("回滚撤销了既有会话")
			}
			var count int
			require(t, f.Owner.Pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM operation_audits WHERE action='users.password.recover')+(SELECT count(*) FROM user_management_requests)`).Scan(&count))
			if count != 0 {
				t.Fatal("回滚残留确认记录或审计")
			}
		})
	}
	if _, err := admin.RecoverAdministrator(ctx, f.Runtime, input); !errors.Is(err, accounts.ErrUnavailable) {
		t.Fatal("运行角色获得离线恢复能力")
	}
	if _, err := admin.InspectAdministrator(ctx, f.Runtime, u.TenantID, u.Username); !errors.Is(err, accounts.ErrUnavailable) {
		t.Fatal("运行角色取得离线核对权限")
	}
	for _, prefix := range []string{"begin", "SELECT session_user::text", "SELECT u.id,u.username", "commit"} {
		db, tracer := disconnectedStore(t, ctx, f.OwnerDSN, prefix)
		if _, err := admin.InspectAdministrator(ctx, db, u.TenantID, u.Username); err == nil || !tracer.fired.Load() {
			t.Fatal("离线核对连接中断被掩盖")
		}
	}
	input.NewPassword = original
	if _, err := admin.RecoverAdministrator(ctx, f.Owner, input); !errors.Is(err, accounts.ErrInput) {
		t.Fatal("恢复接受相同密码")
	}
	input.NewPassword = store.Token()
	_, err = f.Owner.Pool.Exec(ctx, `UPDATE retention_policies SET days=7 WHERE tenant_id=$1 AND category='operations'`, u.TenantID)
	require(t, err)
	result, err := admin.RecoverAdministrator(ctx, f.Owner, input)
	require(t, err)
	if result.Account.Revision != 2 {
		t.Fatal("故障后恢复没有提交")
	}
	var days float64
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT extract(epoch FROM expires_at-created_at)/86400 FROM user_management_requests WHERE tenant_id=$1`, u.TenantID).Scan(&days))
	if days < 6 || days > 8 {
		t.Fatal("恢复确认期限未遵守操作策略")
	}
	changed := input
	changed.RequestID = "recovery_stale"
	if _, err := admin.RecoverAdministrator(ctx, f.Owner, changed); !errors.Is(err, store.ErrConflict) {
		t.Fatal("旧修订覆盖了密码")
	}
	for _, bad := range []string{`{"account":null}`, `{"new_password":"no-secret"}`, `{"confirmed":true}`, `{"account":{},"account":{}}`} {
		_, err = f.Owner.Pool.Exec(ctx, `UPDATE user_management_requests SET record=$1::jsonb WHERE tenant_id=$2`, bad, u.TenantID)
		require(t, err)
		if _, err := admin.RecoverAdministrator(ctx, f.Owner, input); !errors.Is(err, store.ErrConflict) {
			t.Fatal("损坏回执被确认")
		}
	}
	raw, err := json.Marshal(result)
	require(t, err)
	_, err = f.Owner.Pool.Exec(ctx, `UPDATE user_management_requests SET record=$1,expires_at=now()-interval '1 second' WHERE tenant_id=$2`, raw, u.TenantID)
	require(t, err)
	if _, err := admin.RecoverAdministrator(ctx, f.Owner, input); !errors.Is(err, accounts.ErrExpired) {
		t.Fatal("过期恢复请求仍可确认")
	}
	active := true
	viewer, err := f.Runtime.CreateUser(ctx, b, "recovery_viewer", accounts.Create{Username: "recovery_viewer", Password: store.Token(), Role: "viewer", Active: &active})
	require(t, err)
	changed = input
	changed.TenantID, changed.UserID = b.TenantID, viewer.ID
	if _, err := admin.RecoverAdministrator(ctx, f.Owner, changed); !errors.Is(err, accounts.ErrUnavailable) {
		t.Fatal("恢复入口变更了只读用户")
	}
	changed.UserID = b.ID
	_, err = f.Owner.Pool.Exec(ctx, `UPDATE tenants SET active=false WHERE id=$1`, b.TenantID)
	require(t, err)
	if _, err := admin.RecoverAdministrator(ctx, f.Owner, changed); !errors.Is(err, accounts.ErrUnavailable) {
		t.Fatal("恢复入口绕过租户停用")
	}
}

func TestAdministratorRecoveryConcurrentCompareAndSet(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f, u, _, _ := accountFixture(t, ctx)
	var wait sync.WaitGroup
	results := make(chan error, 2)
	for i := range 2 {
		wait.Go(func() {
			_, err := admin.RecoverAdministrator(ctx, f.Owner, admin.RecoveryInput{TenantID: u.TenantID, UserID: u.ID, ExpectedRevision: 1, RequestID: "recovery_concurrent_" + strconv.Itoa(i), Reason: "授权恢复管理员凭据", NewPassword: store.Token()})
			results <- err
		})
	}
	wait.Wait()
	close(results)
	passed, conflicted := 0, 0
	for err := range results {
		if err == nil {
			passed++
		} else if errors.Is(err, store.ErrConflict) {
			conflicted++
		} else {
			t.Fatal("并发恢复返回意外错误", err)
		}
	}
	var revision int64
	var count int
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT revision FROM users WHERE id=$1`, u.ID).Scan(&revision))
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT count(*) FROM operation_audits WHERE action='users.password.recover'`).Scan(&count))
	if passed != 1 || conflicted != 1 || revision != 2 || count != 1 {
		t.Fatal("并发恢复覆盖修订或重复提交")
	}
}
