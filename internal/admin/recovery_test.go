package admin

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kkx600/StarBeacon/internal/accounts"
	"github.com/kkx600/StarBeacon/internal/store"
)

func TestRecoveryInputAndCredentialSources(t *testing.T) {
	valid := RecoveryInput{TenantID: "tenant_owned", UserID: "user_owned", RequestID: "recovery_owned", ExpectedRevision: 1, Reason: "值班管理员凭据遗失", NewPassword: "owned-password-for-test"}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, input := range [][2]string{{"../tenant", "admin"}, {"tenant_owned", ""}} {
		if _, err := InspectAdministrator(context.Background(), nil, input[0], input[1]); !errors.Is(err, accounts.ErrInput) {
			t.Fatal("非法离线核对访问持久层")
		}
	}
	for _, mutate := range []func(*RecoveryInput){
		func(r *RecoveryInput) { r.TenantID = "../foreign" }, func(r *RecoveryInput) { r.UserID = "" }, func(r *RecoveryInput) { r.RequestID = "" },
		func(r *RecoveryInput) { r.ExpectedRevision = 0 }, func(r *RecoveryInput) { r.ExpectedRevision = accounts.MaxRevision },
		func(r *RecoveryInput) { r.NewPassword = "short" }, func(r *RecoveryInput) { r.Reason = " " }, func(r *RecoveryInput) { r.Reason = "解释\n换行" },
		func(r *RecoveryInput) { r.Reason = "解释\u202e控制" }, func(r *RecoveryInput) { r.Reason = "\xff格式" }, func(r *RecoveryInput) { r.Reason = strings.Repeat("x", 513) },
		func(r *RecoveryInput) { r.Reason = "恢复 " + r.NewPassword },
	} {
		input := valid
		mutate(&input)
		if _, err := RecoverAdministrator(context.Background(), nil, input); !errors.Is(err, accounts.ErrInput) {
			t.Fatal("非法恢复输入访问持久层", err)
		}
	}
	if value, err := RecoveryPassword(valid.NewPassword, ""); err != nil || value != valid.NewPassword {
		t.Fatal("受控环境凭据未读取", err)
	}
	dir := t.TempDir()
	for i, text := range []string{valid.NewPassword, valid.NewPassword + "\n", valid.NewPassword + "\r\n"} {
		path := filepath.Join(dir, string(rune('a'+i)))
		if err := os.WriteFile(path, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
		if value, err := RecoveryPassword("", path); err != nil || value != valid.NewPassword {
			t.Fatal("私有文件凭据未读取", err)
		}
		if _, err := RecoveryPassword(valid.NewPassword, path); err == nil {
			t.Fatal("多个密码来源被隐式选择")
		}
	}
	readonly := filepath.Join(dir, "readonly")
	if err := os.WriteFile(readonly, []byte(valid.NewPassword), 0400); err != nil {
		t.Fatal(err)
	}
	if _, err := RecoveryPassword("", readonly); err != nil {
		t.Fatal("只读私有凭据未接受", err)
	}
	public := filepath.Join(dir, "public")
	large := filepath.Join(dir, "large")
	link := filepath.Join(dir, "link")
	if err := os.WriteFile(public, []byte(valid.NewPassword), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(large, []byte(strings.Repeat("x", 75)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(readonly, link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{public, large, link, dir, filepath.Join(dir, "missing")} {
		if value, err := RecoveryPassword("", path); err == nil || value != "" || strings.Contains(err.Error(), valid.NewPassword) || strings.Contains(err.Error(), path) {
			t.Fatal("不安全凭据源被接受或回显", path)
		}
	}
	for _, value := range []string{"", "short", strings.Repeat("x", 73), "owned\npassword", "owned-password-\xff"} {
		if _, err := RecoveryPassword(value, ""); err == nil {
			t.Fatal("非法密码被接受")
		}
	}
	for _, err := range []error{accounts.ErrInput, accounts.ErrUnavailable, accounts.ErrExpired, store.ErrConflict} {
		if !errors.Is(RecoveryFailure(err), err) {
			t.Fatal("业务错误语义被丢失")
		}
	}
	if err := RecoveryFailure(errors.New("private-database-credential")); strings.Contains(err.Error(), "private-database-credential") {
		t.Fatal("管理诊断泄漏内部凭据")
	}
}
