package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kkx600/StarBeacon/internal/accounts"
	"github.com/kkx600/StarBeacon/internal/admin"
	"github.com/kkx600/StarBeacon/internal/probepki"
	"github.com/kkx600/StarBeacon/internal/transport"
)

func TestEnrollmentCommandRejectsInvalidMaterialsWithoutDatabase(t *testing.T) {
	t.Setenv("SB_MIGRATION_DATABASE_URL", "")
	originalArgs := os.Args
	t.Cleanup(func() { os.Args = originalArgs })
	root := t.TempDir()
	pkiDir := filepath.Join(root, "pki")
	if err := admin.DevPKI(pkiDir); err != nil {
		t.Fatal(err)
	}
	id := transport.SensorIdentity{TenantID: "tenant_cli", SensorID: "sensor_cli", RegistrationID: "registration_cli"}
	token, err := probepki.NewCredential(id, "enrollment_cli")
	if err != nil {
		t.Fatal(err)
	}
	tokenFile := filepath.Join(root, "token")
	if err = os.WriteFile(tokenFile, []byte(token), 0600); err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"missing_token", "public_token", "relative_identity", "insecure_origin", "missing_platform_root"} {
		t.Run(fault, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "identity")
			file, origin := tokenFile, "http://127.0.0.1:1"
			switch fault {
			case "missing_token":
				file += ".missing"
			case "public_token":
				file = filepath.Join(t.TempDir(), "public-token")
				if err := os.WriteFile(file, []byte(token), 0644); err != nil {
					t.Fatal(err)
				}
			case "relative_identity":
				dir = "relative-probe-identity"
			case "missing_platform_root":
				origin = "https://127.0.0.1:1"
			}
			os.Args = []string{"starbeaconctl", "enroll-agent", "--token-file", file, "--dir", dir, "--ca-file", filepath.Join(pkiDir, "ca.crt"), "--platform-url", origin, "--platform-ca-file", filepath.Join(root, "missing-platform-root")}
			err := run()
			if err == nil || strings.Contains(err.Error(), "SB_MIGRATION_DATABASE_URL") || strings.Contains(err.Error(), token) {
				t.Fatal("注册命令未在独立材料校验阶段失败，或错误泄露凭据", err)
			}
			if filepath.IsAbs(dir) {
				if _, err := os.Stat(filepath.Join(dir, "identity.pem")); !os.IsNotExist(err) {
					t.Fatal("失败注册生成了可用身份", err)
				}
			}
		})
	}
}

func TestManagementRecoveryValidatesPrivateInputBeforeDatabaseAccess(t *testing.T) {
	originalArgs := os.Args
	t.Cleanup(func() { os.Args = originalArgs })
	// 该连接串不能通过解析；若错误地提前访问数据库，错误类型将与恢复输入校验不符。
	t.Setenv("SB_MIGRATION_DATABASE_URL", "not-a-database-url")
	t.Setenv("SB_RECOVERY_PASSWORD", "")
	t.Setenv("SB_RECOVERY_PASSWORD_FILE", filepath.Join(t.TempDir(), "missing-password"))
	os.Args = []string{"starbeaconctl", "recover-admin"}
	if err := run(); err == nil || !strings.Contains(err.Error(), "恢复密码须由") {
		t.Fatal("恢复未先核对私有密码输入", err)
	}
	t.Setenv("SB_RECOVERY_PASSWORD_FILE", "")
	t.Setenv("SB_RECOVERY_PASSWORD", "Recovery-Fixture-Only-2026!")
	if err := run(); !errors.Is(err, accounts.ErrInput) {
		t.Fatal("缺少固定账号、修订和原因时进入数据库恢复", err)
	}
}

func TestManagementCommandRejectsInvalidInvocationBeforeConnecting(t *testing.T) {
	t.Setenv("SB_MIGRATION_DATABASE_URL", "")
	originalArgs := os.Args
	t.Cleanup(func() { os.Args = originalArgs })
	for _, args := range [][]string{{}, {"migrate", "extra"}, {"enroll-agent", "--unknown-flag"}, {"migrate"}} {
		os.Args = append([]string{"starbeaconctl"}, args...)
		if err := run(); err == nil {
			t.Fatal("无效调用没有失败", args)
		}
	}
	file := filepath.Join(t.TempDir(), "occupied")
	if err := os.WriteFile(file, nil, 0600); err != nil {
		t.Fatal(err)
	}
	os.Args = []string{"starbeaconctl", "command-keys", "--dir", file}
	if err := run(); err == nil {
		t.Fatal("命令密钥写入了非目录目标")
	}
}
