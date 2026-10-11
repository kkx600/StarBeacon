//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/config"
	"github.com/kkx600/StarBeacon/internal/retention"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/transport"
	"golang.org/x/crypto/bcrypt"
)

// 管理入口使用实际子进程；不以直接调用业务函数代替参数、环境和退出码验收。
func TestManagementCLIIdentityAndArtifactPreservation(t *testing.T) {
	binary := os.Getenv("SB_TEST_MANAGEMENT_BINARY")
	if binary == "" || os.Getenv("SB_MODE") != "development" || os.Getenv("SB_MIGRATION_DATABASE_URL") == "" {
		t.Skip("需要独立开发依赖与管理入口制品")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := store.Open(ctx, os.Getenv("SB_MIGRATION_DATABASE_URL"))
	require(t, err)
	defer db.Close()
	tenant, username, password := store.RandomID("it_cli_"), store.RandomID("user_cli_"), store.Token()
	defer func() {
		clean, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		require(t, db.TenantTx(clean, tenant, func(tx pgx.Tx) error {
			for _, table := range []string{"sensors", "retention_policies", "users", "tenants"} {
				column := "tenant_id"
				if table == "tenants" {
					column = "id"
				}
				if _, err := tx.Exec(clean, "DELETE FROM "+table+" WHERE "+column+"=$1", tenant); err != nil {
					return err
				}
			}
			return nil
		}))
	}()
	run := func(expected int, environment []string, args ...string) []byte {
		t.Helper()
		command := exec.CommandContext(ctx, binary, args...)
		command.Env = append(os.Environ(), "GOCOVERDIR="+os.Getenv("SB_TEST_BINARY_COVERDIR"), "SB_BOOTSTRAP_PASSWORD="+password)
		command.Env = append(command.Env, environment...)
		output, err := command.CombinedOutput()
		actual := 0
		if err != nil {
			exit, ok := err.(*exec.ExitError)
			if !ok {
				t.Fatalf("管理进程未完成：%v", err)
			}
			actual = exit.ExitCode()
		}
		if actual != expected {
			t.Fatalf("管理入口退出码 %d，预期 %d：%s", actual, expected, output)
		}
		return output
	}
	if !bytes.Contains(run(0, nil, "--version"), []byte("StarBeacon starbeaconctl")) {
		t.Fatal("构建身份未返回")
	}
	for _, name := range []string{"starbeacon", "starbeacon-ingest", "starbeacon-worker", "starbeacon-agent"} {
		entry := filepath.Join(filepath.Dir(binary), name)
		version := exec.CommandContext(ctx, entry, "--version")
		version.Env = roleEnvironment(config.Config{})
		output, err := version.CombinedOutput()
		require(t, err)
		if !bytes.Contains(output, []byte("StarBeacon")) {
			t.Fatal("角色制品未返回构建身份")
		}
		invalid := exec.CommandContext(ctx, entry)
		invalid.Env = roleEnvironment(config.Config{})
		output, err = invalid.CombinedOutput()
		exit, ok := err.(*exec.ExitError)
		if !ok || exit.ExitCode() != 1 || !bytes.Contains(output, []byte("配置不合法")) {
			t.Fatal("角色制品没有拒绝不完整运行配置")
		}
	}
	run(1, nil)
	run(1, nil, "bootstrap", "--unknown-flag")
	run(1, []string{"SB_MIGRATION_DATABASE_URL="}, "bootstrap")
	dir := t.TempDir()
	ca, keys := filepath.Join(dir, "pki"), filepath.Join(dir, "commands")
	run(1, nil, "dev-pki", "--dir", ca, "--server-hosts", "*.invalid")
	run(0, nil, "dev-pki", "--dir", ca, "--server-hosts", "platform.test,192.0.2.100")
	caKey, err := os.ReadFile(filepath.Join(ca, "ca.key"))
	require(t, err)
	run(1, nil, "dev-pki", "--dir", ca)
	preserved, err := os.ReadFile(filepath.Join(ca, "ca.key"))
	require(t, err)
	if !bytes.Equal(caKey, preserved) {
		t.Fatal("重复初始化覆盖已有 CA")
	}
	run(0, nil, "command-keys", "--dir", keys)
	key, err := os.ReadFile(filepath.Join(keys, "command.key"))
	require(t, err)
	digest := sha256.Sum256(key)
	run(1, nil, "command-keys", "--dir", keys)
	key, err = os.ReadFile(filepath.Join(keys, "command.key"))
	require(t, err)
	if sha256.Sum256(key) != digest {
		t.Fatal("重复初始化覆盖已有签名身份")
	}
	base := []string{"bootstrap", "--tenant", tenant, "--username", username, "--name", "管理入口验收"}
	run(1, nil, append(append([]string{}, base...), "--role", "invalid")...)
	run(0, nil, base...)
	run(0, nil, append(append([]string{}, base...), "--if-missing")...)
	run(1, []string{"SB_BOOTSTRAP_PASSWORD=" + store.Token()}, append(append([]string{}, base...), "--if-missing")...)
	principal, hash, err := db.Password(ctx, username)
	require(t, err)
	require(t, bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)))
	if principal.TenantID != tenant {
		t.Fatal("管理员归属不匹配")
	}
	require(t, db.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		var categories []string
		var nondefault int
		if err := tx.QueryRow(ctx, "SELECT array_agg(category ORDER BY category),count(*) FILTER(WHERE days<>180) FROM retention_policies WHERE tenant_id=$1", tenant).Scan(&categories, &nondefault); err != nil {
			return err
		}
		var expected []string
		for _, category := range retention.Catalog() {
			expected = append(expected, category.ID)
		}
		slices.Sort(expected)
		if !slices.Equal(categories, expected) || nondefault != 0 {
			t.Fatal("初始化留存类别或默认值不匹配")
		}
		return nil
	}))
	sensorDir := filepath.Join(dir, "sensor")
	provision := []string{"provision-agent", "--tenant", tenant, "--sensor", "sensor_cli", "--name", "管理验收探针", "--ca-dir", ca, "--dir", sensorDir}
	var identity transport.SensorIdentity
	require(t, json.Unmarshal(run(0, nil, provision...), &identity))
	certificate, err := os.ReadFile(filepath.Join(sensorDir, "agent.crt"))
	require(t, err)
	block, _ := pem.Decode(certificate)
	if block == nil {
		t.Fatal("证书制品不完整")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	require(t, err)
	if len(cert.URIs) != 1 || cert.URIs[0].String() != transport.SensorURI(identity) {
		t.Fatal("登记与证书身份不一致")
	}
	run(1, nil, provision...)
	sensorKey, err := os.Stat(filepath.Join(sensorDir, "agent.key"))
	require(t, err)
	if sensorKey.Mode().Perm() != 0600 {
		t.Fatal("设备私钥权限不匹配")
	}
	bad := append([]string{}, provision...)
	bad[len(bad)-1] = filepath.Join(dir, "unknown-ca")
	bad[len(bad)-3] = filepath.Join(dir, "missing")
	run(1, nil, bad...)
	if !strings.Contains(string(run(1, nil, "unknown-command")), "未知管理命令") {
		t.Fatal("未知命令未拒绝")
	}
}
