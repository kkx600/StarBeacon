package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kkx600/StarBeacon/internal/admin"
	"github.com/kkx600/StarBeacon/internal/buildinfo"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/probepki"
	"github.com/kkx600/StarBeacon/internal/store"
)

func run() error {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Printf("StarBeacon starbeaconctl %s (%s)\n", buildinfo.Version, buildinfo.Commit)
		return nil
	}
	if len(os.Args) < 2 {
		return fmt.Errorf("用法: starbeaconctl migrate|bootstrap|inspect-admin|recover-admin|dev-pki|enroll-agent|provision-agent|runtime-role|command-keys")
	}
	command := os.Args[1]
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	tenant := flags.String("tenant", "tenant_local", "租户标识")
	name := flags.String("name", "本地安全中心", "名称")
	username := flags.String("username", "admin", "管理员账号")
	role := flags.String("role", "admin", "账号角色")
	ifMissing := flags.Bool("if-missing", false, "已存在且配置匹配时保留账号")
	sensor := flags.String("sensor", "sensor_local", "探针标识")
	dir := flags.String("dir", ".local/pki", "制品目录")
	ca := flags.String("ca-dir", ".local/pki", "签发 CA 目录")
	hosts := flags.String("server-hosts", "", "服务证书附加 DNS/IP，使用逗号分隔")
	userID := flags.String("user-id", "", "恢复管理员的固定账号标识")
	expectedRevision := flags.Int64("expected-revision", 0, "恢复前核对的账号修订")
	requestID := flags.String("request-id", "", "恢复请求标识，同一请求确认时保持不变")
	reason := flags.String("reason", "", "管理员恢复原因，不得包含密码")
	platformURL := flags.String("platform-url", "", "平台 HTTPS 来源")
	tokenFile := flags.String("token-file", "", "私有注册令牌文件")
	caFile := flags.String("ca-file", "", "预置信任的探针 CA 根证书")
	platformCAFile := flags.String("platform-ca-file", "", "预置信任的平台 HTTPS CA 根证书")
	if e := flags.Parse(os.Args[2:]); e != nil {
		return e
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("不接受额外位置参数")
	}
	if command == "dev-pki" {
		var names []string
		if *hosts != "" {
			names = strings.Split(*hosts, ",")
		}
		return admin.DevPKIWithHosts(*dir, names)
	}
	if command == "command-keys" {
		if e := os.MkdirAll(*dir, 0700); e != nil {
			return e
		}
		return control.GenerateKeys(filepath.Join(*dir, "command.key"), filepath.Join(*dir, "command.pub"))
	}
	if command == "enroll-agent" {
		token, err := probepki.ReadTokenFile(*tokenFile)
		if err != nil {
			return err
		}
		credential, err := probepki.ParseCredential(token)
		if err != nil {
			return err
		}
		identity, err := probepki.OpenLocal(*dir, *caFile, credential.Identity)
		if err != nil {
			return err
		}
		defer identity.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err = identity.Enroll(ctx, *platformURL, *platformCAFile, token); err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(identity.Status())
	}
	dsn := os.Getenv("SB_MIGRATION_DATABASE_URL")
	if dsn == "" {
		return fmt.Errorf("缺少 SB_MIGRATION_DATABASE_URL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if command == "migrate" {
		return admin.Migrate(ctx, dsn)
	}
	var recovery admin.RecoveryInput
	if command == "recover-admin" {
		password, err := admin.RecoveryPassword(os.Getenv("SB_RECOVERY_PASSWORD"), os.Getenv("SB_RECOVERY_PASSWORD_FILE"))
		if err != nil {
			return err
		}
		recovery = admin.RecoveryInput{TenantID: *tenant, UserID: *userID, ExpectedRevision: *expectedRevision, RequestID: *requestID, Reason: *reason, NewPassword: password}
		if err := recovery.Validate(); err != nil {
			return err
		}
	}
	p, e := store.Open(ctx, dsn)
	if e != nil {
		if command == "recover-admin" || command == "inspect-admin" {
			return admin.RecoveryFailure(e)
		}
		return e
	}
	defer p.Close()
	switch command {
	case "inspect-admin":
		result, err := admin.InspectAdministrator(ctx, p, *tenant, *username)
		if err != nil {
			return admin.RecoveryFailure(err)
		}
		return json.NewEncoder(os.Stdout).Encode(result)
	case "recover-admin":
		result, err := admin.RecoverAdministrator(ctx, p, recovery)
		if err != nil {
			return admin.RecoveryFailure(err)
		}
		return json.NewEncoder(os.Stdout).Encode(result)
	case "bootstrap":
		if *ifMissing {
			return admin.BootstrapIfMissing(ctx, p, *tenant, *name, *username, os.Getenv("SB_BOOTSTRAP_PASSWORD"), *role)
		}
		return admin.Bootstrap(ctx, p, *tenant, *name, *username, os.Getenv("SB_BOOTSTRAP_PASSWORD"), *role)
	case "runtime-role":
		return admin.CreateRuntimeRole(ctx, p, os.Getenv("SB_RUNTIME_DB_PASSWORD"))
	case "provision-agent":
		id, e := admin.Provision(ctx, p, *tenant, *sensor, *name, *ca, *dir)
		if e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(id)
	default:
		return fmt.Errorf("未知管理命令")
	}
}
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, "管理操作失败:", e)
		os.Exit(1)
	}
}
