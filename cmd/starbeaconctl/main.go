package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/kkx600/StarBeacon/internal/admin"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/store"
)

func run() error {
	if len(os.Args) < 2 {
		return fmt.Errorf("用法: starbeaconctl migrate|bootstrap|dev-pki|provision-agent|runtime-role")
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
	if e := flags.Parse(os.Args[2:]); e != nil {
		return e
	}
	if command == "dev-pki" {
		return admin.DevPKI(*dir)
	}
	if command == "command-keys" {
		if e := os.MkdirAll(*dir, 0700); e != nil {
			return e
		}
		return control.GenerateKeys(filepath.Join(*dir, "command.key"), filepath.Join(*dir, "command.pub"))
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
	p, e := store.Open(ctx, dsn)
	if e != nil {
		return e
	}
	defer p.Close()
	switch command {
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
