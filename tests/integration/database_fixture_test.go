//go:build integration

package integration

import (
	"context"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/kkx600/StarBeacon/internal/admin"
	"github.com/kkx600/StarBeacon/internal/store"
)

type isolatedDatabase struct {
	Owner, Runtime *store.Postgres
	OwnerDSN       string
	RuntimeDSN     string
	roles          []string
}

// 全库扫描与角色权限测试使用专属数据库，避免清理其他用例的租户或变更共享账号。
func newIsolatedDatabase(t *testing.T, ctx context.Context) *isolatedDatabase {
	t.Helper()
	if os.Getenv("SB_MODE") != "development" || os.Getenv("SB_MIGRATION_DATABASE_URL") == "" || os.Getenv("SB_DATABASE_URL") == "" {
		t.Skip("需要独立开发依赖")
	}
	control, err := store.Open(ctx, os.Getenv("SB_MIGRATION_DATABASE_URL"))
	require(t, err)
	runtimeConfig, err := pgx.ParseConfig(os.Getenv("SB_DATABASE_URL"))
	require(t, err)
	if runtimeConfig.User != "starbeacon_app" {
		control.Close()
		t.Fatal("独立数据库用例要求受控的运行账号")
	}
	name := store.RandomID("it_db_")
	_, err = control.Pool.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()+" TEMPLATE template0")
	if err != nil {
		control.Close()
		t.Fatal("创建独立验收数据库失败")
	}
	fixture := &isolatedDatabase{}
	t.Cleanup(func() {
		if fixture.Runtime != nil {
			fixture.Runtime.Close()
		}
		if fixture.Owner != nil {
			fixture.Owner.Close()
		}
		clean, stop := context.WithTimeout(context.Background(), 15*time.Second)
		defer stop()
		defer control.Close()
		if _, err := control.Pool.Exec(clean, "DROP DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
			t.Error("移除独立验收数据库失败", err)
		}
		for _, role := range fixture.roles {
			if _, err := control.Pool.Exec(clean, "DROP ROLE "+pgx.Identifier{role}.Sanitize()); err != nil {
				t.Error("移除独立验收角色失败", err)
			}
		}
	})
	fixture.OwnerDSN = testDatabaseURL(t, os.Getenv("SB_MIGRATION_DATABASE_URL"), name, "", "")
	fixture.RuntimeDSN = testDatabaseURL(t, os.Getenv("SB_DATABASE_URL"), name, "", "")
	fixture.Owner, err = store.Open(ctx, fixture.OwnerDSN)
	require(t, err)
	var actualDatabase string
	require(t, fixture.Owner.Pool.QueryRow(ctx, "SELECT current_database()").Scan(&actualDatabase))
	if actualDatabase != name {
		t.Fatal("连接没有指向专属验收数据库，拒绝执行迁移")
	}
	require(t, admin.Migrate(ctx, fixture.OwnerDSN))
	require(t, admin.CreateRuntimeRole(ctx, fixture.Owner, runtimeConfig.Password))
	fixture.Runtime, err = store.Open(ctx, fixture.RuntimeDSN)
	require(t, err)
	require(t, fixture.Runtime.Pool.QueryRow(ctx, "SELECT current_database()").Scan(&actualDatabase))
	if actualDatabase != name {
		t.Fatal("运行账号连接没有指向专属验收数据库")
	}
	require(t, fixture.Runtime.VerifyRuntimeRole(ctx))
	return fixture
}

func testDatabaseURL(t *testing.T, raw, database, role, password string) string {
	t.Helper()
	v, err := url.Parse(raw)
	if err != nil || (v.Scheme != "postgres" && v.Scheme != "postgresql") || v.Host == "" {
		t.Fatal("独立数据库用例要求 PostgreSQL 连接 URL")
	}
	if database != "" {
		v.Path, v.RawPath = "/"+database, ""
		query := v.Query()
		query.Del("dbname")
		v.RawQuery = query.Encode()
	}
	if role != "" {
		v.User = url.UserPassword(role, password)
		query := v.Query()
		query.Del("user")
		query.Del("password")
		v.RawQuery = query.Encode()
	}
	return v.String()
}

func oneConnectionStore(t *testing.T, ctx context.Context, dsn string, afterConnect func(context.Context, *pgx.Conn) error) *store.Postgres {
	t.Helper()
	config, err := pgxpool.ParseConfig(dsn)
	require(t, err)
	config.MinConns, config.MaxConns, config.AfterConnect = 0, 1, afterConnect
	pool, err := pgxpool.NewWithConfig(ctx, config)
	require(t, err)
	t.Cleanup(pool.Close)
	require(t, pool.Ping(ctx))
	return &store.Postgres{Pool: pool}
}
