//go:build integration

package integration

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/migrations"
)

func TestRetentionUpgradeKeepsCustomDurationsAndInitializesAllCategories(t *testing.T) {
	if os.Getenv("SB_MODE") != "development" || os.Getenv("SB_MIGRATION_DATABASE_URL") == "" {
		t.Skip("需要独立开发依赖")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	db, err := store.Open(ctx, os.Getenv("SB_MIGRATION_DATABASE_URL"))
	require(t, err)
	defer db.Close()
	tx, err := db.Pool.Begin(ctx)
	require(t, err)
	defer tx.Rollback(context.Background())
	// 事务中的独立 schema 复用实际表约束，回滚同时释放全部测试对象。
	schema := pgx.Identifier{store.RandomID("it_retention_")}.Sanitize()
	_, err = tx.Exec(ctx, "CREATE SCHEMA "+schema)
	require(t, err)
	_, err = tx.Exec(ctx, "SET LOCAL search_path TO "+schema+",public")
	require(t, err)
	_, err = tx.Exec(ctx, `CREATE TABLE tenants (LIKE public.tenants INCLUDING ALL);
CREATE TABLE retention_policies (LIKE public.retention_policies INCLUDING ALL);
INSERT INTO tenants(id,name) VALUES('existing','历史租户'),('custom','自定义策略租户');
INSERT INTO retention_policies(tenant_id,category,days) VALUES('existing','pcap',210),('custom','models',365)`)
	require(t, err)
	raw, err := migrations.FS.ReadFile("00009_retention_categories.sql")
	require(t, err)
	up := strings.Split(string(raw), "-- +goose Down")[0]
	for attempt := 0; attempt < 2; attempt++ {
		_, err = tx.Exec(ctx, up)
		require(t, err)
		var categories, unexpected int
		require(t, tx.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE (tenant_id='existing' AND category='pcap' AND days<>210)
 OR (tenant_id='custom' AND category='models' AND days<>365)
 OR (NOT(tenant_id='existing' AND category='pcap') AND NOT(tenant_id='custom' AND category='models') AND days<>180)) FROM retention_policies`).Scan(&categories, &unexpected))
		if categories != 20 || unexpected != 0 {
			t.Fatalf("类别补齐覆盖了自定义时长或遗漏默认类别：%d / %d", categories, unexpected)
		}
	}
}
