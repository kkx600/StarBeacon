// Package admin 提供受控初始化工具，迁移权限不进入在线平台账号。
package admin

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/kkx600/StarBeacon/internal/assistant"
	"github.com/kkx600/StarBeacon/migrations"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivermigrate"
)

func Migrate(ctx context.Context, dsn string) error {
	db, e := sql.Open("pgx", dsn)
	if e != nil {
		return e
	}
	defer db.Close()
	locker, e := lock.NewPostgresSessionLocker()
	if e != nil {
		return e
	}
	provider, e := goose.NewProvider(goose.DialectPostgres, db, migrations.FS, goose.WithSessionLocker(locker))
	if e != nil {
		return e
	}
	defer provider.Close()
	pool, e := pgxpool.New(ctx, dsn)
	if e != nil {
		return e
	}
	defer pool.Close()
	connection, e := pool.Acquire(ctx)
	if e != nil {
		return e
	}
	defer connection.Release()
	// 队列迁移与业务迁移均只在管理命令执行，不扩大在线账号的 DDL 权限。
	if _, e = connection.Exec(ctx, `SELECT pg_advisory_lock(782301026)`); e != nil {
		return e
	}
	defer func() {
		clean, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if _, err := connection.Exec(clean, `SELECT pg_advisory_unlock(782301026)`); err != nil {
			_ = connection.Conn().Close(clean)
		}
	}()
	if _, e = connection.Exec(ctx, `CREATE SCHEMA IF NOT EXISTS starbeacon_jobs`); e != nil {
		return e
	}
	migrator, e := rivermigrate.New(riverpgxv5.New(pool), &rivermigrate.Config{Schema: assistant.QueueSchema})
	if e != nil {
		return e
	}
	// 上游迁移含枚举变更，其后续版本必须看到前一版本已提交的值。
	// 持有会话级锁串行化迁移，但让 River 为每个版本独立提交事务。
	if _, e = migrator.Migrate(ctx, rivermigrate.DirectionUp, nil); e != nil {
		return fmt.Errorf("后台作业数据库迁移失败：%w", e)
	}
	// 业务删除策略引用队列执行状态，首次安装必须先准备独立队列 schema。
	if _, e = provider.Up(ctx); e != nil {
		return e
	}
	return nil
}
