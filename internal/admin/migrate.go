// Package admin 提供受控初始化工具，迁移权限不进入在线平台账号。
package admin

import (
	"context"
	"database/sql"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/kkx600/StarBeacon/migrations"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"
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
	_, e = provider.Up(ctx)
	return e
}
