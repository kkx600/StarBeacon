// Package migrations 将迁移随管理工具交付，应用运行账号不持有 DDL 权限。
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS
