package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/model"
)

// RecordSearchExport 记录已准备的导出；不宣称浏览器已经完整接收文件。
func (p *Postgres) RecordSearchExport(ctx context.Context, u model.Principal, dataset, request string) error {
	if (dataset != "alerts" && dataset != "context") || !contract.ValidID(request) {
		return errors.New("导出审计范围无效")
	}
	return p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := savedSearchUser(ctx, tx, u); err != nil {
			return err
		}
		return insertOperationAudit(ctx, tx, u, "search.export.prepare."+dataset, request, request)
	})
}
