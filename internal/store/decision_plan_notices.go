package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/decision"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/notify"
	"github.com/kkx600/StarBeacon/internal/secrets"
)

// 确认和过期竞争时只保留一个结果。过期与通知登记同事务，失败后让通知工作进程重试。
func (p *Postgres) ExpireDecisionPlans(ctx context.Context, tenant string, vault *secrets.Vault) error {
	return p.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout='2s'; SET LOCAL statement_timeout='5s'`); err != nil {
			return err
		}
		if err := lockDecisionAutomation(ctx, tx, tenant); err != nil {
			return err
		}
		now := time.Now().UTC().Truncate(time.Microsecond)
		rows, err := tx.Query(ctx, `SELECT `+planColumns+planTables+` WHERE v.tenant_id=$1 AND v.expires_at>$2
			AND v.confirmation_deadline IS NOT NULL AND `+actionablePlan+` AND `+planDeadline+`<=$2 ORDER BY `+planDeadline+`,v.id LIMIT 4`, tenant, now)
		if err != nil {
			return err
		}
		runs, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (decision.PlanItem, error) { return readDecisionPlan(row, now) })
		if err != nil {
			return err
		}
		for _, item := range runs {
			run := item.Run
			review := decision.PlanReview{State: "expired", PlanSHA256: run.SHA256, ReviewedAt: now}
			if err := saveDecisionPlanReview(ctx, tx, run, review); err != nil {
				return err
			}
			actor := model.Principal{TenantID: tenant, ID: run.CreatedBy}
			if err := insertOperationAudit(ctx, tx, actor, "decision.plan.expired", run.ID, run.ID); err != nil {
				return err
			}
			message := notify.Message{TenantID: tenant, BatchID: run.ID, DecisionTimeout: &notify.DecisionTimeout{PlanID: run.ID, ExpiredAt: run.ConfirmationDeadline()}}
			if err := enqueueMessageTx(ctx, tx, message, vault, ""); err != nil {
				return err
			}
		}
		return nil
	})
}
