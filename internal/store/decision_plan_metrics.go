package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/decision"
	"github.com/kkx600/StarBeacon/internal/model"
)

// 以本人已完成研判和设备回执为准。待确认表示当前存量，其余指标采用所选时区的半开自然日。
func (p *Postgres) DecisionPlanMetrics(ctx context.Context, u model.Principal, now time.Time, timezone string) (decision.PlanMetrics, error) {
	out, err := decision.PlanMetricsDay(now, timezone)
	if err != nil {
		return out, err
	}
	err = p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := decisionPolicyUser(ctx, tx, u, false); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SET LOCAL statement_timeout='3s'`); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `WITH triage AS (
			SELECT count(*) AS n,round(avg(extract(epoch FROM finished_at-started_at)*1000)
				FILTER (WHERE started_at<=finished_at))::bigint AS mean_ms
			FROM alert_triage_jobs WHERE tenant_id=$1 AND created_by=$2 AND state='succeeded' AND NOT cancel_requested
				AND finished_at>=$3 AND finished_at<$4
		), effects AS (
			SELECT t.id,EXISTS(SELECT 1 FROM decision_continuous_runs v
					WHERE v.tenant_id=t.tenant_id AND v.created_by=$2 AND v.task_id=t.id AND v.state='queued') AS automatic,
				EXISTS(SELECT 1 FROM decision_responses c
					WHERE c.tenant_id=t.tenant_id AND c.created_by=$2 AND c.task_id=t.id) AS confirmed
			FROM sensor_tasks t WHERE t.tenant_id=$1 AND t.created_by=$2 AND t.kind='response.block' AND t.state='succeeded'
				AND t.updated_at>=$3 AND t.updated_at<$4
		)
		SELECT triage.n,triage.mean_ms,
			(SELECT count(*) FROM decision_continuous_runs v WHERE v.tenant_id=$1 AND v.created_by=$2
			  AND v.state='awaiting_confirmation' AND v.expires_at>$5 AND `+planDeadline+`>$5
			  AND NOT EXISTS(SELECT 1 FROM decision_plan_reviews r WHERE (r.tenant_id,r.evaluation_id)=(v.tenant_id,v.evaluation_id))
			  AND NOT EXISTS(SELECT 1 FROM decision_responses c WHERE (c.tenant_id,c.evaluation_id,c.created_by)=(v.tenant_id,v.evaluation_id,v.created_by))),
			(SELECT count(*) FROM effects WHERE automatic OR confirmed),
			(SELECT count(*) FROM effects WHERE automatic),
			(SELECT count(*) FROM decision_plan_reviews r JOIN decision_continuous_runs v ON (v.tenant_id,v.evaluation_id)=(r.tenant_id,r.evaluation_id)
			  WHERE r.tenant_id=$1 AND v.created_by=$2 AND r.state='rejected' AND r.created_at>=$3 AND r.created_at<$4),
			(SELECT count(*) FROM decision_continuous_runs v WHERE v.tenant_id=$1 AND v.created_by=$2
			  AND v.record->>'code'='target_protected' AND v.created_at>=$3 AND v.created_at<$4)
		FROM triage`, u.TenantID, u.ID, out.Start, out.End, now).
			Scan(&out.TriageCount, &out.TriageMeanMS, &out.Pending, &out.Executed, &out.Automatic, &out.Rejected, &out.Protected)
	})
	return out, err
}
