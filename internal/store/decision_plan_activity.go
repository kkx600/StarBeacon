package store

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/decision"
	"github.com/kkx600/StarBeacon/internal/model"
)

// 流水只引用当前账号的档案和有可核验回执的设备结果。
func (p *Postgres) DecisionPlanActivity(ctx context.Context, u model.Principal, cursor string, limit int) (decision.ActivityPage, error) {
	out := decision.ActivityPage{Items: []decision.PlanActivity{}}
	at, key, err := decision.ActivityCursor(cursor)
	if err != nil || limit < 1 || limit > 100 {
		return out, decision.ErrInput
	}
	err = p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := decisionPolicyUser(ctx, tx, u, false); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SET LOCAL statement_timeout='3s'`); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `WITH runs AS (
			SELECT * FROM decision_continuous_runs WHERE tenant_id=$1 AND created_by=$2 AND expires_at>now()
		), authorized AS (
			SELECT task_id, 'automatic' AS kind FROM runs WHERE state='queued'
			UNION ALL SELECT task_id, 'manual' FROM decision_responses WHERE tenant_id=$1 AND created_by=$2 AND expires_at>now()
		), tasks AS (
			SELECT t.*,a.kind AS origin FROM authorized a JOIN sensor_tasks t ON t.tenant_id=$1 AND t.id=a.task_id AND t.created_by=$2
				WHERE t.retain_until>now() AND t.kind='response.block'
		), activity(id,at,kind,state,object,code,task_id) AS (
			SELECT j.id,COALESCE(j.finished_at,j.created_at),'triage',j.state,j.event_id,j.result->>'code',''
				FROM alert_triage_jobs j WHERE j.tenant_id=$1 AND j.created_by=$2 AND j.expires_at>now()
			UNION ALL SELECT v.id,v.created_at,
				CASE WHEN v.record->>'code'='target_protected' THEN 'protection' ELSE 'plan' END,
				v.state,v.event_id,v.record->>'code','' FROM runs v
			UNION ALL SELECT 'review_'||v.id,r.created_at,'review',r.state,v.event_id,r.reason,''
				FROM runs v JOIN decision_plan_reviews r ON (r.tenant_id,r.evaluation_id)=(v.tenant_id,v.evaluation_id)
				WHERE r.expires_at>now()
			UNION ALL SELECT t.id,t.updated_at,t.origin,t.state,COALESCE(t.receipt->'result'->'observation'->>'target_ip',''),
				t.receipt->>'code',t.id FROM tasks t
			UNION ALL SELECT u.id,u.updated_at,'release',u.receipt->'result'->'observation'->>'state',
				u.receipt->'result'->'observation'->>'target_ip','',u.id
				FROM sensor_tasks u WHERE u.tenant_id=$1 AND u.created_by=$2 AND u.state='succeeded' AND u.retain_until>now()
				AND u.kind IN ('response.revoke','response.read') AND u.receipt->'result'->'observation'->>'state' IN ('expired','revoked')
				AND EXISTS(SELECT 1 FROM tasks t WHERE t.state='succeeded' AND (t.sensor_id,t.registration_id)=(u.sensor_id,u.registration_id)
					AND (t.receipt->'result'->'observation'->>'lease_id',t.receipt->'result'->'observation'->>'owner_sha256')=
					    (u.receipt->'result'->'observation'->>'lease_id',u.receipt->'result'->'observation'->>'owner_sha256'))
		)
		SELECT id,at,kind,state,COALESCE(object,''),COALESCE(code,''),task_id FROM activity
		WHERE $3::timestamptz IS NULL OR (at,id)<($3,$4) ORDER BY at DESC,id DESC LIMIT $5`,
			u.TenantID, u.ID, at, key, limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var item decision.PlanActivity
			if err := rows.Scan(&item.ID, &item.At, &item.Kind, &item.State, &item.Object, &item.Code, &item.TaskID); err != nil {
				return err
			}
			out.Items = append(out.Items, item)
		}
		return rows.Err()
	})
	if len(out.Items) > limit {
		out.Items = out.Items[:limit]
		out.NextCursor = out.Items[limit-1].Cursor()
	}
	return out, err
}
