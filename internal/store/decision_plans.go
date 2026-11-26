package store

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/decision"
	"github.com/kkx600/StarBeacon/internal/model"
)

const planDeadline = `COALESCE(v.confirmation_deadline,timezone('UTC',timezone('UTC',v.created_at)+interval '15 minutes'))`
const planColumns = continuousColumns + `,COALESCE(r.state,''),COALESCE(r.plan_sha256,''),
	COALESCE(r.actor_id,''),COALESCE(r.reason,''),r.created_at,COALESCE(c.task_id,''),COALESCE(t.state,'')`
const planTables = ` FROM decision_continuous_runs v
 LEFT JOIN decision_plan_reviews r ON (r.tenant_id,r.evaluation_id)=(v.tenant_id,v.evaluation_id) AND r.expires_at>now()
 LEFT JOIN decision_responses c ON (c.tenant_id,c.evaluation_id,c.created_by)=(v.tenant_id,v.evaluation_id,v.created_by) AND c.expires_at>now()
 LEFT JOIN sensor_tasks t ON t.tenant_id=v.tenant_id AND t.id=COALESCE(NULLIF(v.task_id,''),c.task_id)`
const actionablePlan = `v.state='awaiting_confirmation' AND r.evaluation_id IS NULL AND c.evaluation_id IS NULL`

func decisionEventHasPlan(ctx context.Context, tx pgx.Tx, policy decision.Record, currentEvaluation, event, rawSHA256 string) (bool, error) {
	var exists bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM decision_continuous_runs v
		WHERE v.tenant_id=$1 AND v.policy_id=$2 AND v.policy_revision=$3 AND v.event_id=$4 AND v.raw_sha256=$5
		AND v.evaluation_id<>$6 AND v.state='awaiting_confirmation' AND v.expires_at>now())`,
		policy.TenantID, policy.ID, policy.Revision, event, rawSHA256, currentEvaluation).Scan(&exists)
	return exists, err
}

func readDecisionPlan(row interface{ Scan(...any) error }, now time.Time) (decision.PlanItem, error) {
	var item decision.PlanItem
	var review decision.PlanReview
	var reviewed *time.Time
	var confirmed string
	run, err := readContinuousRecord(row, &review.State, &review.PlanSHA256, &review.ActorID, &review.Reason, &reviewed, &confirmed, &item.TaskState)
	if err != nil {
		return item, err
	}
	item.Run, item.State, item.TaskID = run, run.State, run.TaskID
	if review.State != "" {
		if reviewed == nil || reviewed.Before(run.CreatedAt) || run.State != "awaiting_confirmation" || confirmed != "" ||
			review.PlanSHA256 != run.SHA256 || review.State == "rejected" && (review.ActorID != run.CreatedBy ||
			!(decision.RejectPlan{PlanSHA256: review.PlanSHA256, Reason: review.Reason}).Valid() || !reviewed.Before(run.ConfirmationDeadline())) ||
			review.State == "expired" && (review.ActorID != "" || review.Reason != "" || reviewed.Before(run.ConfirmationDeadline())) {
			return item, decision.ErrSource
		}
		review.ReviewedAt = reviewed.UTC()
		item.State, item.Review = review.State, &review
	} else if confirmed != "" {
		item.State, item.TaskID = "confirmed", confirmed
	} else if run.State == "awaiting_confirmation" && !run.ConfirmationDeadline().After(now) {
		item.State = "expired"
	}
	return item, nil
}

func (p *Postgres) DecisionPlans(ctx context.Context, u model.Principal, view, cursor string, limit int) (decision.PlanPage, error) {
	page := decision.PlanPage{Items: []decision.PlanItem{}}
	if !slices.Contains([]string{"pending", "history", "feedback"}, view) || cursor != "" && !contract.ValidID(cursor) || limit < 1 || limit > 100 {
		return page, decision.ErrInput
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := decisionPolicyUser(ctx, tx, u, false); err != nil {
			return err
		}
		at, filter, comparison, direction := "v.created_at", "", "<", " DESC"
		now := time.Now().UTC()
		switch view {
		case "pending":
			at, comparison, direction = planDeadline, ">", " ASC"
			filter = " AND " + actionablePlan + " AND " + at + ">$5"
		case "feedback":
			filter = " AND r.state='rejected'"
		}
		var anchor *time.Time
		if cursor != "" {
			if err := tx.QueryRow(ctx, `SELECT `+at+` FROM decision_continuous_runs v
				WHERE v.tenant_id=$1 AND v.created_by=$2 AND v.id=$3 AND v.expires_at>$4`, u.TenantID, u.ID, cursor, now).
				Scan(&anchor); err != nil {
				return err
			}
		}
		rows, err := tx.Query(ctx, `SELECT `+planColumns+planTables+`
			WHERE v.tenant_id=$1 AND v.created_by=$2 AND ($3::timestamptz IS NULL OR (`+at+`,v.id)`+comparison+`($3,$4))
			AND v.expires_at>$5`+filter+` ORDER BY `+at+direction+`,v.id`+direction+` LIMIT $6`,
			u.TenantID, u.ID, anchor, cursor, now, limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			item, err := readDecisionPlan(rows, now)
			if err != nil {
				return err
			}
			page.Items = append(page.Items, item)
		}
		return rows.Err()
	})
	if len(page.Items) > limit {
		page.NextCursor = page.Items[limit-1].Run.ID
		page.Items = page.Items[:limit]
	}
	return page, err
}

func saveDecisionPlanReview(ctx context.Context, tx pgx.Tx, run decision.ContinuousRecord, review decision.PlanReview) error {
	_, err := tx.Exec(ctx, `INSERT INTO decision_plan_reviews(tenant_id,evaluation_id,plan_sha256,state,actor_id,reason,created_at,expires_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, run.TenantID, run.EvaluationID, review.PlanSHA256, review.State, review.ActorID,
		review.Reason, review.ReviewedAt, run.ExpiresAt)
	return err
}

func (p *Postgres) RejectDecisionPlan(ctx context.Context, u model.Principal, evaluation string, input decision.RejectPlan) (decision.PlanReview, error) {
	var review decision.PlanReview
	if !contract.ValidID(evaluation) || !input.Valid() {
		return review, decision.ErrInput
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := responseTaskActor(ctx, tx, u); err != nil {
			return err
		}
		if err := lockDecisionAutomation(ctx, tx, u.TenantID); err != nil {
			return err
		}
		now := time.Now().UTC().Truncate(time.Microsecond)
		item, err := readDecisionPlan(tx.QueryRow(ctx, `SELECT `+planColumns+planTables+`
			WHERE v.tenant_id=$1 AND v.evaluation_id=$2 AND v.created_by=$3 AND v.expires_at>$4`, u.TenantID, evaluation, u.ID, now), now)
		if err != nil {
			return err
		}
		if item.Run.SHA256 != input.PlanSHA256 {
			return ErrConflict
		}
		if item.State == "rejected" && item.Review.Reason == input.Reason {
			review = *item.Review
			return nil
		}
		if item.State != "awaiting_confirmation" {
			return decision.ErrPlanClosed
		}
		review = decision.PlanReview{State: "rejected", PlanSHA256: input.PlanSHA256, ActorID: u.ID, Reason: input.Reason, ReviewedAt: now}
		if err := saveDecisionPlanReview(ctx, tx, item.Run, review); err != nil {
			return err
		}
		return insertOperationAudit(ctx, tx, u, "decision.plan.reject", item.Run.ID, model.RequestMetadataFrom(ctx).RequestID)
	})
	return review, err
}

func decisionPlanForConfirmation(ctx context.Context, tx pgx.Tx, u model.Principal, evaluation string, now time.Time) (*decision.PlanItem, error) {
	item, err := readDecisionPlan(tx.QueryRow(ctx, `SELECT `+planColumns+planTables+`
		WHERE v.tenant_id=$1 AND v.evaluation_id=$2 AND v.created_by=$3 AND v.expires_at>$4`, u.TenantID, evaluation, u.ID, now), now)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	switch item.State {
	case "awaiting_confirmation":
		return &item, nil
	case "queued", "skipped":
		return nil, decision.ErrPermission
	default:
		return nil, decision.ErrPlanClosed
	}
}
