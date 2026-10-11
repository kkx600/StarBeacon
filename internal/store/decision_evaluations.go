package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/decision"
	"github.com/kkx600/StarBeacon/internal/model"
)

const decisionEvaluationColumns = `v.tenant_id,v.id,v.created_by,v.policy_id,v.triage_id,v.status,v.created_at,v.expires_at,v.record`

func readDecisionEvaluation(row interface{ Scan(...any) error }) (decision.Evaluation, error) {
	var record decision.Evaluation
	var tenant, id, owner, policy, triage, status string
	var created, expiry time.Time
	var raw []byte
	if err := row.Scan(&tenant, &id, &owner, &policy, &triage, &status, &created, &expiry, &raw); err != nil {
		return record, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if len(raw) > 65536 || decoder.Decode(&record) != nil {
		return record, errors.New("决策评估档案不完整")
	}
	sealed, err := record.Seal()
	if err != nil || sealed.SHA256 != record.SHA256 || tenant != record.TenantID || id != record.ID || owner != record.CreatedBy || policy != record.Result.PolicyID || triage != record.Result.TriageID || status != record.Result.Status || !created.Equal(record.Result.EvaluatedAt) || !expiry.Equal(record.ExpiresAt) {
		return record, errors.New("决策评估档案与持久身份不一致")
	}
	return record, nil
}

func (p *Postgres) DecisionEvaluation(ctx context.Context, u model.Principal, id string) (decision.Evaluation, error) {
	var record decision.Evaluation
	if !contract.ValidID(id) {
		return record, decision.ErrInput
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := decisionPolicyUser(ctx, tx, u, false); err != nil {
			return err
		}
		var err error
		record, err = readDecisionEvaluation(tx.QueryRow(ctx, `SELECT `+decisionEvaluationColumns+` FROM decision_evaluations v WHERE v.tenant_id=$1 AND v.id=$2 AND v.created_by=$3 AND v.expires_at>now()`, u.TenantID, id, u.ID))
		return err
	})
	return record, err
}

// 序号在租户评估锁内分配，目录按持久提交顺序倒序；新增记录只在刷新首屏时出现。
// 游标必须是本人尚未到期的记录，不能借其他租户或账号的标识探测目录位置。
func (p *Postgres) DecisionEvaluations(ctx context.Context, u model.Principal, q decision.EvaluationQuery) (decision.EvaluationPage, error) {
	page := decision.EvaluationPage{Items: []decision.Evaluation{}}
	if q.Validate() != nil {
		return page, decision.ErrInput
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout='2s'; SET LOCAL statement_timeout='5s'`); err != nil {
			return err
		}
		if err := decisionPolicyUser(ctx, tx, u, false); err != nil {
			return err
		}
		var after int64
		if q.Cursor != "" {
			if err := tx.QueryRow(ctx, `SELECT sequence FROM decision_evaluations WHERE tenant_id=$1 AND id=$2 AND created_by=$3 AND expires_at>now()`, u.TenantID, q.Cursor, u.ID).Scan(&after); err != nil {
				return err
			}
		}
		rows, err := tx.Query(ctx, `SELECT `+decisionEvaluationColumns+` FROM decision_evaluations v WHERE v.tenant_id=$1 AND v.created_by=$2 AND v.expires_at>now() AND ($3::bigint=0 OR v.sequence<$3) AND ($4='' OR v.policy_id=$4) AND ($5='' OR v.triage_id=$5) AND ($6='' OR v.status=$6) ORDER BY v.sequence DESC LIMIT $7`, u.TenantID, u.ID, after, q.PolicyID, q.TriageID, q.Status, q.Limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			record, err := readDecisionEvaluation(rows)
			if err != nil {
				return err
			}
			page.Items = append(page.Items, record)
		}
		return rows.Err()
	})
	if len(page.Items) > q.Limit {
		page.NextCursor = page.Items[q.Limit-1].ID
		page.Items = page.Items[:q.Limit]
	}
	return page, err
}
