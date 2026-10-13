package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/decision"
	"github.com/kkx600/StarBeacon/internal/model"
)

const decisionPolicyColumns = `v.tenant_id,v.policy_id,v.revision,v.name,v.description,v.active,v.definition,v.definition_sha256,v.created_by,v.created_at,v.expires_at`

func decisionPolicyUser(ctx context.Context, tx pgx.Tx, u model.Principal, write bool) error {
	if !contract.ValidID(u.TenantID) || !contract.ValidID(u.ID) || u.Role != "admin" && u.Role != "viewer" || write && u.Role != "admin" {
		return decision.ErrPermission
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared(hashtextextended($1,0))`, u.TenantID+"/users"); err != nil {
		return err
	}
	var active, tenantActive bool
	var role string
	var revision int64
	if err := tx.QueryRow(ctx, `SELECT u.active,u.role,u.revision,t.active FROM users u JOIN tenants t ON t.id=u.tenant_id WHERE u.tenant_id=$1 AND u.id=$2`, u.TenantID, u.ID).Scan(&active, &role, &revision, &tenantActive); err != nil {
		return err
	}
	if !active || !tenantActive || role != u.Role || u.CredentialRevision > 0 && revision != u.CredentialRevision {
		return decision.ErrPermission
	}
	return nil
}

func readDecisionPolicy(row interface{ Scan(...any) error }) (decision.Record, error) {
	var record decision.Record
	var definition json.RawMessage
	if err := row.Scan(&record.TenantID, &record.ID, &record.Revision, &record.Name, &record.Description, &record.Active, &definition, &record.DefinitionSHA256, &record.CreatedBy, &record.CreatedAt, &record.ExpiresAt); err != nil {
		return record, err
	}
	if json.Unmarshal(definition, &record.Definition) != nil || record.Validate() != nil {
		return record, errors.New("决策策略修订不完整")
	}
	return record, nil
}

func (p *Postgres) DecisionPolicies(ctx context.Context, u model.Principal, q decision.ListQuery) (decision.Page, error) {
	page := decision.Page{Items: []decision.Record{}}
	if q.Validate() != nil {
		return page, decision.ErrInput
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := decisionPolicyUser(ctx, tx, u, false); err != nil {
			return err
		}
		pattern := "%" + strings.NewReplacer("!", "!!", "%", "!%", "_", "!_").Replace(q.Keyword) + "%"
		rows, err := tx.Query(ctx, `SELECT `+decisionPolicyColumns+` FROM decision_policies h JOIN decision_policy_revisions v ON v.tenant_id=h.tenant_id AND v.policy_id=h.id AND v.revision=h.revision WHERE h.tenant_id=$1 AND h.id>$2 AND h.name ILIKE $3 ESCAPE '!' AND ($4='' OR h.active=($4='true')) ORDER BY h.id LIMIT $5`, u.TenantID, q.Cursor, pattern, q.Active, q.Limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			record, err := readDecisionPolicy(rows)
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

func (p *Postgres) DecisionPolicy(ctx context.Context, u model.Principal, id string, revision int64) (decision.Record, error) {
	var result decision.Record
	if !contract.ValidID(id) || revision < 1 || revision > decision.MaxRevision {
		return result, decision.ErrInput
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := decisionPolicyUser(ctx, tx, u, false); err != nil {
			return err
		}
		var err error
		result, err = readDecisionPolicy(tx.QueryRow(ctx, `SELECT `+decisionPolicyColumns+` FROM decision_policy_revisions v WHERE v.tenant_id=$1 AND v.policy_id=$2 AND v.revision=$3 AND (v.expires_at>now() OR EXISTS(SELECT 1 FROM decision_policies h WHERE h.tenant_id=v.tenant_id AND h.id=v.policy_id AND h.revision=v.revision))`, u.TenantID, id, revision))
		return err
	})
	return result, err
}

func (p *Postgres) SaveDecisionPolicy(ctx context.Context, u model.Principal, key string, c decision.Change) (decision.Record, error) {
	var result decision.Record
	if c.Validate() != nil || !contract.ValidID(key) {
		return result, decision.ErrInput
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout='2s'; SET LOCAL statement_timeout='5s'`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, u.TenantID+"/decision-policies"); err != nil {
			return err
		}
		if err := decisionPolicyUser(ctx, tx, u, true); err != nil {
			return err
		}
		var inputHash string
		err := tx.QueryRow(ctx, `SELECT input_hash FROM decision_policy_revisions WHERE tenant_id=$1 AND created_by=$2 AND key_hash=$3`, u.TenantID, u.ID, Hash(key)).Scan(&inputHash)
		if err == nil {
			if inputHash != decision.Digest(c) {
				return ErrConflict
			}
			result, err = readDecisionPolicy(tx.QueryRow(ctx, `SELECT `+decisionPolicyColumns+` FROM decision_policy_revisions v WHERE v.tenant_id=$1 AND v.created_by=$2 AND v.key_hash=$3`, u.TenantID, u.ID, Hash(key)))
			if err == nil && !result.ExpiresAt.After(time.Now()) {
				return ErrConflict
			}
			return err
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		var current decision.Record
		current, err = readDecisionPolicy(tx.QueryRow(ctx, `SELECT `+decisionPolicyColumns+` FROM decision_policies h JOIN decision_policy_revisions v ON v.tenant_id=h.tenant_id AND v.policy_id=h.id AND v.revision=h.revision WHERE h.tenant_id=$1 AND h.id=$2 FOR UPDATE OF h`, u.TenantID, c.ID))
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if errors.Is(err, pgx.ErrNoRows) && c.ExpectedRevision > 0 {
			return pgx.ErrNoRows
		}
		if current.Revision != c.ExpectedRevision {
			return ErrConflict
		}
		if current.Revision > 0 && current.Name == c.Name && current.Description == c.Description && current.Active == *c.Active && current.DefinitionSHA256 == decision.Digest(c.Definition) {
			return decision.ErrInput
		}
		if *c.Active && c.Definition.Continuous != nil && c.Definition.Continuous.Trigger != nil {
			var count int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM decision_policies h JOIN decision_policy_revisions v ON v.tenant_id=h.tenant_id AND v.policy_id=h.id AND v.revision=h.revision WHERE h.tenant_id=$1 AND h.id<>$2 AND h.active AND v.definition->'continuous'->'trigger' IS NOT NULL`, u.TenantID, c.ID).Scan(&count); err != nil {
				return err
			}
			if count >= 8 {
				return decision.ErrQuota
			}
		}
		var count int
		if current.Revision == 0 {
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM decision_policies WHERE tenant_id=$1`, u.TenantID).Scan(&count); err != nil {
				return err
			}
			if count >= decision.MaxPolicies {
				return decision.ErrQuota
			}
		}
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM decision_policy_revisions WHERE tenant_id=$1 AND created_at>now()-interval '24 hours'`, u.TenantID).Scan(&count); err != nil {
			return err
		}
		if count >= decision.MaxDailyChanges {
			return decision.ErrQuota
		}
		raw, err := json.Marshal(c.Definition)
		if err != nil {
			return err
		}
		result, err = readDecisionPolicy(tx.QueryRow(ctx, `INSERT INTO decision_policy_revisions AS v(tenant_id,policy_id,revision,name,description,active,definition,definition_sha256,created_by,key_hash,input_hash,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,now()+make_interval(days=>COALESCE((SELECT days FROM retention_policies WHERE tenant_id=$1 AND category='operations'),180))) RETURNING `+decisionPolicyColumns, u.TenantID, c.ID, c.ExpectedRevision+1, c.Name, c.Description, *c.Active, raw, decision.Digest(c.Definition), u.ID, Hash(key), decision.Digest(c)))
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO decision_policies(tenant_id,id,revision,name,active) VALUES($1,$2,$3,$4,$5) ON CONFLICT(tenant_id,id) DO UPDATE SET revision=EXCLUDED.revision,name=EXCLUDED.name,active=EXCLUDED.active`, u.TenantID, c.ID, result.Revision, c.Name, *c.Active); err != nil {
			return err
		}
		return insertOperationAudit(ctx, tx, u, "decision.policy.save", c.ID, model.RequestMetadataFrom(ctx).RequestID)
	})
	if err == nil && (result.TenantID != u.TenantID || result.CreatedBy != u.ID || result.ID != c.ID || result.Revision != c.ExpectedRevision+1 || result.Name != c.Name || result.Description != c.Description || result.Active != *c.Active || result.DefinitionSHA256 != decision.Digest(c.Definition)) {
		err = errors.New("决策策略原提交回执与输入不一致")
	}
	return result, err
}

// 仅评估当前策略与调用者自己的已存研判；输出不会进入设备任务或通知队列。
func (p *Postgres) EvaluateDecisionPolicy(ctx context.Context, u model.Principal, id string, request decision.EvaluateRequest) (decision.Result, error) {
	record, err := p.CreateDecisionEvaluation(ctx, u, RandomID("evaluation_request_"), decision.EvaluationRequest{PolicyID: id, ExpectedRevision: request.ExpectedRevision, TriageID: request.TriageID})
	return record.Result, err
}

// 原提交确认先读取不可变档案；当前策略已改变或研判已到期不改变已完成的历史判断。
func (p *Postgres) CreateDecisionEvaluation(ctx context.Context, u model.Principal, key string, request decision.EvaluationRequest) (decision.Evaluation, error) {
	var record decision.Evaluation
	if request.Validate() != nil || !contract.ValidID(key) {
		return record, decision.ErrInput
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout='2s'; SET LOCAL statement_timeout='5s'`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, u.TenantID+"/decision-policy-evaluations"); err != nil {
			return err
		}
		if err := decisionPolicyUser(ctx, tx, u, true); err != nil {
			return err
		}
		var prior string
		err := tx.QueryRow(ctx, `SELECT input_hash FROM decision_evaluations WHERE tenant_id=$1 AND created_by=$2 AND key_hash=$3`, u.TenantID, u.ID, Hash(key)).Scan(&prior)
		if err == nil {
			if prior != decision.Digest(request) {
				return ErrConflict
			}
			record, err = readDecisionEvaluation(tx.QueryRow(ctx, `SELECT `+decisionEvaluationColumns+` FROM decision_evaluations v WHERE v.tenant_id=$1 AND v.created_by=$2 AND v.key_hash=$3 AND v.expires_at>now()`, u.TenantID, u.ID, Hash(key)))
			return err
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		policy, err := readDecisionPolicy(tx.QueryRow(ctx, `SELECT `+decisionPolicyColumns+` FROM decision_policies h JOIN decision_policy_revisions v ON v.tenant_id=h.tenant_id AND v.policy_id=h.id AND v.revision=h.revision WHERE h.tenant_id=$1 AND h.id=$2 FOR SHARE OF h`, u.TenantID, request.PolicyID))
		if err != nil {
			return err
		}
		if policy.Revision != request.ExpectedRevision {
			return ErrConflict
		}
		var count int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM operation_audits WHERE tenant_id=$1 AND action='decision.policy.evaluate' AND created_at>now()-interval '24 hours'`, u.TenantID).Scan(&count); err != nil {
			return err
		}
		if count >= 1024 {
			return decision.ErrQuota
		}
		job, err := scanTriage(tx.QueryRow(ctx, `SELECT `+triageJSON+` FROM alert_triage_jobs WHERE tenant_id=$1 AND id=$2 AND created_by=$3 AND expires_at>now() FOR SHARE`, u.TenantID, request.TriageID, u.ID))
		if err != nil {
			return err
		}
		work, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
		defer cancel()
		result, err := decision.Evaluate(work, policy, job, time.Now().UTC().Truncate(time.Microsecond))
		if err != nil {
			return err
		}
		record = decision.Evaluation{SchemaVersion: decision.EvaluationSchema, TenantID: u.TenantID, ID: RandomID("evaluation_"), CreatedBy: u.ID, Policy: policy, Result: result}
		if err := tx.QueryRow(ctx, `SELECT $2::timestamptz+make_interval(days=>COALESCE((SELECT days FROM retention_policies WHERE tenant_id=$1 AND category='operations'),180))`, u.TenantID, result.EvaluatedAt).Scan(&record.ExpiresAt); err != nil {
			return err
		}
		record, err = record.Seal()
		if err != nil {
			return err
		}
		raw, err := json.Marshal(record)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO decision_evaluations(tenant_id,id,sequence,created_by,policy_id,triage_id,status,created_at,expires_at,key_hash,input_hash,record) VALUES($1,$2,(SELECT COALESCE(max(sequence),0)+1 FROM decision_evaluations WHERE tenant_id=$1),$3,$4,$5,$6,$7,$8,$9,$10,$11)`, u.TenantID, record.ID, u.ID, request.PolicyID, request.TriageID, result.Status, result.EvaluatedAt, record.ExpiresAt, Hash(key), decision.Digest(request), raw); err != nil {
			return err
		}
		return insertOperationAudit(ctx, tx, u, "decision.policy.evaluate", record.ID, model.RequestMetadataFrom(ctx).RequestID)
	})
	return record, err
}
