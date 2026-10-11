package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/decision"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/triage"
)

const decisionResponseColumns = `v.tenant_id,v.id,v.created_by,v.evaluation_id,v.task_id,v.created_at,v.expires_at,v.input_hash,v.record`

func decisionResponseInput(id string, request decision.ResponseRequest) string {
	return decision.Digest(struct {
		EvaluationID string                   `json:"evaluation_id"`
		Request      decision.ResponseRequest `json:"request"`
	}{id, request})
}

func readDecisionResponse(row interface{ Scan(...any) error }) (decision.ResponseRecord, error) {
	var record decision.ResponseRecord
	var tenant, id, owner, evaluation, task, input string
	var created, expiry time.Time
	var raw []byte
	if err := row.Scan(&tenant, &id, &owner, &evaluation, &task, &created, &expiry, &input, &raw); err != nil {
		return record, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if len(raw) > 16384 || decoder.Decode(&record) != nil {
		return record, decision.ErrSource
	}
	sealed, err := record.Seal()
	if err != nil || sealed.SHA256 != record.SHA256 || record.TenantID != tenant || record.ID != id || record.CreatedBy != owner || record.EvaluationID != evaluation || record.TaskID != task || !record.CreatedAt.Equal(created) || !record.ExpiresAt.Equal(expiry) || input != decisionResponseInput(evaluation, record.Request) {
		return record, decision.ErrSource
	}
	return record, nil
}

// 原键确认只返回同一账号的原授权；策略停用、材料回收或设备离线不会补发任务。
func (p *Postgres) ExistingDecisionResponse(ctx context.Context, u model.Principal, id, key string, request decision.ResponseRequest) (decision.ResponseRecord, error) {
	var record decision.ResponseRecord
	if !contract.ValidID(id) || !contract.ValidID(key) || len(key) < 8 || request.Validate() != nil {
		return record, decision.ErrInput
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := decisionPolicyUser(ctx, tx, u, true); err != nil {
			return err
		}
		return existingDecisionResponse(ctx, tx, u, id, key, request, &record)
	})
	return record, err
}

func existingDecisionResponse(ctx context.Context, tx pgx.Tx, u model.Principal, id, key string, request decision.ResponseRequest, record *decision.ResponseRecord) error {
	var prior string
	if err := tx.QueryRow(ctx, `SELECT input_hash FROM decision_responses WHERE tenant_id=$1 AND created_by=$2 AND key_hash=$3`, u.TenantID, u.ID, Hash(key)).Scan(&prior); err != nil {
		return err
	}
	if prior != decisionResponseInput(id, request) {
		return ErrConflict
	}
	var err error
	*record, err = readDecisionResponse(tx.QueryRow(ctx, `SELECT `+decisionResponseColumns+` FROM decision_responses v WHERE v.tenant_id=$1 AND v.created_by=$2 AND v.key_hash=$3 AND v.expires_at>now()`, u.TenantID, u.ID, Hash(key)))
	return err
}

func (p *Postgres) DecisionResponse(ctx context.Context, u model.Principal, id string) (*decision.ResponseRecord, error) {
	if !contract.ValidID(id) {
		return nil, decision.ErrInput
	}
	var record decision.ResponseRecord
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := decisionPolicyUser(ctx, tx, u, false); err != nil {
			return err
		}
		var err error
		record, err = readDecisionResponse(tx.QueryRow(ctx, `SELECT `+decisionResponseColumns+` FROM decision_responses v WHERE v.tenant_id=$1 AND v.evaluation_id=$2 AND v.created_by=$3 AND v.expires_at>now()`, u.TenantID, id, u.ID))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return &record, err
}

// 授权档案、签名任务和两份审计同事务提交；任一失败均不留下可投递的任务。
func (p *Postgres) CreateDecisionResponse(ctx context.Context, u model.Principal, id, key string, request decision.ResponseRequest, evidence triage.Evidence, signer ed25519.PrivateKey) (decision.ResponseRecord, error) {
	var record decision.ResponseRecord
	if !contract.ValidID(id) || !contract.ValidID(key) || len(key) < 8 || request.Validate() != nil {
		return record, decision.ErrInput
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := responseTaskActor(ctx, tx, u); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, u.TenantID+"/decision-response"); err != nil {
			return err
		}
		err := existingDecisionResponse(ctx, tx, u, id, key, request, &record)
		if err == nil {
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		// 同一评估只能授权一次；换请求键、换探针或延长期限不会产生第二次处置。
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM decision_responses WHERE tenant_id=$1 AND evaluation_id=$2 AND created_by=$3)`, u.TenantID, id, u.ID).Scan(&exists); err != nil {
			return err
		}
		if exists {
			return ErrConflict
		}
		// 评估档案不可更新；读取并校验原摘要，不申请行锁所需的 UPDATE 权限。
		evaluation, err := readDecisionEvaluation(tx.QueryRow(ctx, `SELECT `+decisionEvaluationColumns+` FROM decision_evaluations v WHERE v.tenant_id=$1 AND v.id=$2 AND v.created_by=$3 AND v.expires_at>now()`, u.TenantID, id, u.ID))
		if err != nil {
			return err
		}
		policy, err := readDecisionPolicy(tx.QueryRow(ctx, `SELECT `+decisionPolicyColumns+` FROM decision_policies h JOIN decision_policy_revisions v ON v.tenant_id=h.tenant_id AND v.policy_id=h.id AND v.revision=h.revision WHERE h.tenant_id=$1 AND h.id=$2 FOR SHARE OF h`, u.TenantID, evaluation.Policy.ID))
		if err != nil {
			return err
		}
		job, err := scanTriage(tx.QueryRow(ctx, `SELECT `+triageJSON+` FROM alert_triage_jobs WHERE tenant_id=$1 AND id=$2 AND created_by=$3 AND expires_at>now() FOR SHARE`, u.TenantID, evaluation.Result.TriageID, u.ID))
		if err != nil {
			return err
		}
		now := time.Now().UTC().Truncate(time.Microsecond)
		intent, err := decision.ResponseIntent(ctx, evaluation, policy, job, evidence, request, now)
		if err != nil {
			return err
		}
		var registration string
		if err := tx.QueryRow(ctx, `SELECT registration_id FROM sensors WHERE tenant_id=$1 AND id=$2 AND active FOR UPDATE`, u.TenantID, request.SensorID).Scan(&registration); err != nil {
			return err
		}
		if registration != request.RegistrationID {
			return ErrConflict
		}
		raw, err := json.Marshal(intent)
		if err != nil {
			return err
		}
		taskID, err := createTaskTx(ctx, tx, u, request.SensorID, "response.block", "decision_response_"+Hash(key)[:40], raw, signer, true)
		if err != nil {
			return err
		}
		record = decision.ResponseRecord{SchemaVersion: decision.ResponseSchema, TenantID: u.TenantID, ID: RandomID("decision_response_"), CreatedBy: u.ID, CreatedAt: now, EvaluationID: id, EvaluationSHA256: evaluation.SHA256, PolicyID: policy.ID, PolicyRevision: policy.Revision, DefinitionSHA256: policy.DefinitionSHA256, TriageID: job.ID, EvidenceSHA256: evaluation.Result.EvidenceSHA256, TargetIP: intent.TargetIP, Request: request, TaskID: taskID}
		if err := tx.QueryRow(ctx, `SELECT $2::timestamptz+make_interval(days=>COALESCE((SELECT days FROM retention_policies WHERE tenant_id=$1 AND category='operations'),180))`, u.TenantID, now).Scan(&record.ExpiresAt); err != nil {
			return err
		}
		record.ExpiresAt = record.ExpiresAt.UTC()
		record, err = record.Seal()
		if err != nil {
			return err
		}
		raw, err = json.Marshal(record)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO decision_responses(tenant_id,id,created_by,evaluation_id,task_id,created_at,expires_at,key_hash,input_hash,record) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, u.TenantID, record.ID, u.ID, id, taskID, now, record.ExpiresAt, Hash(key), decisionResponseInput(id, request), raw); err != nil {
			return err
		}
		return insertOperationAudit(ctx, tx, u, "decision.response.confirm", record.ID, model.RequestMetadataFrom(ctx).RequestID)
	})
	return record, err
}
