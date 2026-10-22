package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/decision"
	"github.com/kkx600/StarBeacon/internal/model"
	responseapi "github.com/kkx600/StarBeacon/internal/response"
	"github.com/kkx600/StarBeacon/internal/triage"
	"github.com/kkx600/StarBeacon/internal/watchlist"
)

type DecisionCandidate struct {
	Principal model.Principal
	Policy    decision.Record
	TriageID  string
}

func (c DecisionCandidate) Key() string {
	return "continuous_" + Hash(c.Principal.TenantID + "/" + c.Policy.ID + "/" + strconv.FormatInt(c.Policy.Revision, 10) + "/" + c.Policy.DefinitionSHA256 + "/" + c.TriageID)[:40]
}

// 有界读取、模型与账号绑定、启用时刻下界及不可变运行档案防止历史回灌和重复处置。
func (p *Postgres) ContinuousDecisionCandidates(ctx context.Context, tenant string) ([]DecisionCandidate, error) {
	out := []DecisionCandidate{}
	err := p.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL statement_timeout='3s'`); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT `+decisionPolicyColumns+`,j.id,u.revision FROM decision_policies h JOIN decision_policy_revisions v ON v.tenant_id=h.tenant_id AND v.policy_id=h.id AND v.revision=h.revision JOIN users u ON u.tenant_id=v.tenant_id AND u.id=v.created_by AND u.active AND u.role='admin' JOIN alert_triage_jobs j ON j.tenant_id=v.tenant_id AND j.created_by=v.created_by AND j.provider_id=v.definition->'continuous'->>'provider_id' AND j.provider_revision=(v.definition->'continuous'->>'provider_revision')::bigint AND j.created_at>=v.created_at AND j.expires_at>now() AND j.state='succeeded' AND NOT j.cancel_requested WHERE h.tenant_id=$1 AND h.active AND v.definition->>'mode' IN ('approval','automatic') AND NOT EXISTS(SELECT 1 FROM decision_continuous_runs r WHERE r.tenant_id=v.tenant_id AND r.policy_id=v.policy_id AND r.policy_revision=v.revision AND r.triage_id=j.id) ORDER BY j.created_at,j.id,v.policy_id LIMIT 16`, tenant)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c DecisionCandidate
			var raw []byte
			v := &c.Policy
			if err := rows.Scan(&v.TenantID, &v.ID, &v.Revision, &v.Name, &v.Description, &v.Active, &raw, &v.DefinitionSHA256, &v.CreatedBy, &v.CreatedAt, &v.ExpiresAt, &c.TriageID, &c.Principal.CredentialRevision); err != nil {
				return err
			}
			if json.Unmarshal(raw, &v.Definition) != nil || v.Validate() != nil {
				return decision.ErrSource
			}
			c.Principal.TenantID, c.Principal.ID, c.Principal.Role = tenant, v.CreatedBy, "admin"
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}

const continuousColumns = `v.tenant_id,v.id,v.created_by,v.evaluation_id,v.policy_id,v.policy_revision,v.triage_id,v.event_id,v.raw_sha256,v.sensor_id,v.connector_id,v.state,v.task_id,v.created_at,v.expires_at,v.record`

func readContinuousRecord(row interface{ Scan(...any) error }) (decision.ContinuousRecord, error) {
	var r decision.ContinuousRecord
	var raw []byte
	var tenant, id, owner, evaluation, policy, triageID, event, digest, sensor, connector, state, task string
	var revision int64
	var at, expiry time.Time
	if err := row.Scan(&tenant, &id, &owner, &evaluation, &policy, &revision, &triageID, &event, &digest, &sensor, &connector, &state, &task, &at, &expiry, &raw); err != nil {
		return r, err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if len(raw) > 16384 || d.Decode(&r) != nil {
		return r, decision.ErrSource
	}
	s, err := r.Seal()
	if err != nil || s.SHA256 != r.SHA256 || r.TenantID != tenant || r.ID != id || r.CreatedBy != owner || r.EvaluationID != evaluation || r.PolicyID != policy || r.PolicyRevision != revision || r.TriageID != triageID || r.EventID != event || r.RawSHA256 != digest || r.State != state || r.TaskID != task || !r.CreatedAt.Equal(at) || !r.ExpiresAt.Equal(expiry) {
		return r, decision.ErrSource
	}
	if r.Config.Automatic == nil && (sensor != "" || connector != "") || r.Config.Automatic != nil && (r.Config.Automatic.SensorID != sensor || r.Config.Automatic.ConnectorID != connector) {
		return r, decision.ErrSource
	}
	return r, nil
}

func (p *Postgres) ContinuousDecision(ctx context.Context, u model.Principal, evaluation string) (*decision.ContinuousRecord, error) {
	if !contract.ValidID(evaluation) {
		return nil, decision.ErrInput
	}
	var r decision.ContinuousRecord
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := decisionPolicyUser(ctx, tx, u, false); err != nil {
			return err
		}
		var err error
		r, err = readContinuousRecord(tx.QueryRow(ctx, `SELECT `+continuousColumns+` FROM decision_continuous_runs v WHERE v.tenant_id=$1 AND v.created_by=$2 AND v.evaluation_id=$3 AND v.expires_at>now()`, u.TenantID, u.ID, evaluation))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return &r, err
}

// 运行档案、签名任务与审计原子提交；确定性拒绝留档，数据库故障整体回滚并留待下一轮核对。
func (p *Postgres) CompleteContinuousDecision(ctx context.Context, c DecisionCandidate, evaluationID string, evidence triage.Evidence, signer ed25519.PrivateKey) (decision.ContinuousRecord, error) {
	var r decision.ContinuousRecord
	u := c.Principal
	if !contract.ValidID(evaluationID) || !contract.ValidID(c.TriageID) || c.Policy.Validate() != nil || c.Policy.Definition.Mode == "shadow" || u.TenantID != c.Policy.TenantID || u.ID != c.Policy.CreatedBy {
		return r, decision.ErrInput
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := responseTaskActor(ctx, tx, u); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, u.TenantID+"/continuous-decisions"); err != nil {
			return err
		}
		prior, err := readContinuousRecord(tx.QueryRow(ctx, `SELECT `+continuousColumns+` FROM decision_continuous_runs v WHERE v.tenant_id=$1 AND v.policy_id=$2 AND v.policy_revision=$3 AND v.triage_id=$4 AND v.created_by=$5 AND v.expires_at>now()`, u.TenantID, c.Policy.ID, c.Policy.Revision, c.TriageID, u.ID))
		if err == nil {
			r = prior
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		policy, err := readDecisionPolicy(tx.QueryRow(ctx, `SELECT `+decisionPolicyColumns+` FROM decision_policies h JOIN decision_policy_revisions v ON v.tenant_id=h.tenant_id AND v.policy_id=h.id AND v.revision=h.revision WHERE h.tenant_id=$1 AND h.id=$2 FOR SHARE OF h`, u.TenantID, c.Policy.ID))
		if err != nil {
			return err
		}
		if !policy.Active || policy.Revision != c.Policy.Revision || policy.DefinitionSHA256 != c.Policy.DefinitionSHA256 || policy.CreatedBy != u.ID {
			return ErrConflict
		}
		e, err := readDecisionEvaluation(tx.QueryRow(ctx, `SELECT `+decisionEvaluationColumns+` FROM decision_evaluations v WHERE v.tenant_id=$1 AND v.id=$2 AND v.created_by=$3 AND v.expires_at>now()`, u.TenantID, evaluationID, u.ID))
		if err != nil {
			return err
		}
		if e.Policy.ID != policy.ID || e.Policy.Revision != policy.Revision || e.Policy.DefinitionSHA256 != policy.DefinitionSHA256 || e.Result.TriageID != c.TriageID {
			return decision.ErrSource
		}
		job, err := scanTriage(tx.QueryRow(ctx, `SELECT `+triageJSON+` FROM alert_triage_jobs WHERE tenant_id=$1 AND id=$2 AND created_by=$3 AND expires_at>now() FOR SHARE`, u.TenantID, c.TriageID, u.ID))
		if err != nil {
			return err
		}
		if job.CreatedAt.Before(policy.CreatedAt) || job.Evidence.SHA256 != e.Result.EvidenceSHA256 {
			return decision.ErrSource
		}
		now := time.Now().UTC().Truncate(time.Microsecond)
		r = decision.ContinuousRecord{SchemaVersion: decision.ContinuousSchema, TenantID: u.TenantID, ID: RandomID("continuous_"), CreatedBy: u.ID, EvaluationID: e.ID, EvaluationSHA256: e.SHA256, PolicyID: policy.ID, PolicyRevision: policy.Revision, DefinitionSHA256: policy.DefinitionSHA256, TriageID: job.ID, EventID: job.Request.EventID, RawSHA256: job.Request.RawSHA256, TargetIP: e.Result.TargetIP, Config: *policy.Definition.Continuous, State: "skipped", Code: "policy_not_matched", CreatedAt: now}
		var providerRevision int64
		var enabled bool
		if err := tx.QueryRow(ctx, `SELECT revision,COALESCE((public->>'enabled')::boolean,false) FROM model_providers WHERE tenant_id=$1 AND id=$2 FOR SHARE`, u.TenantID, r.Config.ProviderID).Scan(&providerRevision, &enabled); err != nil {
			return err
		}
		if !enabled || providerRevision != r.Config.ProviderRevision || job.Request.ProviderID != r.Config.ProviderID || job.Request.ProviderRevision != r.Config.ProviderRevision {
			r.Code = "model_binding_changed"
		} else if e.Result.Status == "matched" {
			work, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
			if policy.Definition.Mode == "approval" {
				current, err := decision.Evaluate(work, policy, job, now)
				cancel()
				if err != nil {
					return err
				}
				if current.Status == "matched" {
					r.State, r.Code = "awaiting_confirmation", "manual_confirmation_required"
				}
			} else {
				intent, code, err := decision.AutomaticIntent(work, policy, job, evidence, now)
				cancel()
				if err != nil {
					return err
				}
				r.Code = code
				if code == "policy_authorized" {
					if err := authorizeContinuousTask(ctx, tx, u, policy, intent, &r, signer); err != nil {
						return err
					}
				}
			}
		}
		if err := tx.QueryRow(ctx, `SELECT $2::timestamptz+make_interval(days=>COALESCE((SELECT days FROM retention_policies WHERE tenant_id=$1 AND category='operations'),180))`, u.TenantID, now).Scan(&r.ExpiresAt); err != nil {
			return err
		}
		r.ExpiresAt = r.ExpiresAt.UTC()
		r, err = r.Seal()
		if err != nil {
			return err
		}
		raw, err := json.Marshal(r)
		if err != nil {
			return err
		}
		sensor, connector := "", ""
		if r.Config.Automatic != nil {
			sensor, connector = r.Config.Automatic.SensorID, r.Config.Automatic.ConnectorID
		}
		if _, err := tx.Exec(ctx, `INSERT INTO decision_continuous_runs(tenant_id,id,created_by,evaluation_id,policy_id,policy_revision,triage_id,event_id,raw_sha256,sensor_id,connector_id,state,task_id,created_at,expires_at,record) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`, u.TenantID, r.ID, u.ID, r.EvaluationID, r.PolicyID, r.PolicyRevision, r.TriageID, r.EventID, r.RawSHA256, sensor, connector, r.State, r.TaskID, now, r.ExpiresAt, raw); err != nil {
			return err
		}
		return insertOperationAudit(ctx, tx, u, "decision.continuous."+r.State, r.ID, r.ID)
	})
	return r, err
}

func authorizeContinuousTask(ctx context.Context, tx pgx.Tx, u model.Principal, policy decision.Record, intent responseapi.Intent, r *decision.ContinuousRecord, signer ed25519.PrivateKey) error {
	a := policy.Definition.Continuous.Automatic
	var registration string
	err := tx.QueryRow(ctx, `SELECT registration_id FROM sensors WHERE tenant_id=$1 AND id=$2 AND active FOR UPDATE`, u.TenantID, a.SensorID).Scan(&registration)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && registration != a.RegistrationID {
		r.Code = "sensor_binding_changed"
		return nil
	}
	if err != nil {
		return err
	}
	// 与人工任务相同的设备行锁、响应预算锁顺序，跨实例及策略修订共用冷却和目标幂等。
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, u.TenantID+"/response-tasks"); err != nil {
		return err
	}
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM decision_continuous_runs WHERE tenant_id=$1 AND event_id=$2 AND raw_sha256=$3 AND sensor_id=$4 AND connector_id=$5 AND state='queued')`, u.TenantID, r.EventID, r.RawSHA256, a.SensorID, a.ConnectorID).Scan(&exists); err != nil {
		return err
	}
	if exists {
		r.Code = "event_already_authorized"
		return nil
	}
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM sensor_tasks WHERE tenant_id=$1 AND sensor_id=$2 AND kind='response.block' AND created_at>now()-make_interval(secs=>$5) AND convert_from(command,'UTF8')::jsonb->'payload'->>'connector_id'=$3 AND convert_from(command,'UTF8')::jsonb->'payload'->>'target_ip'=$4)`, u.TenantID, a.SensorID, a.ConnectorID, intent.TargetIP, a.CooldownSeconds).Scan(&exists); err != nil {
		return err
	}
	if exists {
		r.Code = "target_cooldown"
		return nil
	}
	var count int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM decision_continuous_runs WHERE tenant_id=$1 AND policy_id=$2 AND state='queued' AND created_at>now()-interval '1 hour'`, u.TenantID, policy.ID).Scan(&count); err != nil {
		return err
	}
	if count >= a.MaxHourlyActions {
		r.Code = "hourly_quota"
		return nil
	}
	raw, err := json.Marshal(intent)
	if err != nil {
		return err
	}
	sp, err := tx.Begin(ctx)
	if err != nil {
		return err
	}
	task, err := createTaskTx(ctx, sp, u, a.SensorID, "response.block", r.ID, raw, signer, true)
	if err != nil {
		rollback, stop := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer stop()
		if re := sp.Rollback(rollback); re != nil {
			return errors.Join(err, re)
		}
		switch {
		case errors.Is(err, watchlist.ErrProtected):
			r.Code = "target_protected"
		case errors.Is(err, responseapi.ErrUnavailable):
			r.Code = "device_unavailable"
		case errors.Is(err, responseapi.ErrQuota):
			r.Code = "tenant_quota"
		case errors.Is(err, ErrConflict):
			r.Code = "task_conflict"
		case errors.Is(err, responseapi.ErrInput), errors.Is(err, pgx.ErrNoRows):
			r.Code = "device_unavailable"
		default:
			return err
		}
		return nil
	}
	if err := sp.Commit(ctx); err != nil {
		return err
	}
	r.State, r.Code, r.TaskID = "queued", "policy_authorized", task
	return nil
}
