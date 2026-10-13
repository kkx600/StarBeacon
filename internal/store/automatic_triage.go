package store

import (
	"context"
	"encoding/json"
	"slices"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/decision"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/secrets"
	"github.com/kkx600/StarBeacon/internal/triage"
	"github.com/riverqueue/river"
)

type AutomaticTriageCandidate struct {
	ID, EventID, RawSHA256, EvidenceSHA256 string
	Principal                              model.Principal
	Policy                                 decision.Record
	CreatedAt                              time.Time
}

type AutomaticTriageRecord struct {
	ID               string    `json:"id"`
	PolicyID         string    `json:"policy_id"`
	PolicyRevision   int64     `json:"policy_revision"`
	DefinitionSHA256 string    `json:"definition_sha256"`
	EventID          string    `json:"event_id"`
	RawSHA256        string    `json:"raw_sha256"`
	SensorID         string    `json:"sensor_id"`
	RegistrationID   string    `json:"registration_id"`
	State            string    `json:"state"`
	Code             string    `json:"code"`
	TriageID         string    `json:"triage_id"`
	CreatedAt        time.Time `json:"created_at"`
	ExpiresAt        time.Time `json:"expires_at"`
}

type AutomaticTriagePage struct {
	Items []AutomaticTriageRecord `json:"items"`
	Next  string                  `json:"next_cursor"`
}

func (p *Postgres) AutomaticTriages(ctx context.Context, u model.Principal, id string, revision int64, cursor string) (AutomaticTriagePage, error) {
	page := AutomaticTriagePage{Items: []AutomaticTriageRecord{}}
	if !contract.ValidID(id) || revision < 1 || revision > decision.MaxRevision || cursor != "" && !contract.ValidID(cursor) {
		return page, decision.ErrInput
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := decisionPolicyUser(ctx, tx, u, true); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT id,policy_id,policy_revision,definition_sha256,event_id,raw_sha256,sensor_id,registration_id,state,code,triage_id,created_at,expires_at FROM decision_triage_triggers WHERE tenant_id=$1 AND created_by=$2 AND policy_id=$3 AND policy_revision=$4 AND id>$5 AND expires_at>now() ORDER BY id LIMIT 21`, u.TenantID, u.ID, id, revision, cursor)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r AutomaticTriageRecord
			if err := rows.Scan(&r.ID, &r.PolicyID, &r.PolicyRevision, &r.DefinitionSHA256, &r.EventID, &r.RawSHA256, &r.SensorID, &r.RegistrationID, &r.State, &r.Code, &r.TriageID, &r.CreatedAt, &r.ExpiresAt); err != nil {
				return err
			}
			page.Items = append(page.Items, r)
		}
		return rows.Err()
	})
	if len(page.Items) > 20 {
		page.Next = page.Items[19].ID
		page.Items = page.Items[:20]
	}
	return page, err
}

func (c AutomaticTriageCandidate) key() string {
	return "trigger_" + Hash(c.Principal.TenantID + "/" + c.ID)[:40]
}

// 已索引告警才登记触发；观测时刻与接收时刻都必须晚于许可修订，防止历史重投成为新授权。
func (p *Postgres) RecordAutomaticTriage(ctx context.Context, tenant string, alerts []model.Alert) error {
	if !contract.ValidID(tenant) || len(alerts) > 500 {
		return decision.ErrInput
	}
	return p.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout='2s'; SET LOCAL statement_timeout='5s'`); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT `+decisionPolicyColumns+` FROM decision_policies h JOIN decision_policy_revisions v ON v.tenant_id=h.tenant_id AND v.policy_id=h.id AND v.revision=h.revision JOIN users u ON u.tenant_id=v.tenant_id AND u.id=v.created_by JOIN tenants t ON t.id=v.tenant_id WHERE h.tenant_id=$1 AND h.active AND u.active AND u.role='admin' AND t.active AND EXISTS(SELECT 1 FROM sensors s WHERE s.tenant_id=v.tenant_id AND s.id=v.definition->'continuous'->'automatic'->>'sensor_id' AND s.registration_id=v.definition->'continuous'->'automatic'->>'registration_id' AND s.active) AND v.definition->>'mode'='automatic' AND v.definition->'continuous'->'trigger' IS NOT NULL ORDER BY h.id`, tenant)
		if err != nil {
			return err
		}
		policies := []decision.Record{}
		for rows.Next() {
			policy, err := readDecisionPolicy(rows)
			if err != nil {
				rows.Close()
				return err
			}
			policies = append(policies, policy)
		}
		err = rows.Err()
		rows.Close()
		if err != nil || len(policies) == 0 {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, tenant+"/triage-admission"); err != nil {
			return err
		}
		for _, policy := range policies {
			config, trigger := policy.Definition.Continuous.Automatic, policy.Definition.Continuous.Trigger
			var count int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM decision_triage_triggers WHERE tenant_id=$1 AND policy_id=$2 AND created_at>=date_trunc('day',now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'`, tenant, policy.ID).Scan(&count); err != nil {
				return err
			}
			for _, alert := range alerts {
				if count >= trigger.MaxDailyJobs {
					break
				}
				if alert.TenantID != tenant || alert.SensorID != config.SensorID || alert.RegistrationID != config.RegistrationID || alert.ObservedAt.Before(policy.CreatedAt) || alert.ReceivedAt.Before(policy.CreatedAt) || !slices.Contains(trigger.Severities, alert.Severity) {
					continue
				}
				evidence, err := triage.Freeze(alert)
				if err != nil {
					return err
				}
				id := "trigger_" + Hash(tenant + "/" + policy.ID + "/" + strconv.FormatInt(policy.Revision, 10) + "/" + alert.EventID + "/" + alert.RawSHA256)[:40]
				tag, err := tx.Exec(ctx, `INSERT INTO decision_triage_triggers(tenant_id,id,created_by,policy_id,policy_revision,definition_sha256,event_id,raw_sha256,sensor_id,registration_id,observed_at,received_at,evidence_sha256,state,code,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'pending','awaiting_model_queue',now()+make_interval(days=>COALESCE((SELECT days FROM retention_policies WHERE tenant_id=$1 AND category='models'),180))) ON CONFLICT DO NOTHING`, tenant, id, policy.CreatedBy, policy.ID, policy.Revision, policy.DefinitionSHA256, alert.EventID, alert.RawSHA256, alert.SensorID, alert.RegistrationID, alert.ObservedAt, alert.ReceivedAt, evidence.SHA256)
				if err != nil {
					return err
				}
				count += int(tag.RowsAffected())
			}
		}
		return nil
	})
}

// 停用、权限撤回、模型变更与超时记录显式跳过；依赖不可用保留原触发，不能另造请求键。
func (p *Postgres) AutomaticTriageCandidates(ctx context.Context, tenant string) ([]AutomaticTriageCandidate, error) {
	result := []AutomaticTriageCandidate{}
	err := p.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL statement_timeout='3s'`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE decision_triage_triggers q SET state='skipped',code='authorization_unavailable' WHERE q.tenant_id=$1 AND q.state='pending' AND (q.created_at<now()-interval '15 minutes' OR NOT EXISTS(SELECT 1 FROM decision_policies h JOIN decision_policy_revisions v ON v.tenant_id=h.tenant_id AND v.policy_id=h.id AND v.revision=h.revision JOIN users u ON u.tenant_id=v.tenant_id AND u.id=v.created_by JOIN tenants t ON t.id=v.tenant_id JOIN model_providers m ON m.tenant_id=v.tenant_id AND m.id=v.definition->'continuous'->>'provider_id' AND m.revision=(v.definition->'continuous'->>'provider_revision')::bigint WHERE h.tenant_id=q.tenant_id AND h.id=q.policy_id AND h.revision=q.policy_revision AND h.active AND v.definition_sha256=q.definition_sha256 AND v.definition->'continuous'->'trigger' IS NOT NULL AND u.id=q.created_by AND u.active AND u.role='admin' AND t.active AND COALESCE((m.public->>'enabled')::boolean,false) AND q.observed_at>=now()-make_interval(secs=>(v.definition->>'max_age_seconds')::integer) AND q.observed_at<=now()+interval '5 seconds' AND EXISTS(SELECT 1 FROM sensors s WHERE s.tenant_id=q.tenant_id AND s.id=q.sensor_id AND s.registration_id=q.registration_id AND s.active)))`, tenant); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT q.id,q.event_id,q.raw_sha256,q.evidence_sha256,`+decisionPolicyColumns+`,u.revision,q.created_at FROM decision_triage_triggers q JOIN decision_policy_revisions v ON v.tenant_id=q.tenant_id AND v.policy_id=q.policy_id AND v.revision=q.policy_revision JOIN users u ON u.tenant_id=q.tenant_id AND u.id=q.created_by WHERE q.tenant_id=$1 AND q.state='pending' ORDER BY q.created_at,q.id LIMIT 16`, tenant)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c AutomaticTriageCandidate
			var raw []byte
			v := &c.Policy
			if err := rows.Scan(&c.ID, &c.EventID, &c.RawSHA256, &c.EvidenceSHA256, &v.TenantID, &v.ID, &v.Revision, &v.Name, &v.Description, &v.Active, &raw, &v.DefinitionSHA256, &v.CreatedBy, &v.CreatedAt, &v.ExpiresAt, &c.Principal.CredentialRevision, &c.CreatedAt); err != nil {
				return err
			}
			if json.Unmarshal(raw, &v.Definition) != nil || v.Validate() != nil {
				return decision.ErrSource
			}
			c.Principal.ID, c.Principal.TenantID, c.Principal.Role = v.CreatedBy, tenant, "admin"
			result = append(result, c)
		}
		return rows.Err()
	})
	return result, err
}

func (p *Postgres) CreateAutomaticAlertTriage(ctx context.Context, c AutomaticTriageCandidate, evidence triage.Evidence, queue *river.Client[pgx.Tx], vault *secrets.Vault) (triage.Job, error) {
	if !contract.ValidID(c.ID) || c.Policy.Validate() != nil || c.Policy.Definition.Continuous == nil || c.Policy.Definition.Continuous.Trigger == nil || c.Policy.Definition.Mode != "automatic" || c.Principal.TenantID != c.Policy.TenantID || c.Principal.ID != c.Policy.CreatedBy || c.EventID != evidence.EventID || c.RawSHA256 != evidence.RawSHA256 || c.EvidenceSHA256 != evidence.SHA256 {
		return triage.Job{}, decision.ErrSource
	}
	input := triage.Request{EventID: c.EventID, RawSHA256: c.RawSHA256, ProviderID: c.Policy.Definition.Continuous.ProviderID, ProviderRevision: c.Policy.Definition.Continuous.ProviderRevision, Note: "持续决策自动研判；策略 " + c.Policy.ID, AllowContext: true}
	return p.createAlertTriage(ctx, c.Principal, input, c.key(), evidence, queue, vault, c.ID, &c)
}

func checkAutomaticTrigger(ctx context.Context, tx pgx.Tx, c AutomaticTriageCandidate) error {
	if err := decisionPolicyUser(ctx, tx, c.Principal, true); err != nil {
		return err
	}
	var state, hash string
	var created, observed time.Time
	if err := tx.QueryRow(ctx, `SELECT state,evidence_sha256,created_at,observed_at FROM decision_triage_triggers WHERE tenant_id=$1 AND id=$2 AND created_by=$3 AND expires_at>now() FOR UPDATE`, c.Principal.TenantID, c.ID, c.Principal.ID).Scan(&state, &hash, &created, &observed); err != nil {
		return err
	}
	if state != "pending" || hash != c.EvidenceSHA256 || time.Since(created) >= 15*time.Minute || time.Since(observed) > time.Duration(c.Policy.Definition.MaxAgeSeconds)*time.Second || observed.After(time.Now().Add(5*time.Second)) {
		return ErrConflict
	}
	policy, err := readDecisionPolicy(tx.QueryRow(ctx, `SELECT `+decisionPolicyColumns+` FROM decision_policies h JOIN decision_policy_revisions v ON v.tenant_id=h.tenant_id AND v.policy_id=h.id AND v.revision=h.revision WHERE h.tenant_id=$1 AND h.id=$2 FOR SHARE OF h`, c.Principal.TenantID, c.Policy.ID))
	if err != nil {
		return err
	}
	if !policy.Active || policy.Revision != c.Policy.Revision || policy.DefinitionSHA256 != c.Policy.DefinitionSHA256 || policy.CreatedBy != c.Principal.ID {
		return ErrConflict
	}
	return nil
}

func (p *Postgres) SkipAutomaticTriage(ctx context.Context, c AutomaticTriageCandidate, code string) error {
	if !contract.ValidID(c.ID) || !slices.Contains([]string{"evidence_changed", "model_quota"}, code) {
		return decision.ErrInput
	}
	return p.TenantTx(ctx, c.Principal.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE decision_triage_triggers SET state='skipped',code=$3 WHERE tenant_id=$1 AND id=$2 AND state='pending'`, c.Principal.TenantID, c.ID, code)
		return err
	})
}
