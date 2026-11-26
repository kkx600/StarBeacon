package store

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/decision"
	"github.com/kkx600/StarBeacon/internal/model"
)

func lockDecisionAutomation(ctx context.Context, tx pgx.Tx, tenant string) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, tenant+"/continuous-decisions")
	return err
}

func decisionAutomationSettings(ctx context.Context, tx pgx.Tx, tenant string) (decision.AutomationSettings, error) {
	out := decision.DefaultAutomationSettings()
	err := tx.QueryRow(ctx, `SELECT revision,ceiling,paused FROM decision_automation_settings WHERE tenant_id=$1`, tenant).
		Scan(&out.Revision, &out.Ceiling, &out.Paused)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, nil
	}
	return out, err
}

func (p *Postgres) DecisionAutomation(ctx context.Context, u model.Principal) (decision.AutomationState, error) {
	out := decision.AutomationState{Scenes: []decision.SceneLevel{}}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := decisionPolicyUser(ctx, tx, u, false); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared(hashtextextended($1,0))`, u.TenantID+"/continuous-decisions"); err != nil {
			return err
		}
		var err error
		out.Settings, err = decisionAutomationSettings(ctx, tx, u.TenantID)
		if err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT h.id,h.name,h.revision,h.active,v.definition,v.definition_sha256
			FROM decision_policies h JOIN decision_policy_revisions v ON (v.tenant_id,v.policy_id,v.revision)=(h.tenant_id,h.id,h.revision)
			WHERE h.tenant_id=$1 ORDER BY h.id LIMIT $2`, u.TenantID, decision.MaxPolicies)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var scene decision.SceneLevel
			var raw []byte
			var digest string
			var definition decision.Definition
			if err := rows.Scan(&scene.ID, &scene.Name, &scene.Revision, &scene.Active, &raw, &digest); err != nil {
				return err
			}
			if json.Unmarshal(raw, &definition) != nil || decision.Digest(definition) != digest || definition.Validate() != nil {
				return decision.ErrSource
			}
			scene.Level, scene.SmallBlockMaxSeconds = definition.Level(), definition.SmallBlockLimit()
			scene.Effective = decision.Observe
			if scene.Active {
				scene.Effective = out.Settings.Effective(scene.Level)
			}
			out.Scenes = append(out.Scenes, scene)
		}
		return rows.Err()
	})
	return out, err
}

// 设置更新、暂停与下一次签发共用一把事务锁。暂停请求可以安全重试。
func (p *Postgres) ChangeDecisionAutomation(ctx context.Context, u model.Principal, change *decision.AutomationChange) (decision.AutomationSettings, error) {
	var out decision.AutomationSettings
	if change != nil && !change.Valid() {
		return out, decision.ErrInput
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := responseTaskActor(ctx, tx, u); err != nil {
			return err
		}
		if err := lockDecisionAutomation(ctx, tx, u.TenantID); err != nil {
			return err
		}
		var err error
		out, err = decisionAutomationSettings(ctx, tx, u.TenantID)
		if err != nil {
			return err
		}
		action := "decision.automation.pause"
		if change == nil {
			if out.Paused {
				return nil
			}
			out.Paused = true
		} else {
			if change.ExpectedRevision != out.Revision {
				return ErrConflict
			}
			out.Ceiling, out.Paused = change.Ceiling, *change.Paused
			action = "decision.automation.save"
		}
		out.Revision++
		if _, err := tx.Exec(ctx, `INSERT INTO decision_automation_settings(tenant_id,revision,ceiling,paused)
			VALUES($1,$2,$3,$4) ON CONFLICT(tenant_id) DO UPDATE SET
			revision=EXCLUDED.revision,ceiling=EXCLUDED.ceiling,paused=EXCLUDED.paused`,
			u.TenantID, out.Revision, out.Ceiling, out.Paused); err != nil {
			return err
		}
		return insertOperationAudit(ctx, tx, u, action, u.TenantID, model.RequestMetadataFrom(ctx).RequestID)
	})
	return out, err
}

func qualifyDecisionPromotion(ctx context.Context, tx pgx.Tx, u model.Principal, current decision.Record, change decision.Change) error {
	next := change.Definition
	if next.Level() == decision.Observe || !*change.Active {
		return nil
	}
	if current.Revision == 0 {
		return decision.ErrShadowRequired
	}
	criteria := next.ShadowCriteria()
	if current.Active && current.CreatedBy == u.ID && !current.Definition.Level().Below(next.Level()) &&
		current.Definition.Continuous.ProviderID == next.Continuous.ProviderID &&
		current.Definition.Continuous.ProviderRevision == next.Continuous.ProviderRevision &&
		decision.Digest(current.Definition.ShadowCriteria()) == decision.Digest(criteria) {
		return nil
	}
	raw, err := json.Marshal(criteria)
	if err != nil {
		return err
	}
	proof, err := readDecisionEvaluation(tx.QueryRow(ctx, `SELECT `+decisionEvaluationColumns+` FROM decision_evaluations v
		WHERE v.tenant_id=$1 AND v.created_by=$2 AND v.policy_id=$3 AND v.status='matched' AND v.expires_at>now()
		  AND (v.record->'policy'->'definition'->>'mode'='shadow' OR v.record->'policy'->'definition'->>'automation_level'='observe')
		  AND jsonb_set(v.record->'policy'->'definition','{mode}','"shadow"'::jsonb) -
		      ARRAY['continuous','automation_level','small_block_max_seconds']::text[] = $4::jsonb
		  AND v.record->'result'->>'provider_id'=$5 AND v.record->'result'->>'provider_revision'=$6::bigint::text
		ORDER BY v.sequence DESC LIMIT 1`, u.TenantID, u.ID, change.ID, raw, next.Continuous.ProviderID, next.Continuous.ProviderRevision))
	if errors.Is(err, pgx.ErrNoRows) {
		return decision.ErrShadowRequired
	}
	if err != nil {
		return err
	}
	if proof.Result.Confidence == nil || *proof.Result.Confidence < next.Threshold {
		return decision.ErrShadowRequired
	}
	return nil
}
