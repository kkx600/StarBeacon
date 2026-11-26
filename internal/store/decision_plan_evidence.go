package store

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/decision"
	"github.com/kkx600/StarBeacon/internal/model"
	responseapi "github.com/kkx600/StarBeacon/internal/response"
	"github.com/kkx600/StarBeacon/internal/triage"
	"github.com/kkx600/StarBeacon/internal/watchlist"
)

func decisionProviderCurrent(ctx context.Context, tx pgx.Tx, tenant string, config decision.ContinuousConfig, job triage.Job) (bool, error) {
	var revision int64
	var enabled bool
	err := tx.QueryRow(ctx, `SELECT revision,COALESCE((public->>'enabled')::boolean,false) FROM model_providers
		WHERE tenant_id=$1 AND id=$2 FOR SHARE`, tenant, config.ProviderID).Scan(&revision, &enabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return enabled && revision == config.ProviderRevision && job.Request.ProviderID == config.ProviderID &&
		job.Request.ProviderRevision == config.ProviderRevision, err
}

func decisionFact(evidence triage.Evidence, id string) string {
	for _, fact := range evidence.Facts {
		if fact.ID == id {
			return fact.Value
		}
	}
	return ""
}

func decisionDestination(ctx context.Context, tx pgx.Tx, policy decision.Record, evidence triage.Evidence, sensor, registration string, now time.Time) error {
	raw := decisionFact(evidence, "destination.ip")
	if raw == "" {
		return nil
	}
	ip, err := netip.ParseAddr(raw)
	if err != nil {
		return decision.ErrSource
	}
	ip = ip.Unmap()
	for _, raw := range policy.Definition.ProtectedPrefixes {
		prefix, _ := netip.ParsePrefix(raw)
		if prefix.Contains(ip) {
			return watchlist.ErrProtected
		}
	}
	_, err = CheckWatchlistResponseTx(ctx, tx, policy.TenantID, sensor, registration, ip.String(), now)
	return err
}

func decisionManagedSource(ctx context.Context, tx pgx.Tx, tenant, ip string) (bool, error) {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared(hashtextextended($1,0))`, tenant+"/inventory/address-space"); err != nil {
		return false, err
	}
	var managed bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM inventory_objects n WHERE n.tenant_id=$1 AND n.kind='networks'
		AND n.active AND n.data->>'purpose' IS DISTINCT FROM 'external' AND $2::text::inet <<= (n.data->>'prefix')::cidr)
		OR EXISTS(SELECT 1 FROM inventory_objects a
		 CROSS JOIN LATERAL jsonb_array_elements(a.data->'interfaces') f
		 CROSS JOIN LATERAL jsonb_array_elements_text(f->'ips') address
		 WHERE a.tenant_id=$1 AND a.kind='assets' AND a.active AND address::inet=$2::text::inet)`, tenant, ip).Scan(&managed)
	return managed, err
}

func assessDecisionPlan(ctx context.Context, tx pgx.Tx, u model.Principal, policy decision.Record, evaluation decision.Evaluation,
	job triage.Job, evidence triage.Evidence, level decision.Level, run *decision.ContinuousRecord, signer ed25519.PrivateKey) error {
	bound, err := decisionProviderCurrent(ctx, tx, u.TenantID, run.Config, job)
	if err != nil {
		return err
	}
	if job.Answer != nil {
		run.Plan = decision.SummarizePlan(level, evaluation.Result.CandidateAction, evaluation.Result.EvidenceSHA256, *job.Answer)
	}
	switch {
	case !bound:
		run.Code = "model_binding_changed"
	case evaluation.Result.Status == "protected":
		run.Code = "target_protected"
	case evaluation.Result.Status != "matched":
	case level == decision.Observe:
		run.Code = "observation_only"
	case evaluation.Result.CandidateAction != "block_source":
		run.Code = "manual_investigation"
	default:
		return qualifyDecisionPlan(ctx, tx, u, policy, evaluation, job, evidence, level, run, signer)
	}
	return nil
}

func qualifyDecisionPlan(ctx context.Context, tx pgx.Tx, u model.Principal, policy decision.Record, evaluation decision.Evaluation,
	job triage.Job, evidence triage.Evidence, level decision.Level, run *decision.ContinuousRecord, signer ed25519.PrivateKey) error {
	recorded, err := decisionEventHasPlan(ctx, tx, policy, run.EvaluationID, run.EventID, run.RawSHA256)
	if err != nil {
		return err
	}
	if recorded {
		run.Code = "plan_already_recorded"
		return nil
	}
	work, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	var intent responseapi.Intent
	if run.Config.Automatic != nil {
		var err error
		intent, run.Code, err = decision.AutomaticIntent(work, policy, job, evidence, run.CreatedAt)
		if err != nil || run.Code != "policy_authorized" {
			return err
		}
		if policy.Definition.SmallSourceBlock(intent.TargetIP, intent.TTLSeconds, false) {
			managed, err := decisionManagedSource(ctx, tx, u.TenantID, intent.TargetIP)
			if err != nil {
				return err
			}
			if !managed {
				run.Plan.Impact = "small"
			}
		}
		if level == decision.Full || level == decision.Conditional && run.Plan.Impact == "small" {
			return authorizeContinuousTask(ctx, tx, u, policy, intent, job.Evidence, run, signer)
		}
	} else {
		current, err := decision.Evaluate(work, policy, job, run.CreatedAt)
		if err != nil || current.Status != "matched" {
			return err
		}
		if code := decision.ManualPlanReason(policy, job); code != "" {
			run.Code = code
			return nil
		}
	}
	sensor, registration := decisionFact(job.Evidence, "sensor.id"), decisionFact(job.Evidence, "sensor.registration")
	_, err = CheckWatchlistResponseTx(ctx, tx, u.TenantID, sensor, registration, run.TargetIP, run.CreatedAt)
	if err == nil {
		err = decisionDestination(ctx, tx, policy, job.Evidence, sensor, registration, run.CreatedAt)
	}
	if errors.Is(err, watchlist.ErrProtected) {
		run.Code = "target_protected"
		return nil
	}
	if err != nil {
		return err
	}
	deadline := minTime(run.CreatedAt.Add(decision.ConfirmationWindow), minTime(job.ExpiresAt, evaluation.ExpiresAt))
	deadline = minTime(deadline, job.Evidence.ObservedAt.Add(time.Duration(policy.Definition.MaxAgeSeconds)*time.Second)).UTC().Truncate(time.Microsecond)
	if !deadline.After(run.CreatedAt) {
		run.Code = "evidence_changed"
		return nil
	}
	run.State, run.Code = "awaiting_confirmation", "manual_confirmation_required"
	run.Plan.ConfirmUntil = &deadline
	return nil
}
