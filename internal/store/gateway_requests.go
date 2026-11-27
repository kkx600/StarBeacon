package store

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/gatewayblock"
	"github.com/kkx600/StarBeacon/internal/model"
)

const gatewayPendingLimit = 128

type gatewayEvidence struct {
	gatewayblock.Request
	RuleID, RuleRevision string
	EventAt, ReceivedAt  time.Time
	ActorID, KeyHash     string
	Deadline             time.Time
	FollowUpUntil        *time.Time
	PlaybookRunID        string
}

func gatewayObservation(alert model.Alert) (gatewayEvidence, error) {
	source, sourceErr := netip.ParseAddr(alert.Source.IP)
	dest, destErr := netip.ParseAddr(alert.Destination.IP)
	flow := gatewayblock.Flow{SourceIP: source, SourcePort: alert.Source.Port, DestinationIP: dest, DestinationPort: alert.Destination.Port, Transport: alert.Network.Transport}
	flowID, flowErr := strconv.ParseUint(alert.Suricata.FlowID, 10, 64)
	if sourceErr != nil || destErr != nil || !flow.Valid() || flowErr != nil || flowID == 0 ||
		alert.Event.Kind != "alert" || alert.Event.Dataset != "suricata.eve" ||
		!gatewayblock.ValidDigest(alert.EventID) || !gatewayblock.ValidDigest(alert.RawSHA256) ||
		!contract.ValidID(alert.SensorID) || !contract.ValidID(alert.RegistrationID) ||
		alert.Timestamp.IsZero() || alert.ObservedAt.IsZero() || alert.ReceivedAt.IsZero() {
		return gatewayEvidence{}, gatewayblock.ErrInput
	}
	return gatewayEvidence{
		Request: gatewayblock.Request{EventID: alert.EventID, RawSHA256: alert.RawSHA256, SensorID: alert.SensorID,
			RegistrationID: alert.RegistrationID, Flow: flow, ObservedAt: alert.ObservedAt},
		RuleID: alert.Rule.ID, RuleRevision: alert.Rule.Revision, EventAt: alert.Timestamp, ReceivedAt: alert.ReceivedAt,
	}, nil
}

func (e gatewayEvidence) qualifies(policy gatewayblock.Policy, config gatewayblock.Settings, now time.Time) bool {
	d := policy.Definition
	if !config.Enabled || config.UpdatedAt == nil || !d.Enabled || !d.ValidUntil.After(now.Add(2*time.Second)) ||
		e.SensorID != d.SensorID || e.RegistrationID != d.RegistrationID || e.RuleID != d.RuleID || e.RuleRevision != d.RuleRevision ||
		!d.Scope.Allows(e.Flow) {
		return false
	}
	age := gatewayblock.RuleFreshness
	if d.Trigger == gatewayblock.Review {
		age = gatewayblock.ReviewFreshness
	}
	for _, stamp := range []time.Time{e.EventAt, e.ObservedAt, e.ReceivedAt} {
		if stamp.After(now.Add(2*time.Second)) || stamp.Before(now.Add(-age)) ||
			stamp.Before(policy.UpdatedAt) || stamp.Before(*config.UpdatedAt) {
			return false
		}
	}
	return true
}

const gatewayRequestColumns = `id,event_id,raw_sha256,policy_id,policy_revision,assessment_revision,sensor_id,registration_id,trigger,
 flow,state,code,COALESCE(task_id,''),observed_at,created_at,authorized_at,lease_until,rule_id,rule_revision,event_at,received_at,
 actor_id,COALESCE(client_key_hash,''),deadline,
 COALESCE(gateway_result,(SELECT receipt->'result' FROM sensor_tasks t WHERE t.tenant_id=gateway_block_requests.tenant_id
 AND t.id=gateway_block_requests.task_id AND t.state='succeeded')),
 COALESCE((SELECT t.state FROM sensor_tasks t WHERE t.tenant_id=gateway_block_requests.tenant_id AND t.id=gateway_block_requests.task_id),''),
 follow_up_state,follow_up_code,follow_up_until,COALESCE(follow_up_task_id,''),
 COALESCE((SELECT t.state FROM sensor_tasks t WHERE t.tenant_id=gateway_block_requests.tenant_id AND t.id=gateway_block_requests.follow_up_task_id),''),
 COALESCE(playbook_run_id,'')`

func scanGatewayRequest(row pgx.Row) (gatewayEvidence, error) {
	var r gatewayEvidence
	var flow, result []byte
	if err := row.Scan(&r.ID, &r.EventID, &r.RawSHA256, &r.PolicyID, &r.PolicyRevision, &r.AssessmentRevision,
		&r.SensorID, &r.RegistrationID, &r.Trigger, &flow, &r.State, &r.Code, &r.TaskID, &r.ObservedAt,
		&r.CreatedAt, &r.AuthorizedAt, &r.LeaseUntil, &r.RuleID, &r.RuleRevision, &r.EventAt, &r.ReceivedAt, &r.ActorID, &r.KeyHash, &r.Deadline,
		&result, &r.TaskState, &r.FollowUpState, &r.FollowUpCode, &r.FollowUpUntil, &r.FollowUpTaskID, &r.FollowUpTaskState, &r.PlaybookRunID); err != nil {
		return r, err
	}
	if json.Unmarshal(flow, &r.Flow) != nil || !r.Flow.Valid() {
		return gatewayEvidence{}, gatewayblock.ErrInput
	}
	if len(result) != 0 && json.Unmarshal(result, &r.GatewayResult) != nil {
		return gatewayEvidence{}, gatewayblock.ErrUnknown
	}
	return r, nil
}

func insertGatewayRequest(ctx context.Context, tx pgx.Tx, tenant string, e gatewayEvidence, policy gatewayblock.Policy, actor string) (gatewayEvidence, error) {
	age := gatewayblock.RuleFreshness
	if policy.Definition.Trigger == gatewayblock.Review {
		age = gatewayblock.ReviewFreshness
	}
	deadline := minTime(e.EventAt.Add(age), minTime(e.ObservedAt.Add(age), policy.Definition.ValidUntil))
	if !e.Deadline.IsZero() {
		deadline = minTime(deadline, e.Deadline)
	}
	flow, _ := json.Marshal(e.Flow)
	id := "gateway_" + Hash(tenant + "/" + e.EventID)[:40]
	return scanGatewayRequest(tx.QueryRow(ctx, `INSERT INTO gateway_block_requests
		(tenant_id,id,event_id,raw_sha256,policy_id,policy_revision,sensor_id,registration_id,trigger,rule_id,rule_revision,
		 assessment_revision,actor_id,client_key_hash,flow,flow_key,observed_at,event_at,received_at,deadline,expires_at,playbook_run_id)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,NULLIF($14,''),$15,$16,$17,$18,$19,$20,
		now()+make_interval(days=>COALESCE((SELECT days FROM retention_policies WHERE tenant_id=$1 AND category='operations'),180)),NULLIF($21,''))
		ON CONFLICT DO NOTHING RETURNING `+gatewayRequestColumns, tenant, id, e.EventID, e.RawSHA256, policy.ID, policy.Revision,
		e.SensorID, e.RegistrationID, policy.Definition.Trigger, e.RuleID, e.RuleRevision, e.AssessmentRevision,
		actor, e.KeyHash, flow, e.Flow.Key(), e.ObservedAt, e.EventAt, e.ReceivedAt, deadline, e.PlaybookRunID))
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func pendingGatewayCount(ctx context.Context, tx pgx.Tx, tenant string) (int, error) {
	var count int
	err := tx.QueryRow(ctx, `SELECT count(*) FROM gateway_block_requests WHERE tenant_id=$1 AND state='pending' AND deadline>clock_timestamp()`, tenant).Scan(&count)
	return count, err
}

// 只有已成功索引的原生告警进入即时触发。队列上限与同一事件唯一性抵御批次重投。
func (p *Postgres) RecordGatewayBlockMatches(ctx context.Context, tenant string, alerts []model.Alert) error {
	return p.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		settings, err := gatewaySettings(ctx, tx, tenant)
		if err != nil || !settings.Enabled {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT `+gatewayPolicyColumns+` FROM gateway_block_policies WHERE tenant_id=$1 AND
			definition->>'trigger'='rule' AND definition->>'enabled'='true' ORDER BY id LIMIT $2`, tenant, gatewayblock.MaxPolicies)
		if err != nil {
			return err
		}
		policies, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (gatewayblock.Policy, error) { return scanGatewayPolicy(row) })
		if err != nil || len(policies) == 0 {
			return err
		}
		if err := lockGatewayBlocks(ctx, tx, tenant); err != nil {
			return err
		}
		pending, err := pendingGatewayCount(ctx, tx, tenant)
		if err != nil {
			return err
		}
		now := time.Now().UTC()
		for _, alert := range alerts {
			if pending >= gatewayPendingLimit {
				break
			}
			evidence, err := gatewayObservation(alert)
			if err != nil || alert.TenantID != tenant {
				continue
			}
			for _, policy := range policies {
				if !evidence.qualifies(policy, settings, now) {
					continue
				}
				if _, err := insertGatewayRequest(ctx, tx, tenant, evidence, policy, policy.AuthorID); err == nil {
					pending++
				} else if !errors.Is(err, pgx.ErrNoRows) {
					return err
				}
				break
			}
		}
		return nil
	})
}

func confirmedGatewayReview(ctx context.Context, tx pgx.Tx, tenant string, e gatewayEvidence) error {
	var ok bool
	err := tx.QueryRow(ctx, `SELECT true FROM alert_assessments WHERE tenant_id=$1 AND event_id=$2 AND raw_sha256=$3 AND revision=$4
		AND record->'spec'->>'verdict'='confirmed' AND expires_at>clock_timestamp() FOR SHARE`,
		tenant, e.EventID, e.RawSHA256, e.AssessmentRevision).Scan(&ok)
	if errors.Is(err, pgx.ErrNoRows) {
		return gatewayblock.ErrIneligible
	}
	return err
}

func gatewayRequestResult(r gatewayEvidence) gatewayblock.Request {
	if r.State == "pending" && !r.Deadline.After(time.Now()) {
		r.State, r.Code = "denied", "observation_expired"
	}
	if r.FollowUpState == "pending" && (r.FollowUpUntil == nil || !r.FollowUpUntil.After(time.Now())) {
		r.FollowUpState, r.FollowUpCode = "skipped", "observation_expired"
	}
	return r.Request
}

func (p *Postgres) CreateGatewayBlockReview(ctx context.Context, u model.Principal, request gatewayblock.ReviewRequest, key string, alert model.Alert) (gatewayblock.Request, error) {
	var out gatewayblock.Request
	evidence, err := gatewayObservation(alert)
	if err != nil || !request.Valid() || request.RawSHA256 != alert.RawSHA256 || alert.TenantID != u.TenantID || !contract.ValidID(key) || len(key) < 8 {
		return out, gatewayblock.ErrInput
	}
	evidence.AssessmentRevision, evidence.KeyHash = request.AssessmentRevision, Hash(key)
	err = p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := configurationActor(ctx, tx, u, true, gatewayblock.ErrPermission); err != nil {
			return err
		}
		if err := lockGatewayBlocks(ctx, tx, u.TenantID); err != nil {
			return err
		}
		prior, err := scanGatewayRequest(tx.QueryRow(ctx, `SELECT `+gatewayRequestColumns+` FROM gateway_block_requests
			WHERE tenant_id=$1 AND actor_id=$2 AND client_key_hash=$3 AND expires_at>now()`, u.TenantID, u.ID, evidence.KeyHash))
		if err == nil {
			if prior.EventID != evidence.EventID || prior.RawSHA256 != evidence.RawSHA256 || prior.PolicyID != request.PolicyID ||
				prior.PolicyRevision != request.PolicyRevision || prior.AssessmentRevision != request.AssessmentRevision {
				return ErrConflict
			}
			out = gatewayRequestResult(prior)
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		policy, err := gatewayPolicy(ctx, tx, u.TenantID, request.PolicyID)
		if err != nil {
			return err
		}
		settings, err := gatewaySettings(ctx, tx, u.TenantID)
		if err != nil {
			return err
		}
		if policy.Revision != request.PolicyRevision || policy.Definition.Trigger != gatewayblock.Review ||
			!evidence.qualifies(policy, settings, time.Now().UTC()) {
			return gatewayblock.ErrIneligible
		}
		if err := confirmedGatewayReview(ctx, tx, u.TenantID, evidence); err != nil {
			return err
		}
		if err := checkPlaybookGateway(ctx, tx, u, key, &evidence, policy, time.Now().UTC()); err != nil {
			return err
		}
		count, err := pendingGatewayCount(ctx, tx, u.TenantID)
		if err != nil {
			return err
		}
		if count >= gatewayPendingLimit {
			return gatewayblock.ErrLimit
		}
		r, err := insertGatewayRequest(ctx, tx, u.TenantID, evidence, policy, u.ID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrConflict
		}
		if err != nil {
			return err
		}
		out = r.Request
		return insertOperationAudit(ctx, tx, u, "gateway.block.review.request", out.ID, key)
	})
	return out, err
}

func (p *Postgres) GatewayBlockRequest(ctx context.Context, u model.Principal, id string) (gatewayblock.Request, error) {
	var out gatewayblock.Request
	if !contract.ValidID(id) {
		return out, gatewayblock.ErrInput
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := configurationActor(ctx, tx, u, false, gatewayblock.ErrPermission); err != nil {
			return err
		}
		r, err := scanGatewayRequest(tx.QueryRow(ctx, `SELECT `+gatewayRequestColumns+` FROM gateway_block_requests
			WHERE tenant_id=$1 AND id=$2 AND expires_at>now()`, u.TenantID, id))
		if err == nil {
			out = gatewayRequestResult(r)
		}
		return err
	})
	return out, err
}

func (p *Postgres) GatewayBlockRequests(ctx context.Context, u model.Principal, cursor string, limit int) (gatewayblock.RequestPage, error) {
	out := gatewayblock.RequestPage{Items: []gatewayblock.Request{}}
	if !contract.ValidListLimit(limit) || cursor != "" && !contract.ValidID(cursor) {
		return out, gatewayblock.ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := configurationActor(ctx, tx, u, false, gatewayblock.ErrPermission); err != nil {
			return err
		}
		var before *time.Time
		if cursor != "" {
			if err := tx.QueryRow(ctx, `SELECT created_at FROM gateway_block_requests WHERE tenant_id=$1 AND id=$2 AND expires_at>now()`,
				u.TenantID, cursor).Scan(&before); err != nil {
				return err
			}
		}
		settings, err := gatewaySettings(ctx, tx, u.TenantID)
		if err != nil {
			return err
		}
		out.Enabled = settings.Enabled
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM sensors WHERE tenant_id=$1 AND active
			AND last_seen BETWEEN now()-interval '35 seconds' AND now()+interval '2 seconds'
			AND health->'gateway_block'->>'config_sha256' ~ '^[a-f0-9]{64}$'`, u.TenantID).Scan(&out.OnlineGateways); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT count(*),
			count(*) FILTER (WHERE gateway_result->'observation'->>'state'='paused'),
			count(*) FILTER (WHERE gateway_result->'observation'->>'state'='continued'),
			count(*) FILTER (WHERE gateway_result->'observation'->>'state'='unknown'),
			count(*) FILTER (WHERE code='protected_endpoint' OR follow_up_code='protected_endpoint')
			FROM gateway_block_requests WHERE tenant_id=$1 AND created_at>=now()-interval '24 hours' AND expires_at>now()`,
			u.TenantID).Scan(&out.LastDay.Total, &out.LastDay.Paused, &out.LastDay.Continued, &out.LastDay.Unknown, &out.LastDay.Protected); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT `+gatewayRequestColumns+` FROM gateway_block_requests
			WHERE tenant_id=$1 AND expires_at>now() AND ($2::timestamptz IS NULL OR (created_at,id)<($2,$3))
			ORDER BY created_at DESC,id DESC LIMIT $4`, u.TenantID, before, cursor, limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			r, err := scanGatewayRequest(rows)
			if err != nil {
				return err
			}
			out.Items = append(out.Items, gatewayRequestResult(r))
		}
		return rows.Err()
	})
	if err == nil && len(out.Items) > limit {
		out.Items = out.Items[:limit]
		out.NextCursor = out.Items[limit-1].ID
	}
	return out, err
}
