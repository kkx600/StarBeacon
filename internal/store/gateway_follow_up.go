package store

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/gatewayblock"
	"github.com/kkx600/StarBeacon/internal/model"
	responseapi "github.com/kkx600/StarBeacon/internal/response"
	"github.com/kkx600/StarBeacon/internal/transport"
	"github.com/kkx600/StarBeacon/internal/watchlist"
)

func recordGatewayResult(ctx context.Context, tx pgx.Tx, tenant, task string, action gatewayblock.Action, result gatewayblock.Result, raw json.RawMessage) error {
	state, code := "none", ""
	var until *time.Time
	observation := result.Observation
	if action.FollowUp {
		state, code = "skipped", "observation_unavailable"
		if observation != nil && observation.State == gatewayblock.FlowContinued {
			code = "traffic_continued"
		}
		if observation != nil && observation.State == gatewayblock.FlowPaused {
			validUntil := observation.FinishedAt.Add(gatewayblock.FollowUpWindow)
			now := time.Now().UTC()
			if observation.FinishedAt.After(now.Add(2*time.Second)) || !validUntil.After(now) {
				code = "observation_expired"
			} else {
				state, code, until = "pending", "", &validUntil
			}
		}
	}
	notice := observation != nil && observation.State == gatewayblock.FlowContinued
	saved, err := tx.Exec(ctx, `UPDATE gateway_block_requests
		SET gateway_result=$4,follow_up_state=$5,follow_up_code=$6,follow_up_until=$7,notice_pending=$8
		WHERE tenant_id=$1 AND id=$2 AND task_id=$3 AND state='authorized' AND gateway_result IS NULL`,
		tenant, action.RequestID, task, raw, state, code, until, notice)
	if err == nil && saved.RowsAffected() != 1 {
		return gatewayblock.ErrUnknown
	}
	return err
}

func authorizeGatewayFollowUp(ctx context.Context, tx pgx.Tx, id transport.SensorIdentity, r gatewayEvidence, binding gatewayblock.Health, signer ed25519.PrivateKey) (*TaskDelivery, error) {
	skip := func(code string) (*TaskDelivery, error) {
		_, err := tx.Exec(ctx, `UPDATE gateway_block_requests SET follow_up_state='skipped',follow_up_code=$3,follow_up_until=NULL
			WHERE tenant_id=$1 AND id=$2`, id.TenantID, r.ID, code)
		return nil, err
	}
	now := time.Now().UTC()
	if r.FollowUpUntil == nil || !r.FollowUpUntil.After(now) || r.GatewayResult == nil || r.GatewayResult.Observation == nil ||
		r.GatewayResult.Observation.State != gatewayblock.FlowPaused {
		return skip("observation_expired")
	}
	if !binding.Observation || r.GatewayResult.ConfigSHA256 != binding.ConfigSHA256 {
		return skip("observer_changed")
	}
	valid, err := gatewayFollowUpProof(ctx, tx, id, r, signer.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, err
	}
	if !valid {
		return skip("observation_unavailable")
	}
	settings, err := gatewaySettings(ctx, tx, id.TenantID)
	if err != nil {
		return nil, err
	}
	if !settings.Enabled || settings.UpdatedAt == nil || r.AuthorizedAt == nil || settings.UpdatedAt.After(*r.AuthorizedAt) {
		return skip("gateway_setting_changed")
	}
	policy, err := gatewayPolicy(ctx, tx, id.TenantID, r.PolicyID)
	if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, gatewayblock.ErrInput) {
		return skip("policy_changed")
	}
	if err != nil {
		return nil, err
	}
	d := policy.Definition
	if policy.Revision != r.PolicyRevision || !d.Enabled || !d.ValidUntil.After(now) || d.FollowUp == nil ||
		d.SensorID != id.SensorID || d.RegistrationID != id.RegistrationID || d.Trigger != r.Trigger || !d.Scope.Allows(r.Flow) {
		return skip("policy_changed")
	}
	actor := model.Principal{TenantID: id.TenantID, ID: policy.AuthorID, Role: "admin"}
	for _, owner := range []string{actor.ID, r.ActorID} {
		err := configurationActor(ctx, tx, model.Principal{TenantID: id.TenantID, ID: owner, Role: "admin"}, true, gatewayblock.ErrPermission)
		if errors.Is(err, gatewayblock.ErrPermission) || errors.Is(err, pgx.ErrNoRows) {
			return skip("authorization_revoked")
		}
		if err != nil {
			return nil, err
		}
	}
	if r.Trigger == gatewayblock.Review {
		if err := confirmedGatewayReview(ctx, tx, id.TenantID, r); errors.Is(err, gatewayblock.ErrIneligible) {
			return skip("assessment_changed")
		} else if err != nil {
			return nil, err
		}
	}
	h, err := gatewayDeviceHealth(ctx, tx, id, now)
	if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, gatewayblock.ErrIneligible) {
		return skip("device_changed")
	}
	if err != nil {
		return nil, err
	}
	// 等待观察之后的健康状态，才能核对本地开关和绑定是否仍然有效。
	if h.ObservedAt.Before(r.GatewayResult.Observation.FinishedAt) {
		return nil, nil
	}
	follow := *d.FollowUp
	device, artifact, err := gatewayPluginDevice(ctx, tx, id, h, follow.PluginID, now)
	if errors.Is(err, gatewayblock.ErrIneligible) || err == nil && (!follow.Matches(device) ||
		artifact.Release.Verify(signer.Public().(ed25519.PublicKey), id.TenantID, id.SensorID, id.RegistrationID) != nil) {
		return skip("device_changed")
	}
	if err != nil {
		return nil, err
	}
	// 和人工响应任务、持续授权使用同一设备行锁、预算锁和保护名单锁的顺序。
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, id.TenantID+"/response-tasks"); err != nil {
		return nil, err
	}
	if _, err := gatewayProtection(ctx, tx, id.TenantID, r, now); errors.Is(err, watchlist.ErrProtected) {
		return skip("protected_endpoint")
	} else if err != nil {
		return nil, err
	}
	target := follow.Target(r.Flow)
	var count int
	var occupied bool
	err = tx.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM gateway_block_requests WHERE tenant_id=$1 AND follow_up_state='issued'
		 AND follow_up_at>clock_timestamp()-interval '60 seconds'),
		EXISTS(SELECT 1 FROM sensor_tasks WHERE tenant_id=$1 AND sensor_id=$2 AND registration_id=$3 AND kind='response.block'
		 AND state NOT IN ('failed','cancelled','expired') AND created_at>now()-interval '1 hour'
		 AND convert_from(command,'UTF8')::jsonb->'payload'->>'device_id'=$4
		 AND convert_from(command,'UTF8')::jsonb->'payload'->>'target_ip'=$5
		 AND ((convert_from(command,'UTF8')::jsonb->'payload'->>'expires_at')::timestamptz>clock_timestamp()
		   OR created_at>clock_timestamp()-interval '60 seconds'))`,
		id.TenantID, id.SensorID, id.RegistrationID, device.DeviceID, target).Scan(&count, &occupied)
	if err != nil {
		return nil, err
	}
	if occupied {
		return skip("target_cooldown")
	}
	if count >= settings.PerMinute {
		return skip("rate_limited")
	}
	if now = time.Now().UTC(); !r.FollowUpUntil.After(now) || !d.ValidUntil.After(now) {
		return skip("observation_expired")
	}
	intent := responseapi.Intent{ConnectorID: follow.ConnectorID, ConfigSHA256: follow.ConfigSHA256, TargetIP: target,
		TTLSeconds: follow.TTLSeconds, Reason: "网关流量暂停后按策略预授权封禁 " + r.ID}
	delivery, err := signGatewayFollowUp(ctx, tx, id, actor, r.ID, intent, signer)
	switch {
	case errors.Is(err, watchlist.ErrProtected):
		return skip("protected_endpoint")
	case errors.Is(err, responseapi.ErrPermission):
		return skip("authorization_revoked")
	case errors.Is(err, responseapi.ErrInput), errors.Is(err, responseapi.ErrUnavailable), errors.Is(err, pgx.ErrNoRows):
		return skip("device_changed")
	case errors.Is(err, responseapi.ErrQuota):
		return skip("rate_limited")
	default:
		return delivery, err
	}
}

func gatewayFollowUpProof(ctx context.Context, tx pgx.Tx, id transport.SensorIdentity, r gatewayEvidence, public ed25519.PublicKey) (bool, error) {
	var command, signature []byte
	err := tx.QueryRow(ctx, `SELECT t.command,t.signature FROM gateway_block_requests g
		JOIN sensor_tasks t ON t.tenant_id=g.tenant_id AND t.id=g.task_id
		WHERE g.tenant_id=$1 AND g.id=$2 AND t.sensor_id=$3 AND t.registration_id=$4 AND t.kind=$5
		AND t.state='succeeded' AND t.receipt->'result'=g.gateway_result`,
		id.TenantID, r.ID, id.SensorID, id.RegistrationID, gatewayblock.CommandKind).Scan(&command, &signature)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var c control.Command
	if !ed25519.Verify(public, control.SignedBytes(command), signature) || json.Unmarshal(command, &c) != nil ||
		c.ID != r.TaskID || c.TenantID != id.TenantID || c.SensorID != id.SensorID || c.RegistrationID != id.RegistrationID ||
		c.Kind != gatewayblock.CommandKind || control.Validate(c) != nil {
		return false, nil
	}
	a, err := gatewayblock.ReadAction(c.Payload, c.IssuedAt, c.ExpiresAt)
	return err == nil && a.Observe && a.FollowUp && a.RequestID == r.ID && a.PolicyID == r.PolicyID &&
		a.Revision == r.PolicyRevision && a.EventID == r.EventID && a.Flow == r.Flow &&
		a.ConfigSHA256 == r.GatewayResult.ConfigSHA256, nil
}

func signGatewayFollowUp(ctx context.Context, tx pgx.Tx, id transport.SensorIdentity, actor model.Principal, requestID string, intent responseapi.Intent, signer ed25519.PrivateKey) (*TaskDelivery, error) {
	if err := intent.Validate("response.block"); err != nil {
		return nil, err
	}
	raw, _ := json.Marshal(intent)
	nested, err := tx.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = nested.Rollback(ctx) }()
	taskID, err := createTaskTx(ctx, nested, actor, id.SensorID, "response.block", RandomID("gatewayfollow_"), raw, signer, true)
	if err != nil {
		return nil, err
	}
	d := &TaskDelivery{ID: taskID}
	if err := nested.QueryRow(ctx, `UPDATE sensor_tasks SET state='delivered',delivery_count=1,last_delivery_at=clock_timestamp(),
		updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND registration_id=$3 AND state='queued'
		RETURNING command,signature,expires_at`, id.TenantID, taskID, id.RegistrationID).Scan(&d.Command, &d.Signature, &d.ExpiresAt); err != nil {
		return nil, err
	}
	if _, err := nested.Exec(ctx, `UPDATE gateway_block_requests SET follow_up_state='issued',follow_up_code='policy_authorized',
		follow_up_until=NULL,follow_up_at=clock_timestamp(),follow_up_task_id=$3 WHERE tenant_id=$1 AND id=$2`,
		id.TenantID, requestID, taskID); err != nil {
		return nil, err
	}
	if err := insertOperationAudit(ctx, nested, actor, "gateway.block.follow_up", requestID, taskID); err != nil {
		return nil, err
	}
	return d, nested.Commit(ctx)
}
