package store

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/gatewayblock"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/transport"
	"github.com/kkx600/StarBeacon/internal/watchlist"
)

// NextGatewayBlock 只在可执行网关的 mTLS 控制流上签发短时命令。
// 在同一事务重新确认授权、两侧保护名单、滚动限额和设备签名绑定。
func (p *Postgres) NextGatewayBlock(ctx context.Context, sensor transport.SensorIdentity, signer ed25519.PrivateKey) (*TaskDelivery, error) {
	if len(signer) != ed25519.PrivateKeySize || !contract.ValidID(sensor.TenantID) ||
		!contract.ValidID(sensor.SensorID) || !contract.ValidID(sensor.RegistrationID) {
		return nil, gatewayblock.ErrInput
	}
	var delivery *TaskDelivery
	err := p.TenantTx(ctx, sensor.TenantID, func(tx pgx.Tx) error {
		tenant := sensor.TenantID
		var pending bool
		err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM gateway_block_requests
			WHERE tenant_id=$1 AND sensor_id=$2 AND registration_id=$3
			AND ((state='pending' AND deadline>clock_timestamp()) OR
			(follow_up_state='pending' AND follow_up_until>clock_timestamp())))`,
			tenant, sensor.SensorID, sensor.RegistrationID).Scan(&pending)
		if err != nil || !pending {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared(hashtextextended($1,0))`, tenant+"/users"); err != nil {
			return err
		}
		if err := lockGatewayBlocks(ctx, tx, tenant); err != nil {
			return err
		}
		binding, err := gatewayBinding(ctx, tx, sensor, signer.Public().(ed25519.PublicKey))
		if err != nil || binding == nil {
			return err
		}
		effect, err := scanGatewayRequest(tx.QueryRow(ctx, `SELECT `+gatewayRequestColumns+` FROM gateway_block_requests
			WHERE tenant_id=$1 AND sensor_id=$2 AND registration_id=$3 AND follow_up_state='pending' AND follow_up_until>clock_timestamp()
			ORDER BY follow_up_until,id LIMIT 1 FOR UPDATE`, tenant, sensor.SensorID, sensor.RegistrationID))
		if err == nil {
			delivery, err = authorizeGatewayFollowUp(ctx, tx, sensor, effect, *binding, signer)
			return err
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		r, err := scanGatewayRequest(tx.QueryRow(ctx, `SELECT `+gatewayRequestColumns+` FROM gateway_block_requests
			WHERE tenant_id=$1 AND sensor_id=$2 AND registration_id=$3 AND state='pending' AND deadline>clock_timestamp()
			ORDER BY created_at,id LIMIT 1 FOR UPDATE`, tenant, sensor.SensorID, sensor.RegistrationID))
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		delivery, err = authorizeGatewayBlock(ctx, tx, tenant, r, *binding, signer)
		return err
	})
	return delivery, err
}

func gatewayBinding(ctx context.Context, tx pgx.Tx, sensor transport.SensorIdentity, public ed25519.PublicKey) (*gatewayblock.Health, error) {
	var encoded []byte
	var seen *time.Time
	err := tx.QueryRow(ctx, `SELECT health,last_seen FROM sensors WHERE tenant_id=$1 AND id=$2 AND registration_id=$3 AND active FOR UPDATE`,
		sensor.TenantID, sensor.SensorID, sensor.RegistrationID).Scan(&encoded, &seen)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var h model.HostHealth
	now := time.Now()
	if json.Unmarshal(encoded, &h) != nil || seen == nil || h.GatewayBlock == nil ||
		now.Sub(*seen) > 35*time.Second || seen.After(now.Add(2*time.Second)) ||
		now.Sub(h.ObservedAt) > 35*time.Second || h.ObservedAt.After(now.Add(2*time.Second)) ||
		h.CommandSignerSHA256 != control.Digest(public) || !gatewayblock.ValidDigest(h.GatewayBlock.ConfigSHA256) {
		return nil, nil
	}
	var busy bool
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM sensor_tasks WHERE tenant_id=$1 AND sensor_id=$2 AND state IN ('queued','delivered','running')
		AND (expires_at>now() OR delivery_count>0))`, sensor.TenantID, sensor.SensorID).Scan(&busy)
	if err != nil || busy {
		return nil, err
	}
	return h.GatewayBlock, nil
}

func authorizeGatewayBlock(ctx context.Context, tx pgx.Tx, tenant string, r gatewayEvidence, binding gatewayblock.Health, signer ed25519.PrivateKey) (*TaskDelivery, error) {
	deny := func(code string) (*TaskDelivery, error) {
		_, err := tx.Exec(ctx, `UPDATE gateway_block_requests SET state='denied',code=$3 WHERE tenant_id=$1 AND id=$2`, tenant, r.ID, code)
		return nil, err
	}
	now := time.Now().UTC()
	if !r.Deadline.After(now) {
		return deny("observation_expired")
	}
	if r.PlaybookRunID != "" {
		allowed, err := playbookGatewayAllowed(ctx, tx, tenant)
		if err != nil {
			return nil, err
		}
		if !allowed {
			return deny("authorization_revoked")
		}
	}
	settings, err := gatewaySettings(ctx, tx, tenant)
	if err != nil {
		return nil, err
	}
	if !settings.Enabled {
		return deny("gateway_block_disabled")
	}
	policy, err := gatewayPolicy(ctx, tx, tenant, r.PolicyID)
	if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, gatewayblock.ErrInput) {
		return deny("policy_changed")
	}
	if err != nil {
		return nil, err
	}
	if policy.Revision != r.PolicyRevision || policy.Definition.Trigger != r.Trigger || !r.qualifies(policy, settings, now) {
		return deny("policy_changed")
	}
	for _, owner := range []string{policy.AuthorID, r.ActorID} {
		err := configurationActor(ctx, tx, model.Principal{ID: owner, TenantID: tenant, Role: "admin"}, true, gatewayblock.ErrPermission)
		if errors.Is(err, gatewayblock.ErrPermission) || errors.Is(err, pgx.ErrNoRows) {
			return deny("authorization_revoked")
		}
		if err != nil {
			return nil, err
		}
	}
	if r.Trigger == gatewayblock.Review {
		err := confirmedGatewayReview(ctx, tx, tenant, r)
		if errors.Is(err, gatewayblock.ErrIneligible) {
			return deny("assessment_changed")
		}
		if err != nil {
			return nil, err
		}
	}
	stateSHA, err := gatewayProtection(ctx, tx, tenant, r, now)
	if errors.Is(err, watchlist.ErrProtected) {
		return deny("protected_endpoint")
	}
	if err != nil {
		return nil, err
	}
	var count int
	var occupied bool
	err = tx.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM gateway_block_requests WHERE tenant_id=$1 AND state='authorized' AND authorized_at>clock_timestamp()-interval '60 seconds'),
		EXISTS(SELECT 1 FROM gateway_block_requests WHERE tenant_id=$1 AND sensor_id=$2 AND registration_id=$3
		 AND state='authorized' AND flow_key=$4 AND lease_until>clock_timestamp())`, tenant, r.SensorID, r.RegistrationID, r.Flow.Key()).
		Scan(&count, &occupied)
	if err != nil {
		return nil, err
	}
	if occupied {
		return deny("active_flow_lease")
	}
	if count >= settings.PerMinute {
		return deny("rate_limited")
	}
	now = time.Now().UTC()
	if !r.Deadline.After(now) || !r.qualifies(policy, settings, now) {
		return deny("observation_expired")
	}
	return signGatewayBlock(ctx, tx, tenant, r, policy, binding, stateSHA, now, signer)
}

func gatewayProtection(ctx context.Context, tx pgx.Tx, tenant string, r gatewayEvidence, now time.Time) (string, error) {
	source, err := CheckWatchlistResponseTx(ctx, tx, tenant, r.SensorID, r.RegistrationID, r.Flow.SourceIP.String(), now)
	if err != nil {
		return "", err
	}
	dest, err := CheckWatchlistResponseTx(ctx, tx, tenant, r.SensorID, r.RegistrationID, r.Flow.DestinationIP.String(), now)
	if err != nil {
		return "", err
	}
	if source.StateSHA256 != dest.StateSHA256 || !gatewayblock.ValidDigest(source.StateSHA256) {
		return "", watchlist.ErrSource
	}
	return source.StateSHA256, nil
}

func signGatewayBlock(ctx context.Context, tx pgx.Tx, tenant string, r gatewayEvidence, policy gatewayblock.Policy,
	binding gatewayblock.Health, stateSHA string, now time.Time, signer ed25519.PrivateKey) (*TaskDelivery, error) {
	id := RandomID("task_")
	lease := minTime(now.Add(time.Duration(policy.Definition.LeaseSeconds)*time.Second), policy.Definition.ValidUntil)
	expires := minTime(now.Add(gatewayblock.DispatchWindow), minTime(r.Deadline, lease.Add(-time.Second)))
	action := gatewayblock.Action{RequestID: r.ID, EventID: r.EventID, ConfigSHA256: binding.ConfigSHA256,
		PolicyID: r.PolicyID, Revision: r.PolicyRevision, Trigger: r.Trigger, Flow: r.Flow, LeaseUntil: lease,
		Observe: binding.Observation, FollowUp: policy.Definition.FollowUp != nil}
	payload, err := json.Marshal(action)
	if err != nil {
		return nil, err
	}
	c := control.Command{ID: id, TenantID: tenant, SensorID: r.SensorID, RegistrationID: r.RegistrationID,
		Kind: gatewayblock.CommandKind, IssuedAt: now, ExpiresAt: expires, Payload: payload}
	raw, signature, err := control.Encode(c, signer)
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `UPDATE sensor_tasks SET state='expired',updated_at=now() WHERE tenant_id=$1 AND sensor_id=$2
		AND state='queued' AND delivery_count=0 AND expires_at<=now()`, tenant, r.SensorID); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO sensor_tasks(tenant_id,id,sensor_id,registration_id,kind,state,idempotency_key,
		 request_sha256,command,signature,command_sha256,created_by,expires_at,retain_until,last_delivery_at,delivery_count)
		 SELECT $1,$2,$3,$4,$5,'delivered',$6,$7,$8,$9,$10,$11,$12,expires_at,clock_timestamp(),1
		 FROM gateway_block_requests WHERE tenant_id=$1 AND id=$6`,
		tenant, id, r.SensorID, r.RegistrationID, c.Kind, r.ID, control.Digest(payload), raw, signature, control.Digest(raw), r.ActorID, expires); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `UPDATE gateway_block_requests SET state='authorized',task_id=$3,
		authorized_at=$4,lease_until=$5,protection_sha256=$6 WHERE tenant_id=$1 AND id=$2`, tenant, r.ID, id, now, lease, stateSHA); err != nil {
		return nil, err
	}
	user := model.Principal{ID: r.ActorID, TenantID: tenant, Role: "admin"}
	if err := insertOperationAudit(ctx, tx, user, "gateway.block.authorize", r.ID, id); err != nil {
		return nil, err
	}
	return &TaskDelivery{ID: id, Command: raw, Signature: signature, ExpiresAt: expires}, nil
}
