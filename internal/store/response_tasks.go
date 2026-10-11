package store

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/model"
	responseapi "github.com/kkx600/StarBeacon/internal/response"
)

func (p *Postgres) CreateResponseTask(ctx context.Context, u model.Principal, sensor, key string, v responseapi.Request, signer ed25519.PrivateKey) (string, error) {
	if u.Role != "admin" {
		return "", responseapi.ErrPermission
	}
	if v.Intent.Validate(v.Kind) != nil || !contract.ValidID(u.ID) || !contract.ValidID(u.TenantID) || !contract.ValidID(sensor) || !contract.ValidID(key) || len(key) < 8 {
		return "", responseapi.ErrInput
	}
	raw, err := json.Marshal(v.Intent)
	if err != nil {
		return "", err
	}
	return p.CreateTask(ctx, u, sensor, v.Kind, key, raw, signer)
}
func responseTaskActor(ctx context.Context, tx pgx.Tx, u model.Principal) error {
	if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout='2s'; SET LOCAL statement_timeout='5s'`); err != nil {
		return err
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
	if !active || !tenantActive || role != "admin" || u.Role != "admin" || u.CredentialRevision > 0 && revision != u.CredentialRevision {
		return responseapi.ErrPermission
	}
	return nil
}
func qualifyResponseTask(ctx context.Context, tx pgx.Tx, u model.Principal, sensor, registration, kind, id string, now time.Time, payload json.RawMessage, signer ed25519.PrivateKey) (json.RawMessage, time.Time, error) {
	intent, err := responseapi.ReadIntent(payload, kind)
	if err != nil {
		return nil, time.Time{}, err
	}
	if len(signer) != ed25519.PrivateKeySize {
		return nil, time.Time{}, responseapi.ErrUnavailable
	}
	var rawHealth []byte
	var lastSeen *time.Time
	if err = tx.QueryRow(ctx, `SELECT health,last_seen FROM sensors WHERE tenant_id=$1 AND id=$2 AND registration_id=$3 AND active`, u.TenantID, sensor, registration).Scan(&rawHealth, &lastSeen); err != nil {
		return nil, time.Time{}, err
	}
	var health model.HostHealth
	if json.Unmarshal(rawHealth, &health) != nil || !slices.Contains(health.TaskCapabilities, kind) || lastSeen == nil || now.Sub(*lastSeen) > 35*time.Second || lastSeen.After(now.Add(30*time.Second)) || now.Sub(health.ObservedAt) > 35*time.Second || health.ObservedAt.After(now.Add(30*time.Second)) || health.CommandSignerSHA256 != control.Digest(signer.Public().(ed25519.PublicKey)) {
		return nil, time.Time{}, responseapi.ErrUnavailable
	}
	var binding *responseapi.Health
	for _, h := range health.ResponseConnectors {
		if h.ConnectorID == intent.ConnectorID {
			if binding != nil {
				return nil, time.Time{}, responseapi.ErrUnavailable
			}
			value := h
			binding = &value
		}
	}
	if binding == nil || !binding.Ready(now) || binding.ConfigSHA256 != intent.ConfigSHA256 {
		return nil, time.Time{}, responseapi.ErrUnavailable
	}
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, u.TenantID+"/response-tasks"); err != nil {
		return nil, time.Time{}, err
	}
	var count int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM sensor_tasks WHERE tenant_id=$1 AND kind LIKE 'response.%' AND created_at>now()-interval '24 hours'`, u.TenantID).Scan(&count); err != nil {
		return nil, time.Time{}, err
	}
	if count >= 1024 {
		return nil, time.Time{}, responseapi.ErrQuota
	}
	var action responseapi.Action
	deadline := now.Add(2 * time.Minute)
	if kind == "response.block" {
		if intent.TTLSeconds > binding.MaxTTLSeconds {
			return nil, time.Time{}, responseapi.ErrInput
		}
		action = responseapi.Action{SchemaVersion: responseapi.ActionSchema, ConnectorID: intent.ConnectorID, ConfigSHA256: intent.ConfigSHA256, DeviceID: binding.DeviceID, LeaseID: id, OwnerSHA256: responseapi.Owner(u.TenantID, sensor, registration, id), TargetIP: intent.TargetIP, RequestedAt: now, ExpiresAt: now.Add(time.Duration(intent.TTLSeconds) * time.Second), Reason: intent.Reason}
		deadline = now.Add(time.Duration(min(intent.TTLSeconds-5, 60)) * time.Second)
	} else {
		var command, signature []byte
		if err = tx.QueryRow(ctx, `SELECT command,signature FROM sensor_tasks WHERE tenant_id=$1 AND id=$2 AND sensor_id=$3 AND registration_id=$4 AND kind='response.block' AND delivery_count>0 AND retain_until>now()`, u.TenantID, intent.OriginalTaskID, sensor, registration).Scan(&command, &signature); err != nil {
			return nil, time.Time{}, err
		}
		var original control.Command
		if !ed25519.Verify(signer.Public().(ed25519.PublicKey), control.SignedBytes(command), signature) || json.Unmarshal(command, &original) != nil || control.Validate(original) != nil || original.ID != intent.OriginalTaskID || original.SensorID != sensor || original.TenantID != u.TenantID || original.RegistrationID != registration {
			return nil, time.Time{}, responseapi.ErrInput
		}
		action, err = responseapi.ReadAction(original.Payload)
		if err != nil || action.ConnectorID != intent.ConnectorID || action.ConfigSHA256 != intent.ConfigSHA256 || action.DeviceID != binding.DeviceID {
			return nil, time.Time{}, responseapi.ErrInput
		}
	}
	if action.Validate() != nil {
		return nil, time.Time{}, responseapi.ErrInput
	}
	raw, err := json.Marshal(action)
	return raw, deadline, err
}
