package store

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/packetarchive"
	"github.com/kkx600/StarBeacon/internal/packetpolicy"
)

var ErrPacketRetentionPermission = errors.New("当前账号不能管理原包留存策略")

type PacketStorageSensor struct {
	ID       string               `json:"id"`
	Name     string               `json:"name"`
	Status   *packetpolicy.Status `json:"status"`
	Fresh    bool                 `json:"fresh"`
	CanApply bool                 `json:"can_apply"`
}

func (p *Postgres) PacketStorageSensors(ctx context.Context, u model.Principal, signer ed25519.PrivateKey) ([]PacketStorageSensor, error) {
	out := []PacketStorageSensor{}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := configurationActor(ctx, tx, u, true, ErrPacketRetentionPermission); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT id,name,active,last_seen,health->'packet_retention',
			health->>'command_signer_sha256',COALESCE(health->'task_capabilities' ? $2,false)
			FROM sensors WHERE tenant_id=$1 AND health ? 'packet_archive' ORDER BY active DESC, id LIMIT 501`, u.TenantID, control.PacketRetentionConfigure)
		if err != nil {
			return err
		}
		defer rows.Close()
		now := time.Now().UTC()
		var digest string
		if len(signer) == ed25519.PrivateKeySize {
			digest = control.Digest(signer.Public().(ed25519.PublicKey))
		}
		for rows.Next() {
			var row PacketStorageSensor
			var active, capable bool
			var lastSeen *time.Time
			var raw json.RawMessage
			var signedBy *string
			if err := rows.Scan(&row.ID, &row.Name, &active, &lastSeen, &raw, &signedBy, &capable); err != nil {
				return err
			}
			var status packetpolicy.Status
			if json.Unmarshal(raw, &status) == nil && status.Valid() {
				row.Status = &status
				row.Fresh = active && lastSeen != nil && freshRetention(*lastSeen, status.ObservedAt, now)
				row.CanApply = row.Fresh && status.State == "ready" && capable && digest != "" && signedBy != nil && *signedBy == digest
			}
			out = append(out, row)
		}
		return rows.Err()
	})
	return out, err
}

func freshRetention(lastSeen, observed, now time.Time) bool {
	return !lastSeen.Before(now.Add(-35*time.Second)) && !observed.Before(now.Add(-35*time.Second)) &&
		!lastSeen.After(now.Add(30*time.Second)) && !observed.After(now.Add(30*time.Second))
}

// 调用方已持有采集器行锁。任务必须绑定当前注册代次、签名者和已报告的修订。
func qualifyPacketRetention(ctx context.Context, tx pgx.Tx, tenant, sensor, registration string, raw json.RawMessage, signer ed25519.PrivateKey) error {
	var change packetpolicy.Change
	if len(signer) != ed25519.PrivateKeySize || json.Unmarshal(raw, &change) != nil {
		return packetpolicy.ErrInput
	}
	var encoded json.RawMessage
	var lastSeen *time.Time
	err := tx.QueryRow(ctx, `SELECT health,last_seen FROM sensors WHERE tenant_id=$1 AND id=$2 AND registration_id=$3 AND active`, tenant, sensor, registration).Scan(&encoded, &lastSeen)
	if err != nil {
		return err
	}
	var health model.HostHealth
	var status packetpolicy.Status
	if lastSeen == nil || json.Unmarshal(encoded, &health) != nil || json.Unmarshal(health.PacketRetention, &status) != nil ||
		!status.Valid() || status.State != "ready" || !freshRetention(*lastSeen, status.ObservedAt, time.Now().UTC()) ||
		!slices.Contains(health.TaskCapabilities, control.PacketRetentionConfigure) ||
		health.CommandSignerSHA256 != control.Digest(signer.Public().(ed25519.PublicKey)) || !status.Configuration.Matches(change) {
		return packetarchive.ErrRetentionConflict
	}
	return nil
}
