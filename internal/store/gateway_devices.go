package store

import (
	"context"
	"encoding/json"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/gatewayblock"
	"github.com/kkx600/StarBeacon/internal/model"
	responseapi "github.com/kkx600/StarBeacon/internal/response"
	"github.com/kkx600/StarBeacon/internal/transport"
)

func gatewayDeviceHealth(ctx context.Context, tx pgx.Tx, id transport.SensorIdentity, now time.Time) (model.HostHealth, error) {
	var h model.HostHealth
	var raw []byte
	var seen *time.Time
	if err := tx.QueryRow(ctx, `SELECT health,last_seen FROM sensors WHERE tenant_id=$1 AND id=$2 AND registration_id=$3 AND active`,
		id.TenantID, id.SensorID, id.RegistrationID).Scan(&raw, &seen); err != nil {
		return h, err
	}
	if json.Unmarshal(raw, &h) != nil || seen == nil || now.Sub(*seen) > 35*time.Second || seen.After(now.Add(2*time.Second)) ||
		h.ObservedAt.IsZero() || now.Sub(h.ObservedAt) > 35*time.Second || h.ObservedAt.After(now.Add(2*time.Second)) ||
		h.GatewayBlock == nil || !h.GatewayBlock.Observation || !gatewayblock.ValidDigest(h.GatewayBlock.ConfigSHA256) ||
		len(h.ResponseConnectors) > 8 || len(h.PluginBindings) > 8 || !slices.Contains(h.TaskCapabilities, "response.block") {
		return model.HostHealth{}, gatewayblock.ErrIneligible
	}
	return h, nil
}

func gatewayPluginDevice(ctx context.Context, tx pgx.Tx, id transport.SensorIdentity, h model.HostHealth, plugin string, now time.Time) (gatewayblock.FollowUpDevice, *responseapi.PluginArtifact, error) {
	var out gatewayblock.FollowUpDevice
	binding := selectPluginBinding(h, plugin)
	if binding == nil {
		return out, nil, gatewayblock.ErrIneligible
	}
	current, _, err := pluginAssignment(ctx, tx, id, plugin)
	if err != nil {
		return out, nil, err
	}
	artifact := current.Current
	if current.Generation < 1 || artifact == nil || artifact.Release.Grant.Binding != *binding || !artifact.Version.Supports("block") {
		return out, nil, gatewayblock.ErrIneligible
	}
	hash := responseapi.PluginConnectorSHA256(binding.BindingSHA256, artifact.Version.DefinitionSHA256())
	var connector *responseapi.Health
	for i := range h.ResponseConnectors {
		entry := &h.ResponseConnectors[i]
		if entry.DeviceID != binding.DeviceID {
			continue
		}
		if connector != nil || entry.ConfigSHA256 != hash || !entry.Ready(now) {
			return out, nil, gatewayblock.ErrIneligible
		}
		connector = entry
	}
	if connector == nil {
		return out, nil, gatewayblock.ErrIneligible
	}
	return gatewayblock.FollowUpDevice{PluginID: plugin, Generation: current.Generation, Version: artifact.Version.Version,
		ConnectorID: connector.ConnectorID, DeviceID: connector.DeviceID, ConfigSHA256: hash, MaxTTLSeconds: connector.MaxTTLSeconds}, artifact, nil
}

func (p *Postgres) GatewayFollowUpDevices(ctx context.Context, u model.Principal, sensor, registration string) ([]gatewayblock.FollowUpDevice, error) {
	out := []gatewayblock.FollowUpDevice{}
	if !contract.ValidID(sensor) || !contract.ValidID(registration) {
		return out, gatewayblock.ErrInput
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := configurationActor(ctx, tx, u, true, gatewayblock.ErrPermission); err != nil {
			return err
		}
		id := transport.SensorIdentity{TenantID: u.TenantID, SensorID: sensor, RegistrationID: registration}
		now := time.Now().UTC()
		h, err := gatewayDeviceHealth(ctx, tx, id, now)
		if err == gatewayblock.ErrIneligible {
			return nil
		}
		if err != nil {
			return err
		}
		for _, binding := range h.PluginBindings {
			device, _, err := gatewayPluginDevice(ctx, tx, id, h, binding.PluginID, now)
			if err == gatewayblock.ErrIneligible {
				continue
			}
			if err != nil {
				return err
			}
			out = append(out, device)
		}
		return nil
	})
	return out, err
}
