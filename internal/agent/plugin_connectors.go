package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/response"
	"github.com/kkx600/StarBeacon/internal/responsescript"
	bolt "go.etcd.io/bbolt"
)

type scriptConnector struct{ runtime *pluginRuntime }

func (s scriptConnector) Describe(ctx context.Context) (response.Device, error) {
	r := s.runtime
	var device response.Device
	plan := r.profile.Script.DeviceHealth
	if plan == nil || !r.version.Supports("health") {
		return device, response.ErrUnavailable
	}
	res := r.script.Run(ctx, responsescript.Invocation{Entry: "health", ReadbackPath: plan.Path})
	if res.Code != responsescript.OK || res.Readback == nil || res.Readback.Status != http.StatusOK || !acceptedScriptResult(res.Value) {
		return device, response.ErrUnavailable
	}
	mapped := make(map[string]json.RawMessage, len(plan.Fields))
	for _, f := range plan.Fields {
		if raw := res.Readback.Fields[f.Value]; raw != nil {
			mapped[f.Name] = raw
		}
	}
	raw, _ := json.Marshal(mapped)
	if json.Unmarshal(raw, &device) != nil {
		return device, response.ErrUnavailable
	}
	device.SchemaVersion, device.ObservedAt = response.DeviceSchema, device.ObservedAt.UTC()
	return device, device.Validate(r.profile.Device.DeviceID, r.profile.Device.DeviceVersion, time.Now().UTC())
}

func actionLease(a response.Action) pluginLease {
	return pluginLease{DeviceID: a.DeviceID, LeaseID: a.LeaseID, OwnerSHA256: a.OwnerSHA256, TargetIP: a.TargetIP, ExpiresAt: a.ExpiresAt}
}

func (s scriptConnector) Read(ctx context.Context, a response.Action) (response.Lease, bool, error) {
	got, err := s.runtime.observe(ctx, "block", actionLease(a))
	if err != nil || got.State == "missing" {
		return response.Lease{}, got.State == "missing", err
	}
	return response.Lease{SchemaVersion: response.LeaseSchema, DeviceID: got.DeviceID, LeaseID: got.LeaseID,
		OwnerSHA256: got.OwnerSHA256, TargetIP: got.TargetIP, ExpiresAt: got.ExpiresAt,
		State: got.State, ObservedAt: got.ObservedAt.UTC(), DeviceRuleID: got.RuleID}, false, nil
}

func (s scriptConnector) Block(ctx context.Context, a response.Action) (string, int, error) {
	id, err := s.runtime.mutate(ctx, "block", actionLease(a), int(a.ExpiresAt.Sub(a.RequestedAt)/time.Second))
	return id, http.StatusAccepted, err
}

func (s scriptConnector) Unblock(ctx context.Context, a response.Action, existing response.Lease) (int, error) {
	lease := actionLease(a)
	lease.RuleID = existing.DeviceRuleID
	_, err := s.runtime.mutate(ctx, "unblock", lease, int(a.ExpiresAt.Sub(a.RequestedAt)/time.Second))
	return http.StatusAccepted, err
}

func (r *pluginRuntime) bindConnector() error {
	if !r.version.Supports("block") || r.script != nil && (!r.version.Supports("health") || r.profile.Script.DeviceHealth == nil) {
		// 生产 IP 处置沿用现有设备身份和原生到期核验。
		return nil
	}
	scope, _ := json.Marshal([]string{"response.plugin.connector.v1", r.profile.binding().BindingSHA256, r.version.DefinitionSHA256()})
	hash := control.Digest(scope)
	if r.template != nil {
		if err := r.template.BindPlugin(hash); err != nil {
			return err
		}
		r.connector = r.template
		return nil
	}
	var err error
	r.connector, err = response.NewPluginDevice(r.profile.Device, hash, scriptConnector{runtime: r})
	return err
}

func (s *PluginService) lookupConnector(id, hash string, activeOnly bool) (*response.Client, func()) {
	s.mu.Lock()
	for _, profile := range s.profiles {
		if profile.Device.ID != id {
			continue
		}
		r, err := s.current(profile.PluginID)
		if err != nil {
			break
		}
		if r != nil && r.connector != nil && r.connector.BindingSHA256() == hash {
			return r.connector, s.mu.Unlock
		}
		if activeOnly {
			break
		}
		var previous *response.PluginArtifact
		err = s.wal.DB.View(func(tx *bolt.Tx) error {
			value, err := localPluginAssignment(tx, profile.PluginID)
			previous = value.Previous
			return err
		})
		if err != nil || previous == nil || previous.Release.Grant.Binding != profile.binding() ||
			previous.Release.Verify(s.key, s.wal.TenantID, s.wal.SensorID, s.wal.RegistrationID) != nil {
			break
		}
		old, err := s.open(profile, previous.Version, nil)
		if err != nil {
			break
		}
		if old.bindConnector() == nil && old.connector != nil && old.connector.BindingSHA256() == hash {
			return old.connector, func() { old.close(); s.mu.Unlock() }
		}
		old.close()
		break
	}
	s.mu.Unlock()
	return nil, nil
}

func (s *PluginService) observeConnector(ctx context.Context, plugin string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := s.current(plugin)
	var entry *response.Health
	if err == nil && r != nil && r.connector != nil {
		cfg := r.profile.Device
		value := response.Health{ConnectorID: cfg.ID, DeviceID: cfg.DeviceID, Version: cfg.DeviceVersion,
			ConfigSHA256: r.connector.BindingSHA256(), MaxTTLSeconds: cfg.MaxTTLSeconds, Status: "unavailable"}
		if device, err := r.connector.Describe(ctx); err == nil {
			value.Status, value.MaxTTLSeconds = "ready", min(device.MaxTTLSeconds, value.MaxTTLSeconds)
		}
		value.ObservedAt = time.Now().UTC()
		entry = &value
	}
	s.healthMu.Lock()
	defer s.healthMu.Unlock()
	if entry == nil {
		delete(s.connectors, plugin)
	} else {
		s.connectors[plugin] = *entry
	}
}

func (s *PluginService) connectorHealth() []response.Health {
	s.healthMu.RLock()
	defer s.healthMu.RUnlock()
	items := make([]response.Health, 0, len(s.connectors))
	for _, p := range s.bindings {
		if v, ok := s.connectors[p.PluginID]; ok {
			items = append(items, v)
		}
	}
	return items
}

func (s *PluginService) hasOpenResponseLease(tx *bolt.Tx, id string) bool {
	leases := tx.Bucket([]byte("response_leases"))
	if leases == nil {
		return false
	}
	now := time.Now()
	cursor := leases.Cursor()
	for _, raw := cursor.First(); raw != nil; _, raw = cursor.Next() {
		var record responseRecord
		if json.Unmarshal(raw, &record) != nil {
			return true
		}
		if record.Action.ConnectorID == id && record.Action.ExpiresAt.After(now) && record.Status != "revoked" && record.Status != "expired" {
			return true
		}
	}
	return false
}
