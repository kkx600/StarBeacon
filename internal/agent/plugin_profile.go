package agent

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/netip"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/response"
	"github.com/kkx600/StarBeacon/internal/responsescript"
	"github.com/kkx600/StarBeacon/internal/strictjson"
)

type pluginProfile struct {
	PluginID    string                 `json:"plugin_id"`
	Device      response.Configuration `json:"device"`
	TestAddress string                 `json:"test_address,omitempty"`
	TestHost    string                 `json:"test_host,omitempty"`
	Script      *scriptProfile         `json:"script,omitempty"`
}

type scriptProfile struct {
	Routes       []responsescript.Route           `json:"routes"`
	Login        *responsescript.Login            `json:"login,omitempty"`
	Secrets      map[string]responsescript.Secret `json:"secrets,omitempty"`
	Actions      map[string]pluginWritePlan       `json:"actions,omitempty"`
	Verify       map[string]pluginVerifyPlan      `json:"verify,omitempty"`
	DeviceHealth *pluginHealthPlan                `json:"device_health,omitempty"`
}

type pluginHealthPlan struct {
	Path   string                   `json:"path"`
	Fields []response.TemplateField `json:"fields"`
}

type pluginWritePlan struct {
	Method string                   `json:"method"`
	Path   string                   `json:"path"`
	Body   []response.TemplateField `json:"body,omitempty"`
}

type pluginVerifyPlan struct {
	Path         string                   `json:"path"`
	Fields       []response.TemplateField `json:"fields"`
	MissingField string                   `json:"missing_field"`
	MissingValue string                   `json:"missing_value"`
}

const pluginTrialSeconds = 60

func readPluginProfiles(filename string) ([]pluginProfile, error) {
	raw, err := response.ReadPrivateFile(filename, 128*1024)
	if err != nil || strictjson.TopFields(string(raw), []string{"schema_version", "profiles"}, 128*1024) != nil {
		return nil, response.ErrInput
	}
	var file struct {
		Schema   string          `json:"schema_version"`
		Profiles []pluginProfile `json:"profiles"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&file) != nil || file.Schema != "response.plugin-bindings.v1" || len(file.Profiles) == 0 || len(file.Profiles) > 8 {
		return nil, response.ErrInput
	}
	plugins, devices, connectors := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, profile := range file.Profiles {
		if !profile.valid() || plugins[profile.PluginID] || devices[profile.Device.DeviceID] || connectors[profile.Device.ID] {
			return nil, response.ErrInput
		}
		plugins[profile.PluginID], devices[profile.Device.DeviceID] = true, true
		connectors[profile.Device.ID] = true
	}
	return file.Profiles, nil
}

func reservedTrialAddress(raw string) bool {
	ip, err := netip.ParseAddr(raw)
	if err != nil || !response.ValidTarget(raw) {
		return false
	}
	for _, cidr := range []string{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"} {
		if netip.MustParsePrefix(cidr).Contains(ip) {
			return true
		}
	}
	return false
}

func (p pluginProfile) valid() bool {
	if !contract.ValidID(p.PluginID) || p.Device.ValidatePlugin() != nil ||
		p.TestAddress != "" && (!reservedTrialAddress(p.TestAddress) || !p.Device.Allows(p.TestAddress, pluginTrialSeconds)) ||
		p.TestHost != "" && !contract.ValidID(p.TestHost) {
		return false
	}
	if p.Script == nil {
		return filepath.IsAbs(p.Device.TokenFile) && p.TestHost == ""
	}
	if len(p.Script.Routes) > 32 || len(p.Script.Secrets) > 16 || len(p.Script.Actions) > 4 || len(p.Script.Verify) > 2 {
		return false
	}
	for name, secret := range p.Script.Secrets {
		if !contract.ValidID(name) || !filepath.IsAbs(secret.File) {
			return false
		}
	}
	for entry, plan := range p.Script.Actions {
		if !plan.valid(entry) {
			return false
		}
	}
	for mode, plan := range p.Script.Verify {
		if !plan.valid(mode) {
			return false
		}
	}
	if p.Script.DeviceHealth != nil && !p.Script.DeviceHealth.valid() {
		return false
	}
	return true
}

func (p pluginHealthPlan) valid() bool {
	fields := []string{"device_id", "version", "native_ttl", "separate_leases", "conditional_revoke", "max_ttl_seconds", "observed_at"}
	if !pluginRoutePath(p.Path, false) {
		return false
	}
	for _, f := range p.Fields {
		i := slices.Index(fields, f.Name)
		if i < 0 || !pluginFieldName(f.Value) {
			return false
		}
		fields = slices.Delete(fields, i, i+1)
	}
	return len(fields) == 0
}

func (p pluginProfile) binding() response.PluginBinding {
	raw, _ := json.Marshal(p)
	return response.PluginBinding{PluginID: p.PluginID, DeviceID: p.Device.DeviceID, BindingSHA256: control.Digest(raw)}
}

func (p pluginProfile) supports(v response.PluginVersion) bool {
	if v.ID != p.PluginID || (v.Script == nil) != (p.Script == nil) ||
		v.Supports("block") && p.TestAddress == "" || v.Supports("isolate") && p.TestHost == "" {
		return false
	}
	if p.Script == nil {
		return true
	}
	for _, entry := range []string{"block", "unblock", "isolate", "release"} {
		if v.Supports(entry) && !p.Script.Actions[entry].valid(entry) {
			return false
		}
	}
	for _, mode := range []string{"block", "isolate"} {
		if v.Supports(mode) && !p.Script.Verify[mode].valid(mode) {
			return false
		}
	}
	return true
}

func pluginRoutePath(raw string, variable bool) bool {
	example := raw
	if variable {
		if !strings.HasSuffix(raw, "/{rule_id}") {
			return false
		}
		example = strings.TrimSuffix(raw, "{rule_id}") + "lease"
	}
	return len(example) <= 256 && strings.HasPrefix(example, "/") && path.Clean(example) == example &&
		!strings.ContainsAny(example, "{}%?#\\") && contract.DeviceAlertText(example, 256)
}

func pluginFieldName(s string) bool {
	return s != "" && len(s) <= 64 && strings.IndexFunc(s, func(r rune) bool {
		return !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-", r)
	}) < 0
}

func (p pluginWritePlan) valid(entry string) bool {
	removes := entry == "unblock" || entry == "release"
	if entry != "block" && entry != "isolate" && !removes || len(p.Body) > 16 || !pluginRoutePath(p.Path, removes) {
		return false
	}
	if removes {
		return p.Method == http.MethodDelete && len(p.Body) == 0
	}
	if p.Method != http.MethodPut && p.Method != http.MethodPost {
		return false
	}
	target := "{{target_ip}}"
	if entry == "isolate" {
		target = "{{host_id}}"
	}
	required := []string{"{{lease_id}}", "{{owner_sha256}}", "{{expires_at}}", target}
	allowed := slices.Concat(required, []string{"{{duration_seconds}}"})
	names := map[string]bool{}
	for _, f := range p.Body {
		if !pluginFieldName(f.Name) || names[f.Name] || !contract.DeviceAlertText(f.Value, 256) ||
			strings.ContainsAny(f.Value, "{}") && !slices.Contains(allowed, f.Value) {
			return false
		}
		names[f.Name] = true
		if i := slices.Index(required, f.Value); i >= 0 {
			required = slices.Delete(required, i, i+1)
		}
	}
	return len(required) == 0
}

func (p pluginVerifyPlan) valid(mode string) bool {
	if mode != "block" && mode != "isolate" || !pluginRoutePath(p.Path, true) ||
		!pluginFieldName(p.MissingField) || !contract.DeviceAlertText(p.MissingValue, 128) {
		return false
	}
	target := "target_ip"
	if mode == "isolate" {
		target = "host_id"
	}
	required := []string{"device_id", "lease_id", "owner_sha256", "expires_at", "state", "rule_id", "observed_at", target}
	for _, f := range p.Fields {
		i := slices.Index(required, f.Name)
		if i < 0 || !pluginFieldName(f.Value) {
			return false
		}
		required = slices.Delete(required, i, i+1)
	}
	return len(required) == 0
}

type pluginLease struct {
	DeviceID    string    `json:"device_id"`
	LeaseID     string    `json:"lease_id"`
	OwnerSHA256 string    `json:"owner_sha256"`
	TargetIP    string    `json:"target_ip,omitempty"`
	HostID      string    `json:"host_id,omitempty"`
	ExpiresAt   time.Time `json:"expires_at"`
	ObservedAt  time.Time `json:"observed_at,omitempty"`
	State       string    `json:"state,omitempty"`
	RuleID      string    `json:"rule_id,omitempty"`
}

func (p pluginWritePlan) grant(lease pluginLease, duration int) *responsescript.ApprovedWrite {
	grant := &responsescript.ApprovedWrite{Method: p.Method, Path: p.Path}
	if p.Method == http.MethodDelete {
		grant.Path = strings.Replace(p.Path, "{rule_id}", lease.RuleID, 1)
		grant.OwnerSHA256 = lease.OwnerSHA256
		return grant
	}
	slots := map[string]any{"{{lease_id}}": lease.LeaseID, "{{owner_sha256}}": lease.OwnerSHA256,
		"{{expires_at}}": lease.ExpiresAt.Format(time.RFC3339Nano), "{{target_ip}}": lease.TargetIP, "{{host_id}}": lease.HostID,
		"{{duration_seconds}}": duration}
	body := make(map[string]any, len(p.Body))
	for _, field := range p.Body {
		value, ok := slots[field.Value]
		if !ok {
			value = field.Value
		}
		body[field.Name] = value
	}
	grant.Body, _ = json.Marshal(body)
	return grant
}

func (p pluginVerifyPlan) readback(reply *responsescript.Readback, want pluginLease) (pluginLease, error) {
	if reply == nil {
		return pluginLease{}, response.ErrUnknown
	}
	if reply.Status == http.StatusNotFound {
		var missing string
		if json.Unmarshal(reply.Fields[p.MissingField], &missing) == nil && missing == p.MissingValue {
			return pluginLease{State: "missing"}, nil
		}
	}
	if reply.Status != http.StatusOK {
		return pluginLease{}, response.ErrUnknown
	}
	selected := make(map[string]json.RawMessage, len(p.Fields))
	for _, f := range p.Fields {
		if raw, ok := reply.Fields[f.Value]; ok {
			selected[f.Name] = raw
		}
	}
	raw, _ := json.Marshal(selected)
	var actual pluginLease
	now := time.Now()
	if json.Unmarshal(raw, &actual) != nil || (actual.State != "active" && actual.State != "expired" && actual.State != "revoked") ||
		actual.DeviceID != want.DeviceID || actual.LeaseID != want.LeaseID || actual.OwnerSHA256 != want.OwnerSHA256 ||
		actual.TargetIP != want.TargetIP || actual.HostID != want.HostID || !actual.ExpiresAt.Equal(want.ExpiresAt) ||
		!contract.ValidID(actual.RuleID) || want.RuleID != "" && actual.RuleID != want.RuleID ||
		actual.ObservedAt.Before(now.Add(-30*time.Second)) || actual.ObservedAt.After(now.Add(30*time.Second)) ||
		actual.State == "active" && !actual.ExpiresAt.After(now) {
		return pluginLease{}, response.ErrUnknown
	}
	return actual, nil
}
