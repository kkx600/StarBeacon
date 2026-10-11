// Package response 定义采集器侧有界 HTTP 响应协议；配置生效不代表流量阻断效果。
package response

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/kkx600/StarBeacon/internal/contract"
)

const ActionSchema = "response.action.v1"
const LeaseSchema = "response.lease.v1"
const DeviceSchema = "response.device.v1"
const MaxTTLSeconds = 3600

var ErrInput = errors.New("联动参数不符合目标、范围或期限要求")
var ErrUnavailable = errors.New("联动设备身份、能力或认证无法确认")
var ErrUnknown = errors.New("设备执行结果尚未确认，需回读原租约")
var ErrPermission = errors.New("当前账号没有联动任务权限")
var ErrQuota = errors.New("租户最近 24 小时的联动任务额度已用尽")

func digest(v any) string {
	raw, _ := json.Marshal(v)
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}
func validHash(value string) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == 32 && strings.ToLower(value) == value
}
func validText(value string, limit int) bool {
	return utf8.ValidString(value) && value != "" && strings.TrimSpace(value) == value && len([]rune(value)) <= limit && !strings.ContainsFunc(value, unicode.IsControl)
}
func ValidTarget(value string) bool {
	ip, err := netip.ParseAddr(value)
	return err == nil && ip.String() == value && !ip.Is4In6() && ip.Zone() == "" && ip.IsGlobalUnicast() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !netip.MustParsePrefix("0.0.0.0/8").Contains(ip) && !netip.MustParsePrefix("240.0.0.0/4").Contains(ip)
}
func Owner(tenant, sensor, registration, lease string) string {
	return digest([]string{"StarBeacon/response-owner/v1", tenant, sensor, registration, lease})
}

// Intent 由平台管理员明确提交；影子评估和模型分数不能直接生成此授权。
type Intent struct {
	ConnectorID    string `json:"connector_id"`
	ConfigSHA256   string `json:"config_sha256"`
	TargetIP       string `json:"target_ip,omitempty"`
	TTLSeconds     int    `json:"ttl_seconds,omitempty"`
	Reason         string `json:"reason"`
	OriginalTaskID string `json:"original_task_id,omitempty"`
}
type Request struct {
	Kind string `json:"kind"`
	Intent
}

func ReadIntent(raw []byte, kind string) (Intent, error) {
	var result Intent
	if contract.JSONFields(string(raw), []string{"connector_id", "config_sha256", "target_ip", "ttl_seconds", "reason", "original_task_id"}, 8192) != nil || json.Unmarshal(raw, &result) != nil || result.Validate(kind) != nil {
		return result, ErrInput
	}
	return result, nil
}

func (v Intent) Validate(kind string) error {
	if !contract.ValidID(v.ConnectorID) || !validHash(v.ConfigSHA256) || !validText(v.Reason, 500) {
		return ErrInput
	}
	switch kind {
	case "response.block":
		if !ValidTarget(v.TargetIP) || v.TTLSeconds < 30 || v.TTLSeconds > MaxTTLSeconds || v.OriginalTaskID != "" {
			return ErrInput
		}
	case "response.read", "response.revoke":
		if !contract.ValidID(v.OriginalTaskID) || v.TargetIP != "" || v.TTLSeconds != 0 {
			return ErrInput
		}
	default:
		return ErrInput
	}
	return nil
}

type Action struct {
	SchemaVersion string    `json:"schema_version"`
	ConnectorID   string    `json:"connector_id"`
	ConfigSHA256  string    `json:"config_sha256"`
	DeviceID      string    `json:"device_id"`
	LeaseID       string    `json:"lease_id"`
	OwnerSHA256   string    `json:"owner_sha256"`
	TargetIP      string    `json:"target_ip"`
	RequestedAt   time.Time `json:"requested_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	Reason        string    `json:"reason"`
}

func (v Action) Validate() error {
	if v.SchemaVersion != ActionSchema || !contract.ValidID(v.ConnectorID) || !contract.ValidID(v.DeviceID) || !contract.ValidID(v.LeaseID) || !validHash(v.ConfigSHA256) || !validHash(v.OwnerSHA256) || !ValidTarget(v.TargetIP) || !validText(v.Reason, 500) || v.RequestedAt.IsZero() || v.RequestedAt.Location() != time.UTC || v.ExpiresAt.Location() != time.UTC {
		return ErrInput
	}
	d := v.ExpiresAt.Sub(v.RequestedAt)
	if d < 30*time.Second || d > MaxTTLSeconds*time.Second {
		return ErrInput
	}
	return nil
}
func ReadAction(raw []byte) (Action, error) {
	var v Action
	fields := []string{"schema_version", "connector_id", "config_sha256", "device_id", "lease_id", "owner_sha256", "target_ip", "requested_at", "expires_at", "reason"}
	if contract.JSONFields(string(raw), fields, 8192) != nil || json.Unmarshal(raw, &v) != nil || v.Validate() != nil {
		return v, ErrInput
	}
	return v, nil
}

type Device struct {
	SchemaVersion     string    `json:"schema_version"`
	DeviceID          string    `json:"device_id"`
	Version           string    `json:"version"`
	NativeTTL         bool      `json:"native_ttl"`
	SeparateLeases    bool      `json:"separate_leases"`
	ConditionalRevoke bool      `json:"conditional_revoke"`
	MaxTTLSeconds     int       `json:"max_ttl_seconds"`
	ObservedAt        time.Time `json:"observed_at"`
}

func fresh(value, now time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && !value.After(now.Add(30*time.Second)) && !value.Before(now.Add(-30*time.Second))
}
func (v Device) Validate(id, version string, now time.Time) error {
	if v.SchemaVersion != DeviceSchema || v.DeviceID != id || v.Version != version || !v.NativeTTL || !v.SeparateLeases || !v.ConditionalRevoke || v.MaxTTLSeconds < 30 || v.MaxTTLSeconds > MaxTTLSeconds || !fresh(v.ObservedAt, now) {
		return ErrUnavailable
	}
	return nil
}

type Lease struct {
	SchemaVersion string    `json:"schema_version"`
	DeviceID      string    `json:"device_id"`
	LeaseID       string    `json:"lease_id"`
	OwnerSHA256   string    `json:"owner_sha256"`
	TargetIP      string    `json:"target_ip"`
	ExpiresAt     time.Time `json:"expires_at"`
	State         string    `json:"state"`
	ObservedAt    time.Time `json:"observed_at"`
}

func (v Lease) Validate(a Action, now time.Time) error {
	if a.Validate() != nil || v.SchemaVersion != LeaseSchema || v.DeviceID != a.DeviceID || v.LeaseID != a.LeaseID || v.OwnerSHA256 != a.OwnerSHA256 || v.TargetIP != a.TargetIP || !v.ExpiresAt.Equal(a.ExpiresAt) || !fresh(v.ObservedAt, now) {
		return ErrUnknown
	}
	switch v.State {
	case "active":
		if !v.ExpiresAt.After(v.ObservedAt) || !v.ExpiresAt.After(now) {
			return ErrUnknown
		}
	case "expired":
		if v.ExpiresAt.After(v.ObservedAt) || v.ExpiresAt.After(now) {
			return ErrUnknown
		}
	case "revoked":
	default:
		return ErrUnknown
	}
	return nil
}

type Result struct {
	SchemaVersion string `json:"schema_version"`
	ConnectorID   string `json:"connector_id"`
	ConfigSHA256  string `json:"config_sha256"`
	Verified      bool   `json:"verified"`
	Observation   Lease  `json:"observation"`
	Effect        string `json:"traffic_effect"`
}

func (v Result) Validate(a Action, kind string, now time.Time) error {
	if v.SchemaVersion != "response.result.v1" || !v.Verified || v.ConnectorID != a.ConnectorID || v.ConfigSHA256 != a.ConfigSHA256 || v.Effect != "not_observed" || v.Observation.Validate(a, now) != nil {
		return ErrUnknown
	}
	if kind == "response.block" && v.Observation.State != "active" || kind == "response.revoke" && v.Observation.State == "active" || kind != "response.block" && kind != "response.read" && kind != "response.revoke" {
		return ErrUnknown
	}
	return nil
}

type Health struct {
	ConnectorID   string    `json:"connector_id"`
	DeviceID      string    `json:"device_id"`
	Version       string    `json:"version"`
	ConfigSHA256  string    `json:"config_sha256"`
	Status        string    `json:"status"`
	ObservedAt    time.Time `json:"observed_at"`
	MaxTTLSeconds int       `json:"max_ttl_seconds"`
}

func ReadResult(raw []byte, a Action, kind string, now time.Time) (Result, error) {
	var v Result
	fields := []string{"schema_version", "connector_id", "config_sha256", "verified", "observation", "traffic_effect", "device_id", "lease_id", "owner_sha256", "target_ip", "expires_at", "state", "observed_at"}
	if contract.JSONFields(string(raw), fields, 16384) != nil || json.Unmarshal(raw, &v) != nil || v.Validate(a, kind, now) != nil {
		return v, ErrUnknown
	}
	return v, nil
}

func (v Health) Ready(now time.Time) bool {
	return v.Status == "ready" && contract.ValidID(v.ConnectorID) && contract.ValidID(v.DeviceID) && validText(v.Version, 64) && validHash(v.ConfigSHA256) && v.MaxTTLSeconds >= 30 && v.MaxTTLSeconds <= MaxTTLSeconds && !v.ObservedAt.IsZero() && v.ObservedAt.Location() == time.UTC && !v.ObservedAt.Before(now.Add(-35*time.Second)) && !v.ObservedAt.After(now.Add(30*time.Second))
}
