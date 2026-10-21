package response

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/netip"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/outbound"
	"github.com/kkx600/StarBeacon/internal/privatefile"
)

type Configuration struct {
	ID               string   `json:"id"`
	DeviceID         string   `json:"device_id"`
	DeviceVersion    string   `json:"device_version"`
	Origin           string   `json:"origin"`
	CAFile           string   `json:"ca_file"`
	TokenFile        string   `json:"token_file"`
	AllowedTargets   []string `json:"allowed_targets"`
	ProtectedTargets []string `json:"protected_targets"`
	MaxTTLSeconds    int      `json:"max_ttl_seconds"`
}

func (v Configuration) SHA256() string { return digest(v) }
func (v Configuration) Validate() error {
	u, err := url.Parse(v.Origin)
	if err != nil || !contract.ValidID(v.ID) || !contract.ValidID(v.DeviceID) || !validText(v.DeviceVersion, 64) || u.Scheme != "https" || u.User != nil || u.Opaque != "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Hostname() == "" || strings.ContainsAny(v.Origin, "\r\n\x00") {
		return ErrInput
	}
	// 固定管理 IP 避免配置被远程输入、DNS 或重定向替换；证书仍须包含该 IP。
	ip, err := netip.ParseAddr(u.Hostname())
	if err != nil || ip.String() != u.Hostname() || ip.Is4In6() || ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return ErrInput
	}
	if !filepath.IsAbs(v.TokenFile) || !filepath.IsAbs(v.CAFile) || v.MaxTTLSeconds < 30 || v.MaxTTLSeconds > MaxTTLSeconds || len(v.AllowedTargets) == 0 || len(v.AllowedTargets) > 32 || len(v.ProtectedTargets) > 32 {
		return ErrInput
	}
	for _, group := range [][]string{v.AllowedTargets, v.ProtectedTargets} {
		seen := map[string]bool{}
		for _, raw := range group {
			p, err := netip.ParsePrefix(raw)
			if err != nil || p != p.Masked() || p.Addr().Is4In6() || p.String() != raw || seen[raw] {
				return ErrInput
			}
			seen[raw] = true
		}
	}
	return nil
}
func (v Configuration) Allows(target string, seconds int) bool {
	if v.Validate() != nil || !ValidTarget(target) || seconds < 30 || seconds > v.MaxTTLSeconds {
		return false
	}
	ip, _ := netip.ParseAddr(target)
	u, _ := url.Parse(v.Origin)
	if target == u.Hostname() {
		return false
	}
	for _, raw := range v.ProtectedTargets {
		if netip.MustParsePrefix(raw).Contains(ip) {
			return false
		}
	}
	for _, raw := range v.AllowedTargets {
		if netip.MustParsePrefix(raw).Contains(ip) {
			return true
		}
	}
	return false
}

// ReadPrivateFile 不跟随链接，不接受 FIFO；打开前后核对身份和所有者权限。
func ReadPrivateFile(path string, limit int64) ([]byte, error) {
	raw, err := privatefile.Read(path, limit)
	if err != nil {
		return nil, ErrUnavailable
	}
	return raw, nil
}

type File struct {
	SchemaVersion string          `json:"schema_version"`
	RetentionDays int             `json:"retention_days"`
	Connectors    []Configuration `json:"connectors"`
}

func LoadFile(path string) (File, error) {
	var result File
	raw, err := ReadPrivateFile(path, 128*1024)
	fields := []string{"schema_version", "retention_days", "connectors", "id", "device_id", "device_version", "origin", "ca_file", "token_file", "allowed_targets", "protected_targets", "max_ttl_seconds"}
	if err != nil || contract.JSONFields(string(raw), fields, 128*1024) != nil || json.Unmarshal(raw, &result) != nil || result.SchemaVersion != "response.connectors.v1" || len(result.Connectors) < 1 || len(result.Connectors) > 8 {
		return result, ErrInput
	}
	if result.RetentionDays == 0 {
		result.RetentionDays = 180
	}
	if result.RetentionDays < 1 || result.RetentionDays > 3650 {
		return result, ErrInput
	}
	seen := map[string]bool{}
	devices := map[string]bool{}
	for _, v := range result.Connectors {
		if v.Validate() != nil || seen[v.ID] || devices[v.DeviceID] {
			return result, ErrInput
		}
		seen[v.ID], devices[v.DeviceID] = true, true
	}
	return result, nil
}

type Client struct {
	Config Configuration
	http   *http.Client
}

func NewClient(c Configuration) (*Client, error) {
	if c.Validate() != nil {
		return nil, ErrInput
	}
	roots, err := outbound.LoadRoots(c.CAFile)
	if err != nil || roots == nil {
		return nil, ErrUnavailable
	}
	u, _ := url.Parse(c.Origin)
	ip, _ := netip.ParseAddr(u.Hostname())
	policy := outbound.Policy{Roots: roots, PrivateNetworks: []netip.Prefix{netip.PrefixFrom(ip, ip.BitLen())}}
	if _, err := policy.URL(c.Origin); err != nil || !policy.Allowed(ip) {
		return nil, ErrInput
	}
	client := policy.HTTPClient()
	// 每次写只建立一条连接，不让连接复用触发隐式重发；未知结果通过 GET 核对。
	client.Transport.(*http.Transport).DisableKeepAlives = true
	client.Timeout = 8 * time.Second
	return &Client{Config: c, http: client}, nil
}
func (c *Client) Close() { c.http.CloseIdleConnections() }
func (c *Client) request(ctx context.Context, method, path string, body any, owner string) ([]byte, int, error) {
	token, err := ReadPrivateFile(c.Config.TokenFile, 4096)
	value := strings.TrimSuffix(strings.TrimSuffix(string(token), "\n"), "\r")
	if err != nil || len(value) < 16 || len(value) > 4096 || strings.ContainsAny(value, "\r\n\x00 \t") {
		return nil, 0, ErrUnavailable
	}
	var input []byte
	if body != nil {
		input, err = json.Marshal(body)
		if err != nil {
			return nil, 0, ErrInput
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Config.Origin+path, bytes.NewReader(input))
	if err != nil {
		return nil, 0, ErrInput
	}
	req.Header.Set("Authorization", "Bearer "+value)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if owner != "" {
		req.Header.Set("If-Match", `"`+owner+`"`)
	}
	res, err := c.http.Do(req)
	if err != nil {
		return nil, 0, ErrUnknown
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 16385))
	contentType, _, typeErr := mime.ParseMediaType(res.Header.Get("Content-Type"))
	if err != nil || len(raw) > 16384 || typeErr != nil || contentType != "application/json" {
		return nil, res.StatusCode, ErrUnknown
	}
	return raw, res.StatusCode, nil
}
func (c *Client) Describe(ctx context.Context) (Device, error) {
	var value Device
	raw, status, err := c.request(ctx, http.MethodGet, "/starbeacon/v1/device", nil, "")
	fields := []string{"schema_version", "device_id", "version", "native_ttl", "separate_leases", "conditional_revoke", "max_ttl_seconds", "observed_at"}
	if err != nil || status != 200 || contract.JSONFields(string(raw), fields, 16384) != nil || json.Unmarshal(raw, &value) != nil || value.Validate(c.Config.DeviceID, c.Config.DeviceVersion, time.Now().UTC()) != nil {
		return value, ErrUnavailable
	}
	return value, nil
}
func (c *Client) read(ctx context.Context, a Action) (Lease, bool, error) {
	var value Lease
	raw, status, err := c.request(ctx, http.MethodGet, "/starbeacon/v1/leases/"+a.LeaseID, nil, "")
	if err != nil {
		return value, false, ErrUnknown
	}
	if status == 404 {
		var missing struct {
			SchemaVersion string `json:"schema_version"`
			Code          string `json:"code"`
		}
		if contract.JSONFields(string(raw), []string{"schema_version", "code"}, 16384) == nil && json.Unmarshal(raw, &missing) == nil && missing.SchemaVersion == "response.error.v1" && missing.Code == "lease_not_found" {
			return value, true, nil
		}
	}
	fields := []string{"schema_version", "device_id", "lease_id", "owner_sha256", "target_ip", "expires_at", "state", "observed_at"}
	if status != 200 || contract.JSONFields(string(raw), fields, 16384) != nil || json.Unmarshal(raw, &value) != nil || value.Validate(a, time.Now().UTC()) != nil {
		return value, false, ErrUnknown
	}
	return value, false, nil
}
func (c *Client) Execute(ctx context.Context, kind string, a Action) (Result, error) {
	var result Result
	if a.Validate() != nil || a.ConnectorID != c.Config.ID || a.ConfigSHA256 != c.Config.SHA256() || a.DeviceID != c.Config.DeviceID || kind != "response.block" && kind != "response.read" && kind != "response.revoke" {
		return result, ErrInput
	}
	device, err := c.Describe(ctx)
	if err != nil {
		return result, err
	}
	lease, absent, err := c.read(ctx, a)
	if err != nil {
		return result, err
	}
	if kind == "response.block" {
		seconds := int(a.ExpiresAt.Sub(a.RequestedAt) / time.Second)
		if !c.Config.Allows(a.TargetIP, seconds) || seconds > device.MaxTTLSeconds || !a.ExpiresAt.After(time.Now().UTC().Add(5*time.Second)) || a.RequestedAt.After(time.Now().UTC().Add(30*time.Second)) {
			return result, ErrInput
		}
		if !absent && lease.State != "active" {
			return result, ErrUnknown
		}
		if absent {
			_, status, putErr := c.request(ctx, http.MethodPut, "/starbeacon/v1/leases/"+a.LeaseID, a, "")
			// 受理、异步及丢失响应都只回读原资源，绝不重新提交 PUT。
			if putErr == nil && (status == 400 || status == 401 || status == 403 || status == 409 || status == 412 || status == 429) {
				return result, ErrUnavailable
			}
			lease, absent, err = c.read(ctx, a)
			if err != nil || absent || lease.State != "active" {
				return result, ErrUnknown
			}
		}
	} else if kind == "response.revoke" {
		if absent {
			return result, ErrUnknown
		}
		if lease.State == "active" {
			_, status, deleteErr := c.request(ctx, http.MethodDelete, "/starbeacon/v1/leases/"+a.LeaseID, nil, a.OwnerSHA256)
			if deleteErr == nil && (status == 400 || status == 401 || status == 403 || status == 409 || status == 412 || status == 429) {
				return result, ErrUnavailable
			}
			lease, absent, err = c.read(ctx, a)
			if err != nil || absent || lease.State == "active" {
				return result, ErrUnknown
			}
		}
	} else if absent {
		return result, ErrUnknown
	}
	result = Result{SchemaVersion: "response.result.v1", ConnectorID: a.ConnectorID, ConfigSHA256: a.ConfigSHA256, Verified: true, Observation: lease, Effect: "not_observed"}
	return result, result.Validate(a, kind, time.Now().UTC())
}
func Code(err error) string {
	switch {
	case errors.Is(err, ErrInput):
		return "response_scope_invalid"
	case errors.Is(err, ErrUnavailable):
		return "response_device_unavailable"
	default:
		return "result_unknown"
	}
}
