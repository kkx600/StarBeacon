// Package gatewayblock 定义受控网关上的限时连接阻断。
package gatewayblock

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/kkx600/StarBeacon/internal/contract"
)

const (
	CommandKind      = "gateway.block_flow"
	Rule             = "rule"
	Review           = "review"
	DefaultPerMinute = 10
	MaxPerMinute     = 60
	MaxPolicies      = 128
	MaxRevision      = (1 << 53) - 1
	RuleFreshness    = 20 * time.Second
	ReviewFreshness  = 2 * time.Minute
	DispatchWindow   = 4 * time.Second
)

var (
	ErrInput       = errors.New("受控网关阻断参数无效")
	ErrPermission  = errors.New("账号没有受控网关阻断权限")
	ErrIneligible  = errors.New("阻断授权、采集器状态或告警观测已变化")
	ErrUnavailable = errors.New("本地网关配置或防火墙不可用")
	ErrLimit       = errors.New("受控网关阻断额度已用尽")
	ErrUnknown     = errors.New("防火墙写入结果待核对")
)

type Flow struct {
	SourceIP        netip.Addr `json:"source_ip"`
	SourcePort      uint16     `json:"source_port"`
	DestinationIP   netip.Addr `json:"destination_ip"`
	DestinationPort uint16     `json:"destination_port"`
	Transport       string     `json:"transport"`
}

func endpoint(ip netip.Addr) bool {
	return ip.IsGlobalUnicast() && !ip.Is4In6() && ip.Zone() == ""
}

func (f Flow) Valid() bool {
	return endpoint(f.SourceIP) && endpoint(f.DestinationIP) &&
		f.SourceIP.BitLen() == f.DestinationIP.BitLen() && f.SourceIP != f.DestinationIP &&
		f.SourcePort != 0 && f.DestinationPort != 0 && (f.Transport == "tcp" || f.Transport == "udp")
}

// Key 的方向归一化避免同一连接在双向观测中占用两个租约。
func (f Flow) Key() string {
	a := netip.AddrPortFrom(f.SourceIP, f.SourcePort)
	b := netip.AddrPortFrom(f.DestinationIP, f.DestinationPort)
	if a.Compare(b) > 0 {
		a, b = b, a
	}
	return f.Transport + "/" + a.String() + "/" + b.String()
}

type Scope struct {
	Sources      []netip.Prefix `json:"sources"`
	Destinations []netip.Prefix `json:"destinations"`
}

func rangesValid(prefixes []netip.Prefix) bool {
	if len(prefixes) == 0 || len(prefixes) > 16 {
		return false
	}
	seen := make(map[netip.Prefix]bool, len(prefixes))
	for _, p := range prefixes {
		if p != p.Masked() || !endpoint(p.Addr()) || p.Bits() < p.Addr().BitLen()/4 || seen[p] {
			return false
		}
		seen[p] = true
	}
	return true
}

func (s Scope) Valid() bool { return rangesValid(s.Sources) && rangesValid(s.Destinations) }

func contains(prefixes []netip.Prefix, ip netip.Addr) bool {
	for _, p := range prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func (s Scope) Allows(f Flow) bool {
	return contains(s.Sources, f.SourceIP) && contains(s.Destinations, f.DestinationIP)
}

type SettingsChange struct {
	ExpectedRevision int64 `json:"expected_revision"`
	Enabled          bool  `json:"enabled"`
	PerMinute        int   `json:"per_minute"`
}

func (s SettingsChange) Valid() bool {
	return s.ExpectedRevision >= 0 && s.ExpectedRevision < MaxRevision && s.PerMinute >= 1 && s.PerMinute <= MaxPerMinute
}

type Settings struct {
	Revision  int64      `json:"revision"`
	Enabled   bool       `json:"enabled"`
	PerMinute int        `json:"per_minute"`
	UpdatedAt *time.Time `json:"updated_at"`
}

type Definition struct {
	Name           string    `json:"name"`
	Enabled        bool      `json:"enabled"`
	Trigger        string    `json:"trigger"`
	SensorID       string    `json:"sensor_id"`
	RegistrationID string    `json:"registration_id"`
	RuleID         string    `json:"rule_id"`
	RuleRevision   string    `json:"rule_revision"`
	Scope          Scope     `json:"scope"`
	LeaseSeconds   int       `json:"lease_seconds"`
	ValidUntil     time.Time `json:"valid_until"`
}

func numbered(value string) bool {
	n, err := strconv.ParseUint(value, 10, 32)
	return err == nil && n != 0 && strconv.FormatUint(n, 10) == value
}

func (d Definition) Valid() bool {
	return d.Name != "" && len(d.Name) <= 120 && strings.TrimSpace(d.Name) == d.Name &&
		!strings.ContainsFunc(d.Name, unicode.IsControl) &&
		(d.Trigger == Rule || d.Trigger == Review) && contract.ValidID(d.SensorID) &&
		contract.ValidID(d.RegistrationID) && numbered(d.RuleID) && numbered(d.RuleRevision) &&
		d.Scope.Valid() && d.LeaseSeconds >= 5 && d.LeaseSeconds <= 60 && !d.ValidUntil.IsZero()
}

type PolicyChange struct {
	ExpectedRevision int64      `json:"expected_revision"`
	Definition       Definition `json:"definition"`
}

func (c PolicyChange) Valid(now time.Time) bool {
	return c.ExpectedRevision >= 0 && c.ExpectedRevision < MaxRevision && c.Definition.Valid() &&
		(!c.Definition.Enabled || c.Definition.ValidUntil.After(now) && !c.Definition.ValidUntil.After(now.Add(24*time.Hour)))
}

type Policy struct {
	ID         string     `json:"id"`
	Revision   int64      `json:"revision"`
	Definition Definition `json:"definition"`
	AuthorID   string     `json:"author_id"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

type PolicyPage struct {
	Items      []Policy `json:"items"`
	NextCursor string   `json:"next_cursor"`
}

type ReviewRequest struct {
	PolicyID           string `json:"policy_id"`
	PolicyRevision     int64  `json:"policy_revision"`
	AssessmentRevision int64  `json:"assessment_revision"`
	RawSHA256          string `json:"raw_sha256"`
}

func (r ReviewRequest) Valid() bool {
	return contract.ValidID(r.PolicyID) && r.PolicyRevision > 0 && r.PolicyRevision <= MaxRevision &&
		r.AssessmentRevision > 0 && r.AssessmentRevision <= MaxRevision && ValidDigest(r.RawSHA256)
}

type Request struct {
	ID                 string     `json:"id"`
	EventID            string     `json:"event_id"`
	RawSHA256          string     `json:"raw_sha256"`
	PolicyID           string     `json:"policy_id"`
	PolicyRevision     int64      `json:"policy_revision"`
	AssessmentRevision int64      `json:"assessment_revision,omitempty"`
	SensorID           string     `json:"sensor_id"`
	RegistrationID     string     `json:"registration_id"`
	Trigger            string     `json:"trigger"`
	Flow               Flow       `json:"flow"`
	State              string     `json:"state"`
	Code               string     `json:"code"`
	TaskID             string     `json:"task_id,omitempty"`
	ObservedAt         time.Time  `json:"observed_at"`
	CreatedAt          time.Time  `json:"created_at"`
	AuthorizedAt       *time.Time `json:"authorized_at,omitempty"`
	LeaseUntil         *time.Time `json:"lease_until,omitempty"`
}

type LocalConfig struct {
	Enabled bool  `json:"enabled"`
	Scope   Scope `json:"scope"`
}

func (c LocalConfig) Binding() Health {
	raw, _ := json.Marshal(c)
	hash := sha256.Sum256(raw)
	return Health{ConfigSHA256: hex.EncodeToString(hash[:])}
}

type Health struct {
	ConfigSHA256 string `json:"config_sha256"`
}

func ValidDigest(s string) bool {
	decoded, err := hex.DecodeString(s)
	return err == nil && len(decoded) == sha256.Size && hex.EncodeToString(decoded) == s
}

type Action struct {
	RequestID    string    `json:"request_id"`
	EventID      string    `json:"event_id"`
	ConfigSHA256 string    `json:"config_sha256"`
	PolicyID     string    `json:"policy_id"`
	Revision     int64     `json:"policy_revision"`
	Trigger      string    `json:"trigger"`
	Flow         Flow      `json:"flow"`
	LeaseUntil   time.Time `json:"lease_until"`
}

func ReadAction(raw []byte, issued, expires time.Time) (Action, error) {
	var a Action
	fields := []string{"request_id", "event_id", "config_sha256", "policy_id", "policy_revision", "trigger", "flow",
		"source_ip", "source_port", "destination_ip", "destination_port", "transport", "lease_until"}
	if contract.JSONFields(string(raw), fields, 4096) != nil || json.Unmarshal(raw, &a) != nil ||
		!contract.ValidID(a.RequestID) || !ValidDigest(a.EventID) || !ValidDigest(a.ConfigSHA256) || !contract.ValidID(a.PolicyID) ||
		a.Revision < 1 || a.Revision > MaxRevision || (a.Trigger != Rule && a.Trigger != Review) || !a.Flow.Valid() ||
		expires.Sub(issued) > DispatchWindow || !a.LeaseUntil.After(expires) || a.LeaseUntil.After(issued.Add(time.Minute)) {
		return Action{}, ErrInput
	}
	return a, nil
}

type Result struct {
	RequestID    string    `json:"request_id"`
	ConfigSHA256 string    `json:"config_sha256"`
	Flow         Flow      `json:"flow"`
	LeaseUntil   time.Time `json:"lease_until"`
	VerifiedAt   time.Time `json:"verified_at"`
}

func VerifyResult(raw []byte, a Action, issued, finished time.Time) error {
	var r Result
	fields := []string{"request_id", "config_sha256", "flow", "source_ip", "source_port", "destination_ip",
		"destination_port", "transport", "lease_until", "verified_at"}
	if contract.JSONFields(string(raw), fields, 4096) != nil || json.Unmarshal(raw, &r) != nil ||
		r.RequestID != a.RequestID || r.ConfigSHA256 != a.ConfigSHA256 || r.Flow != a.Flow ||
		!r.LeaseUntil.Equal(a.LeaseUntil) || r.VerifiedAt.Before(issued) || r.VerifiedAt.After(finished) || !r.VerifiedAt.Before(a.LeaseUntil) {
		return ErrUnknown
	}
	return nil
}
