// Package watchlist 管理有期限和探针注册范围的保护、观察名单，不删除告警或授予设备动作权限。
package watchlist

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/kkx600/StarBeacon/internal/contract"
	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

const (
	Schema          = "watchlist.v1"
	PreviewSchema   = "watchlist-preview.v1"
	ResponseSchema  = "watchlist-response-check.v1"
	MaxLists        = 256
	MaxRevision     = 1000000
	MaxDailyChanges = 2048
	MaxValues       = 64
	MaxSensors      = 32
	MaxTargets      = 128
)

var (
	ErrInput      = errors.New("名单、期限或范围无效")
	ErrQuota      = errors.New("名单或变更数量达到上限")
	ErrPermission = errors.New("名单权限已变化")
	ErrSource     = errors.New("名单修订或来源不完整")
	ErrLimit      = errors.New("名单预览或读取数量超过上限")
	ErrProtected  = errors.New("目标属于当前有效保护名单")
)

func Text(v string, max int, required bool) bool {
	return utf8.ValidString(v) && v == strings.TrimSpace(v) && (!required || v != "") && len([]rune(v)) <= max && strings.IndexFunc(v, unicode.IsControl) == -1
}

func Digest(v any) string {
	raw, _ := json.Marshal(v)
	d := sha256.Sum256(raw)
	return hex.EncodeToString(d[:])
}

func validIP(v string) bool {
	a, e := netip.ParseAddr(v)
	return e == nil && a.Zone() == "" && !a.Is4In6() && a.String() == v && !a.IsUnspecified() && !a.IsMulticast()
}

func validDomain(v string) bool {
	if !Text(v, 253, true) || strings.ContainsAny(v, "/*:@\\?#[]") || strings.HasSuffix(v, ".") {
		return false
	}
	canonical, e := idna.Lookup.ToASCII(v)
	if e != nil || canonical != v || strings.ToLower(v) != v || !strings.Contains(v, ".") {
		return false
	}
	if _, e = netip.ParseAddr(v); e == nil {
		return false
	}
	for _, part := range strings.Split(v, ".") {
		if len(part) < 1 || len(part) > 63 || part[0] == '-' || part[len(part)-1] == '-' {
			return false
		}
		for _, r := range part {
			if r != '-' && (r < 'a' || r > 'z') && (r < '0' || r > '9') {
				return false
			}
		}
	}
	_, e = publicsuffix.EffectiveTLDPlusOne(v)
	return e == nil
}

func ValidValue(kind, value string) bool {
	switch kind {
	case "ip":
		return validIP(value)
	case "cidr":
		p, e := netip.ParsePrefix(value)
		return e == nil && p.Addr().Zone() == "" && !p.Addr().Is4In6() && p.Masked().String() == value
	case "domain":
		return validDomain(value)
	default:
		return false
	}
}

type Sensor struct {
	SensorID       string `json:"sensor_id"`
	RegistrationID string `json:"registration_id"`
}

func (s Sensor) Valid() bool {
	return contract.ValidID(s.SensorID) && contract.ValidID(s.RegistrationID)
}

type Definition struct {
	SchemaVersion string    `json:"schema_version"`
	Kind          string    `json:"kind"`
	MatchType     string    `json:"match_type"`
	Values        []string  `json:"values"`
	Sensors       []Sensor  `json:"sensors"`
	ValidFrom     time.Time `json:"valid_from"`
	ValidUntil    time.Time `json:"valid_until"`
}

func (d Definition) Validate() error {
	_, fromOffset := d.ValidFrom.Zone()
	_, untilOffset := d.ValidUntil.Zone()
	if d.SchemaVersion != Schema || !slices.Contains([]string{"protect", "observe"}, d.Kind) || !slices.Contains([]string{"ip", "cidr", "domain"}, d.MatchType) || len(d.Values) < 1 || len(d.Values) > MaxValues || len(d.Sensors) < 1 || len(d.Sensors) > MaxSensors || d.ValidFrom.Before(time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)) || !d.ValidUntil.After(d.ValidFrom) || d.ValidUntil.Sub(d.ValidFrom) > 3650*24*time.Hour || d.ValidFrom.Nanosecond() != 0 || d.ValidUntil.Nanosecond() != 0 || fromOffset != 0 || untilOffset != 0 {
		return ErrInput
	}
	seen := map[string]bool{}
	for _, v := range d.Values {
		if !ValidValue(d.MatchType, v) || seen[v] {
			return ErrInput
		}
		seen[v] = true
	}
	seen = map[string]bool{}
	for _, s := range d.Sensors {
		if !s.Valid() || seen[s.SensorID] {
			return ErrInput
		}
		seen[s.SensorID] = true
	}
	return nil
}

// 过宽前缀允许作为停用草稿保存，但没有审批系统时不得启用。
func (d Definition) Broad() bool {
	if d.MatchType != "cidr" {
		return false
	}
	for _, v := range d.Values {
		p, e := netip.ParsePrefix(v)
		if e != nil || p.Addr().Is4() && p.Bits() < 24 || p.Addr().Is6() && p.Bits() < 120 {
			return true
		}
	}
	return false
}

func (d Definition) Effective(active bool, now time.Time) bool {
	return active && !now.Before(d.ValidFrom) && now.Before(d.ValidUntil)
}
func (d Definition) Admissible(now time.Time) bool {
	return d.Validate() == nil && !d.Broad() && now.Before(d.ValidUntil)
}

type Change struct {
	ID               string     `json:"id"`
	ExpectedRevision int64      `json:"expected_revision"`
	Name             string     `json:"name"`
	Description      string     `json:"description"`
	Active           *bool      `json:"active"`
	Definition       Definition `json:"definition"`
}

func (c Change) Validate() error {
	if !contract.ValidID(c.ID) || c.ExpectedRevision < 0 || c.ExpectedRevision >= MaxRevision || !Text(c.Name, 128, true) || !Text(c.Description, 1000, true) || c.Active == nil {
		return ErrInput
	}
	return c.Definition.Validate()
}

type Record struct {
	TenantID         string     `json:"tenant_id"`
	ID               string     `json:"id"`
	Revision         int64      `json:"revision"`
	Name             string     `json:"name"`
	Description      string     `json:"description"`
	Active           bool       `json:"active"`
	Definition       Definition `json:"definition"`
	DefinitionSHA256 string     `json:"definition_sha256"`
	CreatedBy        string     `json:"created_by"`
	CreatedAt        time.Time  `json:"created_at"`
	ExpiresAt        time.Time  `json:"expires_at"`
}

func (r Record) Validate() error {
	if !contract.ValidID(r.TenantID) || !contract.ValidID(r.ID) || !contract.ValidID(r.CreatedBy) || r.Revision < 1 || r.Revision > MaxRevision || !Text(r.Name, 128, true) || !Text(r.Description, 1000, true) || r.DefinitionSHA256 != Digest(r.Definition) || r.CreatedAt.IsZero() || !r.ExpiresAt.After(r.CreatedAt) || r.Active && r.Definition.Broad() {
		return ErrSource
	}
	if r.Definition.Validate() != nil {
		return ErrSource
	}
	return nil
}

type Query struct {
	Cursor  string `json:"cursor"`
	Keyword string `json:"keyword"`
	Active  string `json:"active"`
	Kind    string `json:"kind"`
	Limit   int    `json:"limit"`
}
type cursor struct {
	After string `json:"after"`
	Scope string `json:"scope"`
}

func (q Query) Validate() error {
	if q.Limit < 1 || q.Limit > 100 || !Text(q.Keyword, 128, false) || !slices.Contains([]string{"", "true", "false"}, q.Active) || !slices.Contains([]string{"", "protect", "observe"}, q.Kind) || q.Cursor != "" && (!Text(q.Cursor, 2048, true) || len(q.Cursor) > 2048) {
		return ErrInput
	}
	return nil
}
func (q Query) scope(tenant string) string {
	q.Cursor = ""
	return Digest(struct {
		Tenant string `json:"tenant"`
		Query  Query  `json:"query"`
	}{tenant, q})
}
func (q Query) Position(tenant string) (string, error) {
	if q.Validate() != nil || !contract.ValidID(tenant) {
		return "", ErrInput
	}
	if q.Cursor == "" {
		return "", nil
	}
	b := base64.RawURLEncoding.Strict()
	raw, e := b.DecodeString(q.Cursor)
	var c cursor
	if e != nil || b.EncodeToString(raw) != q.Cursor || contract.JSONFields(string(raw), []string{"after", "scope"}, 1024) != nil || json.Unmarshal(raw, &c) != nil || !contract.ValidID(c.After) || c.Scope != q.scope(tenant) {
		return "", ErrInput
	}
	return c.After, nil
}
func (q Query) Next(tenant, after string) string {
	raw, _ := json.Marshal(cursor{after, q.scope(tenant)})
	return base64.RawURLEncoding.EncodeToString(raw)
}

type Page struct {
	Items      []Record `json:"items"`
	NextCursor string   `json:"next_cursor"`
}

type Target struct {
	SensorID       string `json:"sensor_id"`
	RegistrationID string `json:"registration_id"`
	Type           string `json:"type"`
	Value          string `json:"value"`
}

func (t Target) Valid() bool {
	return (Sensor{t.SensorID, t.RegistrationID}).Valid() && slices.Contains([]string{"ip", "domain"}, t.Type) && ValidValue(t.Type, t.Value)
}
func (d Definition) Matches(t Target) bool {
	if d.Validate() != nil || !t.Valid() || !slices.Contains(d.Sensors, Sensor{t.SensorID, t.RegistrationID}) {
		return false
	}
	if d.MatchType == "domain" {
		return t.Type == "domain" && slices.Contains(d.Values, t.Value)
	}
	if t.Type != "ip" {
		return false
	}
	if d.MatchType == "ip" {
		return slices.Contains(d.Values, t.Value)
	}
	a, _ := netip.ParseAddr(t.Value)
	for _, v := range d.Values {
		p, _ := netip.ParsePrefix(v)
		if p.Contains(a) {
			return true
		}
	}
	return false
}

type PreviewRequest struct {
	Definition Definition `json:"definition"`
	Active     *bool      `json:"active"`
	Targets    []Target   `json:"targets"`
}

func (p PreviewRequest) Validate() error {
	if p.Active == nil || p.Targets == nil || len(p.Targets) > MaxTargets || p.Definition.Validate() != nil {
		return ErrInput
	}
	for _, t := range p.Targets {
		if !t.Valid() {
			return ErrInput
		}
	}
	return nil
}

type Match struct {
	Index   int  `json:"index"`
	Matched bool `json:"matched"`
}
type Preview struct {
	SchemaVersion       string    `json:"schema_version"`
	DefinitionSHA256    string    `json:"definition_sha256"`
	Active              bool      `json:"active"`
	Admissible          bool      `json:"admissible"`
	Effective           bool      `json:"effective"`
	CheckedAt           time.Time `json:"checked_at"`
	ScopeSensorCount    int       `json:"scope_sensor_count"`
	ValueCount          int       `json:"value_count"`
	Reasons             []string  `json:"reasons"`
	Matches             []Match   `json:"matches"`
	ExecutionAuthorized bool      `json:"execution_authorized"`
	FactDeletionAllowed bool      `json:"fact_deletion_allowed"`
}

func (p PreviewRequest) Evaluate(now time.Time) (Preview, error) {
	if p.Validate() != nil || now.IsZero() {
		return Preview{}, ErrInput
	}
	d := p.Definition
	out := Preview{SchemaVersion: PreviewSchema, DefinitionSHA256: Digest(d), Active: *p.Active, Admissible: d.Admissible(now), Effective: d.Effective(*p.Active, now), CheckedAt: now.UTC(), ScopeSensorCount: len(d.Sensors), ValueCount: len(d.Values), Reasons: []string{}, Matches: []Match{}}
	if d.Broad() {
		out.Reasons = append(out.Reasons, "scope_too_broad")
		out.Effective = false
	}
	if !now.Before(d.ValidUntil) {
		out.Reasons = append(out.Reasons, "expired")
	} else if now.Before(d.ValidFrom) {
		out.Reasons = append(out.Reasons, "not_yet_valid")
	}
	if !*p.Active {
		out.Reasons = append(out.Reasons, "inactive")
	}
	for i, t := range p.Targets {
		out.Matches = append(out.Matches, Match{i, d.Matches(t)})
	}
	return out, nil
}

type Reference struct {
	ID               string `json:"id"`
	Revision         int64  `json:"revision"`
	DefinitionSHA256 string `json:"definition_sha256"`
}
type ResponseCheck struct {
	SchemaVersion string      `json:"schema_version"`
	CheckedAt     time.Time   `json:"checked_at"`
	StateSHA256   string      `json:"state_sha256"`
	Matches       []Reference `json:"matches"`
}
