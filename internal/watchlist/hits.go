package watchlist

import (
	"encoding/base64"
	"encoding/json"
	"slices"
	"strings"
	"time"

	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/traffic"
	"golang.org/x/net/idna"
)

const (
	HitSchema = "watchlist-hit.v1"
	// MaxDailyHits 限定每份名单每个 UTC 处理日逐条登记的命中告警数，超过后只记录发生截断的时刻。
	MaxDailyHits = 10000
	// MaxBatchHits 限定单个告警批次新增的命中记录，避免重叠名单在一次事务中放大写入。
	MaxBatchHits   = 2000
	MaxHitMatches  = 16
	MaxHitWindow   = 31 * 24 * time.Hour
	maxDNSNames    = 8
	maxRuleNameLen = 512
)

const (
	FieldSourceIP      = "source.ip"
	FieldDestinationIP = "destination.ip"
	FieldHTTPHost      = "http.hostname"
	FieldTLSSNI        = "tls.sni"
	FieldDNSName       = "dns.rrname"
)

var hitFields = []string{FieldSourceIP, FieldDestinationIP, FieldHTTPHost, FieldTLSSNI, FieldDNSName}

// Observed 是告警中实际出现、已规范化的匹配值；域名不经 DNS 解析扩展。
type Observed struct {
	Field string `json:"field"`
	Value string `json:"value"`
}

func fieldType(field string) string {
	if field == FieldSourceIP || field == FieldDestinationIP {
		return "ip"
	}
	return "domain"
}

func (o Observed) Valid() bool {
	return slices.Contains(hitFields, o.Field) && ValidValue(fieldType(o.Field), o.Value)
}

// CanonicalHost 只做大小写、末尾点和 IDNA 规范化；IP 字面量、通配符和公共后缀不作为域名。
func CanonicalHost(v string) (string, bool) {
	v = strings.TrimSuffix(strings.ToLower(v), ".")
	if v == "" || len(v) > 253 {
		return "", false
	}
	canonical, err := idna.Lookup.ToASCII(v)
	if err != nil || !validDomain(canonical) {
		return "", false
	}
	return canonical, true
}

// AlertTargets 按固定字段顺序提取告警中的候选值；只有存在域名名单时才解析原始 EVE 的 TLS 与 DNS 字段。
func AlertTargets(a model.Alert, domains bool) []Observed {
	out := []Observed{}
	add := func(o Observed) {
		if len(out) < MaxHitMatches && o.Valid() && !slices.Contains(out, o) {
			out = append(out, o)
		}
	}
	add(Observed{FieldSourceIP, a.Source.IP})
	add(Observed{FieldDestinationIP, a.Destination.IP})
	if !domains {
		return out
	}
	if host, ok := CanonicalHost(a.HTTP.Hostname); ok {
		add(Observed{FieldHTTPHost, host})
	}
	details := traffic.Parse(a.Event.Original)
	if details.TLS != nil {
		if host, ok := CanonicalHost(details.TLS.SNI); ok {
			add(Observed{FieldTLSSNI, host})
		}
	}
	if details.DNS != nil {
		for _, q := range details.DNS.Queries[:min(len(details.DNS.Queries), maxDNSNames)] {
			if host, ok := CanonicalHost(q.Name); ok {
				add(Observed{FieldDNSName, host})
			}
		}
	}
	return out
}

// AlertMatches 只关联观察名单当前修订：修订保存后由平台接收、观测时间处于业务有效期且探针注册在范围内。
// 修订保存前接收的告警不追溯登记，历史数据只能通过影响预览核对。
func (r Record) AlertMatches(a model.Alert, targets []Observed) []Observed {
	d := r.Definition
	if d.Kind != "observe" || !d.Effective(r.Active, a.ObservedAt) || a.ReceivedAt.Before(r.CreatedAt) || !slices.Contains(d.Sensors, Sensor{a.SensorID, a.RegistrationID}) {
		return nil
	}
	var out []Observed
	for _, o := range targets {
		if d.Matches(Target{SensorID: a.SensorID, RegistrationID: a.RegistrationID, Type: fieldType(o.Field), Value: o.Value}) {
			out = append(out, o)
		}
	}
	return out
}

// Hit 是观察名单与单条告警的不可变关联，不代表攻击成立、误报结论或任何设备授权。
type Hit struct {
	SchemaVersion    string     `json:"schema_version"`
	ID               string     `json:"id"`
	ListID           string     `json:"list_id"`
	ListRevision     int64      `json:"list_revision"`
	DefinitionSHA256 string     `json:"definition_sha256"`
	EventID          string     `json:"event_id"`
	RawSHA256        string     `json:"raw_sha256"`
	SensorID         string     `json:"sensor_id"`
	RegistrationID   string     `json:"registration_id"`
	Matches          []Observed `json:"matches"`
	Severity         string     `json:"severity"`
	RuleID           string     `json:"rule_id"`
	RuleName         string     `json:"rule_name"`
	ObservedAt       time.Time  `json:"observed_at"`
	ReceivedAt       time.Time  `json:"received_at"`
	CreatedAt        time.Time  `json:"created_at"`
	ExpiresAt        time.Time  `json:"expires_at"`
}

func HitID(tenant, list string, revision int64, event, raw string) string {
	return "whit_" + Digest([]any{tenant, list, revision, event, raw})[:56]
}

func ValidDigest(v string) bool {
	if len(v) != 64 {
		return false
	}
	for _, r := range v {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

func validSeverity(v string) bool {
	return slices.Contains([]string{"critical", "high", "medium", "low", "unknown"}, v)
}

// NewHit 冻结告警摘要；规则名称不符合展示约束时记为空，不截断成另一条规则名。
func NewHit(tenant string, r Record, a model.Alert, matches []Observed) Hit {
	name := a.Rule.Name
	if !Text(name, maxRuleNameLen, false) {
		name = ""
	}
	rule := a.Rule.ID
	if !Text(rule, 64, false) {
		rule = ""
	}
	return Hit{SchemaVersion: HitSchema, ID: HitID(tenant, r.ID, r.Revision, a.EventID, a.RawSHA256), ListID: r.ID, ListRevision: r.Revision, DefinitionSHA256: r.DefinitionSHA256, EventID: a.EventID, RawSHA256: a.RawSHA256, SensorID: a.SensorID, RegistrationID: a.RegistrationID, Matches: matches, Severity: a.Severity, RuleID: rule, RuleName: name, ObservedAt: a.ObservedAt.UTC(), ReceivedAt: a.ReceivedAt.UTC()}
}

func (h Hit) Validate(tenant string) error {
	if h.SchemaVersion != HitSchema || !contract.ValidID(tenant) || !contract.ValidID(h.ListID) || h.ListRevision < 1 || h.ListRevision > MaxRevision || !ValidDigest(h.DefinitionSHA256) || !contract.ValidID(h.EventID) || !ValidDigest(h.RawSHA256) || h.ID != HitID(tenant, h.ListID, h.ListRevision, h.EventID, h.RawSHA256) || !(Sensor{h.SensorID, h.RegistrationID}).Valid() || !validSeverity(h.Severity) || !Text(h.RuleID, 64, false) || !Text(h.RuleName, maxRuleNameLen, false) || h.ObservedAt.IsZero() || h.ReceivedAt.IsZero() || len(h.Matches) < 1 || len(h.Matches) > MaxHitMatches {
		return ErrSource
	}
	for i, o := range h.Matches {
		if !o.Valid() || slices.Contains(h.Matches[:i], o) {
			return ErrSource
		}
	}
	if !h.CreatedAt.IsZero() && !h.ExpiresAt.After(h.CreatedAt) {
		return ErrSource
	}
	return nil
}

// HitQuery 按告警观测时间倒序读取单份名单的命中；游标绑定租户、名单、窗口和页大小。
type HitQuery struct {
	ListID string    `json:"list_id"`
	Start  time.Time `json:"start"`
	End    time.Time `json:"end"`
	Cursor string    `json:"cursor"`
	Limit  int       `json:"limit"`
}

type hitCursor struct {
	Time  time.Time `json:"time"`
	ID    string    `json:"id"`
	Scope string    `json:"scope"`
}

func (q HitQuery) scope(tenant string) string {
	q.Cursor = ""
	q.Start, q.End = q.Start.UTC(), q.End.UTC()
	return Digest(struct {
		Tenant string   `json:"tenant"`
		Query  HitQuery `json:"query"`
	}{tenant, q})
}

func (q HitQuery) Validate(now time.Time) error {
	if !contract.ValidID(q.ListID) || q.Start.IsZero() || q.End.IsZero() || !q.Start.Before(q.End) || q.End.Sub(q.Start) > MaxHitWindow || q.End.After(now.Add(30*time.Second)) || q.Limit < 1 || q.Limit > 100 || len(q.Cursor) > 512 {
		return ErrInput
	}
	return nil
}

// Position 返回续读位置；首次读取从窗口终点开始，不含终点。
func (q HitQuery) Position(tenant string) (time.Time, string, error) {
	if !contract.ValidID(tenant) {
		return time.Time{}, "", ErrInput
	}
	if q.Cursor == "" {
		return q.End.UTC(), "", nil
	}
	b := base64.RawURLEncoding.Strict()
	raw, err := b.DecodeString(q.Cursor)
	var c hitCursor
	if err != nil || b.EncodeToString(raw) != q.Cursor || contract.JSONFields(string(raw), []string{"time", "id", "scope"}, 384) != nil || json.Unmarshal(raw, &c) != nil || !contract.ValidID(c.ID) || c.Scope != q.scope(tenant) || c.Time.Before(q.Start) || !c.Time.Before(q.End) {
		return time.Time{}, "", ErrInput
	}
	return c.Time.UTC(), c.ID, nil
}

func (q HitQuery) Next(tenant string, last Hit) string {
	raw, _ := json.Marshal(hitCursor{Time: last.ObservedAt.UTC(), ID: last.ID, Scope: q.scope(tenant)})
	return base64.RawURLEncoding.EncodeToString(raw)
}

// HitDay 只列出存在未逐条登记命中的处理日；截断后的命中次数未统计。
type HitDay struct {
	Day      string     `json:"day"`
	Recorded int        `json:"recorded"`
	CappedAt *time.Time `json:"capped_at"`
}

type HitPage struct {
	Items      []Hit     `json:"items"`
	NextCursor string    `json:"next_cursor"`
	ObservedAt time.Time `json:"observed_at"`
	CappedDays []HitDay  `json:"capped_days"`
}

type AlertHits struct {
	Items      []Hit     `json:"items"`
	ObservedAt time.Time `json:"observed_at"`
}
