// Package application 根据受限可见元数据验证产品规则，不推断加密正文或执行网络动作。
package application

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/kkx600/StarBeacon/internal/contract"
	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

const (
	Schema            = "application-rule.v1"
	ObservationSchema = "application-observation.v1"
	ResultSchema      = "application-test.v1"
	MaxRules          = 128
	MaxRevision       = 1000000
	MaxDailyChanges   = 2048
)

var (
	ErrInput      = errors.New("应用识别规则或验证材料无效")
	ErrQuota      = errors.New("应用识别规则或变更数量已达上限")
	ErrPermission = errors.New("应用识别规则维护权限已撤回")
)

var Categories = []string{"cloud_storage", "video", "communication", "office", "development", "remote_access", "business", "other"}

type Condition struct {
	Field string `json:"field"`
	Op    string `json:"op"`
	Value string `json:"value"`
}

type Definition struct {
	SchemaVersion string      `json:"schema_version"`
	ProductID     string      `json:"product_id"`
	ProductName   string      `json:"product_name"`
	CategoryID    string      `json:"category_id"`
	Protocols     []string    `json:"protocols"`
	Any           []Condition `json:"any"`
	All           []Condition `json:"all"`
	Exclude       []Condition `json:"exclude"`
}

func Text(value string, limit int, required bool) bool {
	return utf8.ValidString(value) && value == strings.TrimSpace(value) && (!required || value != "") && len([]rune(value)) <= limit && strings.IndexFunc(value, unicode.IsControl) < 0
}

// 域名按 IDNA label 规范化。公共后缀、地址、URL、通配符和用户信息不作为产品域名。
func domain(value string) (string, error) {
	if !Text(value, 1024, true) || strings.ContainsAny(value, "/*:@\\?#[]") {
		return "", ErrInput
	}
	name, err := idna.Lookup.ToASCII(strings.TrimSuffix(value, "."))
	name = strings.ToLower(name)
	if err != nil || len(name) > 253 || !strings.Contains(name, ".") || net.ParseIP(name) != nil {
		return "", ErrInput
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", ErrInput
		}
		for _, c := range label {
			if c != '-' && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
				return "", ErrInput
			}
		}
	}
	if _, err := publicsuffix.EffectiveTLDPlusOne(name); err != nil {
		return "", ErrInput
	}
	return name, nil
}

func domainField(field string) bool {
	return field == "http.host" || field == "tls.sni" || field == "dns.name"
}

func (c Condition) Validate() error {
	if domainField(c.Field) {
		if c.Op != "eq" && c.Op != "domain_suffix" {
			return ErrInput
		}
		_, err := domain(c.Value)
		return err
	}
	switch c.Field {
	case "http.method":
		if c.Op != "eq" || !slices.Contains([]string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT", "TRACE"}, c.Value) {
			return ErrInput
		}
	case "http.path":
		if (c.Op != "eq" && c.Op != "prefix") || !Text(c.Value, 256, true) || !strings.HasPrefix(c.Value, "/") {
			return ErrInput
		}
	case "http.user_agent":
		if (c.Op != "eq" && c.Op != "contains") || !Text(c.Value, 128, true) {
			return ErrInput
		}
	case "tls.alpn":
		if c.Op != "eq" || !Text(c.Value, 64, true) {
			return ErrInput
		}
	default:
		return ErrInput
	}
	return nil
}

func (d Definition) Validate() error {
	encoded, _ := json.Marshal(d)
	if len(encoded) > 16384 {
		return ErrInput
	}
	if d.SchemaVersion != Schema || !contract.ValidID(d.ProductID) || !Text(d.ProductName, 128, true) || !slices.Contains(Categories, d.CategoryID) || len(d.Protocols) < 1 || len(d.Protocols) > 4 || len(d.Any) < 1 || len(d.Any) > 16 || d.All == nil || d.Exclude == nil || len(d.All)+len(d.Any)+len(d.Exclude) > 32 {
		return ErrInput
	}
	seen := map[string]bool{}
	for _, protocol := range d.Protocols {
		if !slices.Contains([]string{"http", "tls", "quic", "dns"}, protocol) || seen[protocol] {
			return ErrInput
		}
		seen[protocol] = true
	}
	seen = map[string]bool{}
	for group, conditions := range [][]Condition{d.Any, d.All, d.Exclude} {
		for _, c := range conditions {
			if c.Validate() != nil || group == 0 && !domainField(c.Field) {
				return ErrInput
			}
			compatible := strings.HasPrefix(c.Field, "http.") && slices.Contains(d.Protocols, "http") || strings.HasPrefix(c.Field, "tls.") && (slices.Contains(d.Protocols, "tls") || slices.Contains(d.Protocols, "quic")) || c.Field == "dns.name" && slices.Contains(d.Protocols, "dns")
			key := strconv.Itoa(group) + "/" + c.Field + "/" + c.Op + "/" + c.Value
			if !compatible || seen[key] {
				return ErrInput
			}
			seen[key] = true
		}
	}
	return nil
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
	if !contract.ValidID(c.ID) || c.ExpectedRevision < 0 || c.ExpectedRevision >= MaxRevision || !Text(c.Name, 128, true) || !Text(c.Description, 1000, false) || c.Active == nil || c.ExpectedRevision == 0 && !*c.Active {
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

func Digest(value any) string {
	raw, _ := json.Marshal(value)
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func (r Record) Validate() error {
	if !contract.ValidID(r.TenantID) || !contract.ValidID(r.ID) || !contract.ValidID(r.CreatedBy) || r.Revision < 1 || r.Revision > MaxRevision || !Text(r.Name, 128, true) || !Text(r.Description, 1000, false) || r.CreatedAt.IsZero() || !r.ExpiresAt.After(r.CreatedAt) || r.DefinitionSHA256 != Digest(r.Definition) {
		return ErrInput
	}
	return r.Definition.Validate()
}

type ListQuery struct {
	Cursor, Keyword, Active string
	Limit                   int
}

func (q ListQuery) Validate() error {
	if q.Limit < 1 || q.Limit > 100 || q.Cursor != "" && !contract.ValidID(q.Cursor) || !Text(q.Keyword, 128, false) || q.Active != "" && q.Active != "true" && q.Active != "false" {
		return ErrInput
	}
	return nil
}

type Page struct {
	Items      []Record `json:"items"`
	NextCursor string   `json:"next_cursor"`
}

type Observation struct {
	SchemaVersion string   `json:"schema_version"`
	Protocol      string   `json:"protocol"`
	HTTPHost      string   `json:"http_host"`
	HTTPMethod    string   `json:"http_method"`
	HTTPPath      string   `json:"http_path"`
	HTTPUserAgent string   `json:"http_user_agent"`
	TLSSNI        string   `json:"tls_sni"`
	TLSALPN       []string `json:"tls_alpn"`
	DNSNames      []string `json:"dns_names"`
}

func host(value string) (string, error) {
	if strings.Contains(value, ":") {
		name, port, err := net.SplitHostPort(value)
		if err != nil {
			return "", ErrInput
		}
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return "", ErrInput
		}
		value = name
	}
	return domain(value)
}

func (o Observation) fields() (map[string][]string, error) {
	if o.SchemaVersion != ObservationSchema || !slices.Contains([]string{"http", "tls", "quic", "dns"}, o.Protocol) || o.TLSALPN == nil || o.DNSNames == nil || len(o.TLSALPN) > 8 || len(o.DNSNames) > 32 || !Text(o.HTTPPath, 4096, false) || o.HTTPPath != "" && !strings.HasPrefix(o.HTTPPath, "/") || !Text(o.HTTPUserAgent, 1024, false) {
		return nil, ErrInput
	}
	if o.Protocol != "http" && (o.HTTPHost != "" || o.HTTPMethod != "" || o.HTTPPath != "" || o.HTTPUserAgent != "") || o.Protocol != "tls" && o.Protocol != "quic" && (o.TLSSNI != "" || len(o.TLSALPN) > 0) || o.Protocol != "dns" && len(o.DNSNames) > 0 {
		return nil, ErrInput
	}
	fields := map[string][]string{}
	for _, field := range []struct {
		name, value string
		authority   bool
	}{{"http.host", o.HTTPHost, true}, {"tls.sni", o.TLSSNI, false}} {
		if field.value == "" {
			continue
		}
		var value string
		var err error
		if field.authority {
			value, err = host(field.value)
		} else {
			value, err = domain(field.value)
		}
		if err != nil {
			return nil, err
		}
		fields[field.name] = []string{value}
	}
	for _, value := range o.DNSNames {
		name, err := domain(value)
		if err != nil {
			return nil, err
		}
		fields["dns.name"] = append(fields["dns.name"], name)
	}
	if o.HTTPMethod != "" {
		if (Condition{Field: "http.method", Op: "eq", Value: o.HTTPMethod}).Validate() != nil {
			return nil, ErrInput
		}
		fields["http.method"] = []string{o.HTTPMethod}
	}
	if o.HTTPPath != "" {
		fields["http.path"] = []string{o.HTTPPath}
	}
	if o.HTTPUserAgent != "" {
		fields["http.user_agent"] = []string{o.HTTPUserAgent}
	}
	for _, value := range o.TLSALPN {
		if !Text(value, 64, true) {
			return nil, ErrInput
		}
		fields["tls.alpn"] = append(fields["tls.alpn"], value)
	}
	return fields, nil
}

func (o Observation) Validate() error {
	_, err := o.fields()
	return err
}

type Version struct {
	ID         string     `json:"id"`
	Revision   int64      `json:"revision"`
	Definition Definition `json:"definition"`
}
type Evidence struct {
	Field   string `json:"field"`
	Op      string `json:"op"`
	Pattern string `json:"pattern"`
}
type Match struct {
	RuleID          string     `json:"rule_id"`
	Revision        int64      `json:"revision"`
	ProductID       string     `json:"product_id"`
	ProductName     string     `json:"product_name"`
	CategoryID      string     `json:"category_id"`
	Evidence        []Evidence `json:"evidence"`
	EvidenceLimited bool       `json:"evidence_limited"`
}
type Result struct {
	SchemaVersion     string    `json:"schema_version"`
	Origin            string    `json:"origin"`
	Protocol          string    `json:"protocol"`
	Status            string    `json:"status"`
	Reason            string    `json:"reason"`
	EvaluatedAt       time.Time `json:"evaluated_at"`
	ObservationSHA256 string    `json:"observation_sha256"`
	RulesSHA256       string    `json:"rules_sha256"`
	RuleCount         int       `json:"rule_count"`
	MatchedRuleCount  int       `json:"matched_rule_count"`
	Matches           []Match   `json:"matches"`
	Limited           bool      `json:"limited"`
}

func matches(c Condition, fields map[string][]string) bool {
	pattern := c.Value
	if domainField(c.Field) {
		pattern, _ = domain(pattern)
	}
	for _, value := range fields[c.Field] {
		switch c.Op {
		case "eq":
			if value == pattern {
				return true
			}
		case "domain_suffix":
			if value == pattern || strings.HasSuffix(value, "."+pattern) {
				return true
			}
		case "prefix":
			if strings.HasPrefix(value, pattern) {
				return true
			}
		case "contains":
			if strings.Contains(value, pattern) {
				return true
			}
		}
	}
	return false
}

// 测试材料与当前规则快照分别摘要绑定。不同产品命中始终保留冲突，不以优先级掩盖证据。
// 仅对有界的验证请求逐规则计算；该入口不是逐包 DPI 或流量计量路径。
func Evaluate(versions []Version, observation Observation, now time.Time) (Result, error) {
	result := Result{SchemaVersion: ResultSchema, Origin: "user_supplied_metadata", Protocol: observation.Protocol, Status: "unknown", Reason: "no_matching_rule", EvaluatedAt: now.UTC(), ObservationSHA256: Digest(observation), Matches: []Match{}}
	fields, err := observation.fields()
	if err != nil || now.IsZero() || len(versions) > MaxRules {
		return Result{}, ErrInput
	}
	versions = slices.Clone(versions)
	slices.SortFunc(versions, func(a, b Version) int { return strings.Compare(a.ID, b.ID) })
	seen := map[string]bool{}
	products := map[string]bool{}
	for _, version := range versions {
		if !contract.ValidID(version.ID) || version.Revision < 1 || version.Revision > MaxRevision || version.Definition.Validate() != nil || seen[version.ID] {
			return Result{}, ErrInput
		}
		seen[version.ID] = true
		d := version.Definition
		if !slices.Contains(d.Protocols, observation.Protocol) {
			continue
		}
		allowed := true
		for _, c := range d.Exclude {
			if matches(c, fields) {
				allowed = false
				break
			}
		}
		if !allowed {
			continue
		}
		for _, c := range d.All {
			if !matches(c, fields) {
				allowed = false
				break
			}
		}
		if !allowed {
			continue
		}
		evidence := []Evidence{}
		for _, c := range d.Any {
			if matches(c, fields) {
				evidence = append(evidence, Evidence{Field: c.Field, Op: c.Op, Pattern: c.Value})
			}
		}
		if len(evidence) == 0 {
			continue
		}
		for _, c := range d.All {
			evidence = append(evidence, Evidence{Field: c.Field, Op: c.Op, Pattern: c.Value})
		}
		products[d.ProductID] = true
		result.MatchedRuleCount++
		if len(result.Matches) < 16 {
			result.Matches = append(result.Matches, Match{RuleID: version.ID, Revision: version.Revision, ProductID: d.ProductID, ProductName: d.ProductName, CategoryID: d.CategoryID, Evidence: slices.Clone(evidence[:min(len(evidence), 8)]), EvidenceLimited: len(evidence) > 8})
		}
	}
	result.RuleCount = len(versions)
	result.RulesSHA256 = Digest(versions)
	result.Limited = result.MatchedRuleCount > len(result.Matches)
	if len(products) == 1 {
		result.Status = "candidate"
		result.Reason = "visible_name_rule"
	}
	if len(products) > 1 {
		result.Status = "conflict"
		result.Reason = "multiple_products"
	}
	if len(fields) == 0 {
		result.Reason = "metadata_unavailable"
	}
	return result, nil
}
