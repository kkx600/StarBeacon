package application

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/kkx600/StarBeacon/internal/contract"
)

const PackageSchema = "application-package.v1"
const StateSchema = "application-state.v1"
const AttributionSchema = "application-attribution.v1"
const MaxPackageBytes = 900 * 1024
const MaxAttributionBytes = 32 * 1024

// 快照按稳定规则标识排序，空快照用于显式停用采集器的所有应用规则。
type Snapshot struct {
	RulesSHA256 string    `json:"rules_sha256"`
	Versions    []Version `json:"versions"`
}

type DeploymentInput struct {
	ExpectedRegistrationID string `json:"expected_registration_id"`
	ExpectedStateSHA256    string `json:"expected_state_sha256"`
	RulesSHA256            string `json:"rules_sha256"`
}

type Package struct {
	SchemaVersion string `json:"schema_version"`
	DeploymentInput
	Versions []Version `json:"versions"`
}

type State struct {
	SchemaVersion string     `json:"schema_version"`
	DeploymentID  string     `json:"deployment_id"`
	RulesSHA256   string     `json:"rules_sha256"`
	StateSHA256   string     `json:"state_sha256"`
	RuleCount     int        `json:"rule_count"`
	InstalledAt   *time.Time `json:"installed_at"`
}

func ValidSHA256(value string) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == sha256.Size && hex.EncodeToString(raw) == value
}

func (p DeploymentInput) Validate() error {
	if !contract.ValidID(p.ExpectedRegistrationID) || !ValidSHA256(p.ExpectedStateSHA256) || !ValidSHA256(p.RulesSHA256) {
		return ErrInput
	}
	return nil
}

func StateDigest(id, rules string) string {
	return Digest(struct {
		DeploymentID string `json:"deployment_id"`
		RulesSHA256  string `json:"rules_sha256"`
	}{id, rules})
}

func EmptyState() State {
	rules := Digest([]Version{})
	return State{SchemaVersion: StateSchema, RulesSHA256: rules, StateSHA256: StateDigest("", rules)}
}

func (s State) Validate() error {
	if s.SchemaVersion != StateSchema || !ValidSHA256(s.RulesSHA256) || s.StateSHA256 != StateDigest(s.DeploymentID, s.RulesSHA256) || s.RuleCount < 0 || s.RuleCount > MaxRules {
		return ErrInput
	}
	if s.DeploymentID == "" {
		if s != EmptyState() {
			return ErrInput
		}
		return nil
	}
	if !contract.ValidID(s.DeploymentID) || s.InstalledAt == nil || s.InstalledAt.IsZero() {
		return ErrInput
	}
	return nil
}

func ReadPackage(raw []byte) (Package, error) {
	var p Package
	fields := []string{"schema_version", "expected_registration_id", "expected_state_sha256", "rules_sha256", "versions", "id", "revision", "definition", "product_id", "product_name", "category_id", "protocols", "any", "all", "exclude", "field", "op", "value"}
	if contract.JSONFields(string(raw), fields, MaxPackageBytes) != nil {
		return p, ErrInput
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil || d.Decode(new(any)) != io.EOF || p.SchemaVersion != PackageSchema || p.DeploymentInput.Validate() != nil || p.Versions == nil || Digest(p.Versions) != p.RulesSHA256 {
		return Package{}, ErrInput
	}
	if _, err := Compile(p.Versions); err != nil {
		return Package{}, err
	}
	return p, nil
}

// 只对协议元数据事件匹配，反向域名桶避免在热路径重复验证配置或扫描所有规则。
// 编译器不接收正则或脚本，也不将 DNS 名称扩散到其他连接。
type Matcher struct {
	versions []Version
	sha256   string
	exact    map[string]map[string][]int
	suffix   map[string]map[string][]int
}

func Compile(versions []Version) (*Matcher, error) {
	if versions == nil || len(versions) > MaxRules {
		return nil, ErrInput
	}
	raw, err := json.Marshal(versions)
	if err != nil || len(raw) > MaxPackageBytes {
		return nil, ErrInput
	}
	m := &Matcher{sha256: Digest(versions), exact: map[string]map[string][]int{}, suffix: map[string]map[string][]int{}}
	// 独立副本不能被调用者修改，也不能引用已关闭的数据库事务内存。
	if json.Unmarshal(raw, &m.versions) != nil {
		return nil, ErrInput
	}
	products := map[string]string{}
	for index, version := range m.versions {
		if !contract.ValidID(version.ID) || version.Revision < 1 || version.Revision > MaxRevision || version.Definition.Validate() != nil || index > 0 && versions[index-1].ID >= version.ID {
			return nil, ErrInput
		}
		d := &m.versions[index].Definition
		identity := d.ProductName + "\x00" + d.CategoryID
		if old, ok := products[d.ProductID]; ok && old != identity {
			return nil, ErrInput
		}
		products[d.ProductID] = identity
		for _, group := range [][]Condition{d.Any, d.All, d.Exclude} {
			for i := range group {
				if domainField(group[i].Field) {
					group[i].Value, _ = domain(group[i].Value)
				}
			}
		}
		for _, c := range d.Any {
			buckets := m.exact
			if c.Op == "domain_suffix" {
				buckets = m.suffix
			}
			if buckets[c.Field] == nil {
				buckets[c.Field] = map[string][]int{}
			}
			buckets[c.Field][c.Value] = append(buckets[c.Field][c.Value], index)
		}
	}
	return m, nil
}

func (m *Matcher) SHA256() string { return m.sha256 }

func (m *Matcher) Evaluate(o Observation, now time.Time) (Result, error) {
	fields, err := o.fields()
	if err != nil || now.IsZero() {
		return Result{}, ErrInput
	}
	selected := make([]bool, len(m.versions))
	for field, values := range fields {
		if !domainField(field) {
			continue
		}
		for _, value := range values {
			for _, index := range m.exact[field][value] {
				selected[index] = true
			}
			for name := value; name != ""; {
				for _, index := range m.suffix[field][name] {
					selected[index] = true
				}
				_, rest, ok := strings.Cut(name, ".")
				if !ok {
					break
				}
				name = rest
			}
		}
	}
	result := Result{SchemaVersion: ResultSchema, Origin: "suricata_visible_metadata", Protocol: o.Protocol, Status: "unknown", Reason: "no_matching_rule", EvaluatedAt: now.UTC(), ObservationSHA256: Digest(o), RulesSHA256: m.sha256, RuleCount: len(m.versions), Matches: []Match{}}
	products := map[string]bool{}
	for index, version := range m.versions {
		if !selected[index] || !slices.Contains(version.Definition.Protocols, o.Protocol) {
			continue
		}
		d := version.Definition
		if slices.ContainsFunc(d.Exclude, func(c Condition) bool { return matches(c, fields) }) || !allMatch(d.All, fields) {
			continue
		}
		evidence := []Evidence{}
		// 依据保留与本次比较相同的 IDNA 规范条件，不输出测试材料中的原始名称。
		for _, c := range append(slices.Clone(d.Any), d.All...) {
			if matches(c, fields) {
				evidence = append(evidence, Evidence{Field: c.Field, Op: c.Op, Pattern: c.Value})
			}
		}
		products[d.ProductID] = true
		result.MatchedRuleCount++
		if len(result.Matches) < 16 {
			result.Matches = append(result.Matches, Match{RuleID: version.ID, Revision: version.Revision, ProductID: d.ProductID, ProductName: d.ProductName, CategoryID: d.CategoryID, Evidence: slices.Clone(evidence[:min(len(evidence), 8)]), EvidenceLimited: len(evidence) > 8})
		}
	}
	result.Limited = result.MatchedRuleCount > len(result.Matches)
	if len(products) == 1 {
		result.Status, result.Reason = "candidate", "visible_name_rule"
	} else if len(products) > 1 {
		result.Status, result.Reason = "conflict", "multiple_products"
	} else if len(fields) == 0 {
		result.Reason = "metadata_unavailable"
	}
	return result, nil
}

func allMatch(conditions []Condition, fields map[string][]string) bool {
	return !slices.ContainsFunc(conditions, func(c Condition) bool { return !matches(c, fields) })
}
