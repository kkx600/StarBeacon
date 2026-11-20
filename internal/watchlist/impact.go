package watchlist

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/model"
)

const (
	ImpactSchema     = "watchlist-impact.v1"
	MaxImpactWindow  = 31 * 24 * time.Hour
	MaxImpactSamples = 20
	MaxImpactBytes   = 4 << 20
	// MaxDailyImpacts 限定每个租户滚动 24 小时内可发起的历史影响预览次数；每次预览都会打一次 ES 检索。
	MaxDailyImpacts = 200
)

// ErrIncomplete 表示历史检索超时、分片失败或返回材料与查询条件不一致，不能交付部分计数。
var ErrIncomplete = errors.New("历史告警检索结果不完整")

// ImpactRequest 对指定修订在有界时间窗内核对已索引告警；预览不登记命中，也不回填历史。
type ImpactRequest struct {
	Revision int64     `json:"revision"`
	Start    time.Time `json:"start"`
	End      time.Time `json:"end"`
}

func (r ImpactRequest) Validate(now time.Time) error {
	if r.Revision < 1 || r.Revision > MaxRevision || r.Start.IsZero() || r.End.IsZero() || !r.Start.Before(r.End) || r.End.Sub(r.Start) > MaxImpactWindow || r.End.After(now.Add(30*time.Second)) || r.Start.Before(time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)) {
		return ErrInput
	}
	return nil
}

type ValueCount struct {
	Value string `json:"value"`
	Count int64  `json:"count"`
}

type ImpactSample struct {
	EventID        string     `json:"event_id"`
	RawSHA256      string     `json:"raw_sha256"`
	Timestamp      time.Time  `json:"@timestamp"`
	SensorID       string     `json:"sensor_id"`
	RegistrationID string     `json:"registration_id"`
	Severity       string     `json:"severity"`
	RuleName       string     `json:"rule_name"`
	Matches        []Observed `json:"matches"`
}

type Impact struct {
	SchemaVersion       string         `json:"schema_version"`
	ListID              string         `json:"list_id"`
	ListRevision        int64          `json:"list_revision"`
	DefinitionSHA256    string         `json:"definition_sha256"`
	Kind                string         `json:"kind"`
	MatchType           string         `json:"match_type"`
	Current             bool           `json:"current"`
	Active              bool           `json:"active"`
	Start               time.Time      `json:"start"`
	End                 time.Time      `json:"end"`
	CheckedAt           time.Time      `json:"checked_at"`
	Fields              []string       `json:"fields"`
	Total               int64          `json:"total"`
	Values              []ValueCount   `json:"values"`
	Samples             []ImpactSample `json:"samples"`
	HitsRecorded        bool           `json:"hits_recorded"`
	ExecutionAuthorized bool           `json:"execution_authorized"`
}

// ImpactFields 是历史预览实际查询的已索引字段；TLS SNI 与 DNS 查询名没有检索字段，不在预览范围。
func ImpactFields(matchType string) []string {
	if matchType == "domain" {
		return []string{FieldHTTPHost}
	}
	return []string{FieldSourceIP, FieldDestinationIP}
}

func term(field string, value any) map[string]any {
	return map[string]any{"term": map[string]any{field: value}}
}

func valueClause(matchType, value string) map[string]any {
	if matchType == "domain" {
		// 主机名按原文入索引；大小写不同的同一主机名仍须命中，其余变体不扩展。
		return term(FieldHTTPHost, map[string]any{"value": value, "case_insensitive": true})
	}
	return map[string]any{"bool": map[string]any{"minimum_should_match": 1, "should": []any{term(FieldSourceIP, value), term(FieldDestinationIP, value)}}}
}

func bucketKey(i int) string { return fmt.Sprintf("v%02d", i) }

// ImpactDSL 只读取告警数据流，同时约束租户、时间、固定探针注册和名单值；聚合桶与名单值一一对应。
func ImpactDSL(tenant string, d Definition, start, end time.Time) ([]byte, error) {
	if !contract.ValidID(tenant) || d.Validate() != nil || start.IsZero() || !start.Before(end) {
		return nil, ErrInput
	}
	scopes := make([]any, 0, len(d.Sensors))
	for _, s := range d.Sensors {
		scopes = append(scopes, map[string]any{"bool": map[string]any{"filter": []any{term("sensor_id", s.SensorID), term("sensor_registration_id", s.RegistrationID)}}})
	}
	values := make([]any, 0, len(d.Values))
	buckets := map[string]any{}
	for i, v := range d.Values {
		clause := valueClause(d.MatchType, v)
		values = append(values, clause)
		buckets[bucketKey(i)] = clause
	}
	filter := []any{term("tenant_id", tenant), term("event.kind", "alert"), map[string]any{"range": map[string]any{"@timestamp": map[string]any{"gte": start.UTC(), "lt": end.UTC()}}}, map[string]any{"bool": map[string]any{"minimum_should_match": 1, "should": scopes}}, map[string]any{"bool": map[string]any{"minimum_should_match": 1, "should": values}}}
	return json.Marshal(map[string]any{
		"size": MaxImpactSamples, "track_total_hits": true, "timeout": "5s",
		"_source": []string{"event_id", "tenant_id", "raw_sha256", "@timestamp", "sensor_id", "sensor_registration_id", "severity", "rule.name", "event.kind", "source.ip", "destination.ip", "http.hostname"},
		"query":   map[string]any{"bool": map[string]any{"filter": filter}},
		"sort":    []any{map[string]string{"@timestamp": "desc"}, map[string]string{"event_id": "asc"}},
		"aggs":    map[string]any{"values": map[string]any{"filters": map[string]any{"filters": buckets}}},
	})
}

// impactMatches 用与实时关联相同的值规则复核检索结果，不考虑名单开关和有效期。
func impactMatches(d Definition, a model.Alert) []Observed {
	candidates := []Observed{{FieldSourceIP, a.Source.IP}, {FieldDestinationIP, a.Destination.IP}}
	if host, ok := CanonicalHost(a.HTTP.Hostname); ok {
		candidates = append(candidates, Observed{FieldHTTPHost, host})
	}
	out := []Observed{}
	for _, o := range candidates {
		if o.Valid() && slices.Contains(ImpactFields(d.MatchType), o.Field) && d.Matches(Target{SensorID: a.SensorID, RegistrationID: a.RegistrationID, Type: fieldType(o.Field), Value: o.Value}) && !slices.Contains(out, o) {
			out = append(out, o)
		}
	}
	return out
}

// DecodeImpact 拒绝超时、部分分片、非精确计数及不符合租户、时间、范围或排序的样本。
func DecodeImpact(raw []byte, tenant string, d Definition, start, end time.Time) (int64, []ValueCount, []ImpactSample, error) {
	var decoded struct {
		TimedOut *bool `json:"timed_out"`
		Shards   struct {
			Total      *int `json:"total"`
			Successful *int `json:"successful"`
			Failed     *int `json:"failed"`
		} `json:"_shards"`
		Hits struct {
			Total struct {
				Value    *int64 `json:"value"`
				Relation string `json:"relation"`
			} `json:"total"`
			Hits []struct {
				ID     string      `json:"_id"`
				Index  string      `json:"_index"`
				Source model.Alert `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
		Aggregations struct {
			Values struct {
				Buckets map[string]struct {
					DocCount *int64 `json:"doc_count"`
				} `json:"buckets"`
			} `json:"values"`
		} `json:"aggregations"`
	}
	if len(raw) > MaxImpactBytes || json.Unmarshal(raw, &decoded) != nil || decoded.TimedOut == nil || *decoded.TimedOut || decoded.Shards.Total == nil || decoded.Shards.Successful == nil || decoded.Shards.Failed == nil || *decoded.Shards.Total < 0 || *decoded.Shards.Successful != *decoded.Shards.Total || *decoded.Shards.Failed != 0 || decoded.Hits.Total.Value == nil || *decoded.Hits.Total.Value < 0 || decoded.Hits.Total.Relation != "eq" || decoded.Hits.Hits == nil {
		return 0, nil, nil, ErrIncomplete
	}
	total := *decoded.Hits.Total.Value
	// 尚无告警索引时没有分片参与，空结果不携带聚合桶；其余情况每个名单值都必须有精确计数。
	empty := *decoded.Shards.Total == 0 && total == 0 && len(decoded.Aggregations.Values.Buckets) == 0
	if int64(len(decoded.Hits.Hits)) != min(total, MaxImpactSamples) || !empty && len(decoded.Aggregations.Values.Buckets) != len(d.Values) {
		return 0, nil, nil, ErrIncomplete
	}
	values := make([]ValueCount, 0, len(d.Values))
	for i, v := range d.Values {
		if empty {
			values = append(values, ValueCount{Value: v})
			continue
		}
		bucket, ok := decoded.Aggregations.Values.Buckets[bucketKey(i)]
		if !ok || bucket.DocCount == nil || *bucket.DocCount < 0 || *bucket.DocCount > total {
			return 0, nil, nil, ErrIncomplete
		}
		values = append(values, ValueCount{Value: v, Count: *bucket.DocCount})
	}
	samples := make([]ImpactSample, 0, len(decoded.Hits.Hits))
	for i, h := range decoded.Hits.Hits {
		a := h.Source
		matches := impactMatches(d, a)
		if !contract.IndexServes(h.Index, "alerts") || h.ID != a.EventID || !contract.ValidID(a.EventID) || a.TenantID != tenant || a.Event.Kind != "alert" || !ValidDigest(a.RawSHA256) || !validSeverity(a.Severity) || a.Timestamp.Before(start) || !a.Timestamp.Before(end) || !slices.Contains(d.Sensors, Sensor{a.SensorID, a.RegistrationID}) || len(matches) == 0 {
			return 0, nil, nil, ErrIncomplete
		}
		if i > 0 {
			previous := samples[i-1]
			if a.Timestamp.After(previous.Timestamp) || a.Timestamp.Equal(previous.Timestamp) && a.EventID <= previous.EventID {
				return 0, nil, nil, ErrIncomplete
			}
		}
		name := a.Rule.Name
		if !Text(name, maxRuleNameLen, false) {
			name = ""
		}
		samples = append(samples, ImpactSample{EventID: a.EventID, RawSHA256: a.RawSHA256, Timestamp: a.Timestamp.UTC(), SensorID: a.SensorID, RegistrationID: a.RegistrationID, Severity: a.Severity, RuleName: name, Matches: matches})
	}
	return total, values, samples, nil
}
