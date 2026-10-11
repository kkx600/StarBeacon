// Package analytics 定义有界态势统计；观测计数不推断攻击成功或风险评分。
package analytics

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/kkx600/StarBeacon/internal/contract"
)

var ErrIncomplete = errors.New("统计结果不完整")

type Window struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

func (w Window) Validate() error {
	if w.Start.IsZero() || w.End.IsZero() || !w.End.After(w.Start) || w.End.Sub(w.Start) > 31*24*time.Hour {
		return errors.New("统计时间范围必须大于零且不超过 31 天")
	}
	return nil
}

type Bucket struct {
	Key   string `json:"key"`
	Count string `json:"count"`
}

type Distribution struct {
	Buckets         []Bucket `json:"buckets"`
	Other           string   `json:"other"`
	ErrorUpperBound string   `json:"error_upper_bound"`
}

type Events struct {
	Total     string       `json:"total"`
	Interval  string       `json:"interval"`
	Trend     []Bucket     `json:"trend"`
	Severity  Distribution `json:"severity"`
	Protocols Distribution `json:"protocols"`
	Rules     Distribution `json:"rules"`
	Sensors   Distribution `json:"sensors"`
}

type Inventory struct {
	Assets   string `json:"assets"`
	Groups   string `json:"groups"`
	Networks string `json:"networks"`
	Sensors  string `json:"sensors"`
	Online   string `json:"online"`
	Offline  string `json:"offline"`
	Disabled string `json:"disabled"`
}

type Snapshot struct {
	Window      Window    `json:"window"`
	ObservedAt  time.Time `json:"observed_at"`
	Events      Events    `json:"events"`
	Inventory   Inventory `json:"inventory"`
	Limitations []string  `json:"limitations"`
}

func (s Snapshot) Validate() error {
	if s.Window.Validate() != nil || s.ObservedAt.IsZero() || (s.Events.Interval != "hour" && s.Events.Interval != "day") || s.Events.Trend == nil || s.Limitations == nil {
		return ErrIncomplete
	}
	count := func(value string) bool {
		n, err := strconv.ParseInt(value, 10, 64)
		return err == nil && n >= 0 && strconv.FormatInt(n, 10) == value
	}
	for _, value := range []string{s.Events.Total, s.Inventory.Assets, s.Inventory.Groups, s.Inventory.Networks, s.Inventory.Sensors, s.Inventory.Online, s.Inventory.Offline, s.Inventory.Disabled} {
		if !count(value) {
			return ErrIncomplete
		}
	}
	for _, bucket := range s.Events.Trend {
		if !count(bucket.Count) {
			return ErrIncomplete
		}
		if _, err := time.Parse(time.RFC3339Nano, bucket.Key); err != nil {
			return ErrIncomplete
		}
	}
	for _, d := range []Distribution{s.Events.Severity, s.Events.Protocols, s.Events.Rules, s.Events.Sensors} {
		if d.Buckets == nil || !count(d.Other) || !count(d.ErrorUpperBound) {
			return ErrIncomplete
		}
		for _, b := range d.Buckets {
			if b.Key == "" || len(b.Key) > 512 || !count(b.Count) {
				return ErrIncomplete
			}
		}
	}
	return nil
}

func Interval(w Window) string {
	if w.End.Sub(w.Start) > 48*time.Hour {
		return "day"
	}
	return "hour"
}

func Query(tenant string, w Window) ([]byte, error) {
	if !contract.ValidID(tenant) {
		return nil, errors.New("租户标识无效")
	}
	if err := w.Validate(); err != nil {
		return nil, err
	}
	terms := func(field string, size int) any {
		return map[string]any{"terms": map[string]any{"field": field, "size": size, "shard_size": 100, "missing": "unknown", "show_term_doc_count_error": true}}
	}
	bounds := map[string]any{"min": w.Start.UnixMilli(), "max": w.End.Add(-time.Nanosecond).UnixMilli()}
	return json.Marshal(map[string]any{
		"size": 0, "track_total_hits": true, "timeout": "8s",
		"query": map[string]any{"bool": map[string]any{"filter": []any{
			map[string]any{"term": map[string]string{"tenant_id": tenant}},
			map[string]any{"range": map[string]any{"@timestamp": map[string]any{"gte": w.Start, "lt": w.End}}},
		}}},
		"aggs": map[string]any{
			"trend":    map[string]any{"date_histogram": map[string]any{"field": "@timestamp", "calendar_interval": Interval(w), "time_zone": "UTC", "min_doc_count": 0, "extended_bounds": bounds, "hard_bounds": bounds}},
			"severity": terms("severity", 10), "protocols": terms("network.protocol", 10), "rules": terms("rule.id", 10), "sensors": terms("sensor_id", 10),
		},
	})
}

type rawBucket struct {
	Key         json.RawMessage `json:"key"`
	KeyAsString string          `json:"key_as_string"`
	Count       *int64          `json:"doc_count"`
}

type rawDistribution struct {
	Buckets         []rawBucket `json:"buckets"`
	Other           *int64      `json:"sum_other_doc_count"`
	ErrorUpperBound *int64      `json:"doc_count_error_upper_bound"`
}

func Decode(raw []byte, w Window) (Events, error) {
	var value struct {
		TimedOut *bool `json:"timed_out"`
		Shards   struct {
			Failed *int `json:"failed"`
		} `json:"_shards"`
		Hits struct {
			Total struct {
				Value    *int64 `json:"value"`
				Relation string `json:"relation"`
			} `json:"total"`
		} `json:"hits"`
		Aggregations map[string]rawDistribution `json:"aggregations"`
	}
	if err := w.Validate(); err != nil {
		return Events{}, err
	}
	if err := json.Unmarshal(raw, &value); err != nil {
		return Events{}, err
	}
	if value.TimedOut == nil || *value.TimedOut || value.Shards.Failed == nil || *value.Shards.Failed != 0 || value.Hits.Total.Relation != "eq" || value.Hits.Total.Value == nil || *value.Hits.Total.Value < 0 {
		return Events{}, ErrIncomplete
	}
	out := Events{Total: strconv.FormatInt(*value.Hits.Total.Value, 10), Interval: Interval(w), Trend: []Bucket{}}
	decode := func(name string, max int, trend bool) (Distribution, error) {
		input, ok := value.Aggregations[name]
		if !ok || input.Buckets == nil || len(input.Buckets) > max || (!trend && (input.Other == nil || *input.Other < 0 || input.ErrorUpperBound == nil || *input.ErrorUpperBound < 0)) {
			return Distribution{}, ErrIncomplete
		}
		result := Distribution{Buckets: []Bucket{}, Other: "0", ErrorUpperBound: "0"}
		if !trend {
			result.Other = strconv.FormatInt(*input.Other, 10)
			result.ErrorUpperBound = strconv.FormatInt(*input.ErrorUpperBound, 10)
		}
		for _, b := range input.Buckets {
			var key string
			if trend {
				key = b.KeyAsString
				if _, err := time.Parse(time.RFC3339Nano, key); err != nil {
					return Distribution{}, ErrIncomplete
				}
			} else if json.Unmarshal(b.Key, &key) != nil || key == "" || len(key) > 512 {
				return Distribution{}, ErrIncomplete
			}
			if b.Count == nil || *b.Count < 0 {
				return Distribution{}, ErrIncomplete
			}
			result.Buckets = append(result.Buckets, Bucket{key, strconv.FormatInt(*b.Count, 10)})
		}
		return result, nil
	}
	// 时间桶的键是毫秒数字，显示使用 ES 返回的时间字符串。
	trend, err := decode("trend", 49, true)
	if err != nil {
		return Events{}, fmt.Errorf("时间分布：%w", err)
	}
	out.Trend = trend.Buckets
	for _, item := range []struct {
		name   string
		target *Distribution
	}{{"severity", &out.Severity}, {"protocols", &out.Protocols}, {"rules", &out.Rules}, {"sensors", &out.Sensors}} {
		*item.target, err = decode(item.name, 10, false)
		if err != nil {
			return Events{}, fmt.Errorf("%s：%w", item.name, err)
		}
	}
	return out, nil
}
