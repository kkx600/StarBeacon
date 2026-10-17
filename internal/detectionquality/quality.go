// Package detectionquality 将原生总计数转换为有界的探针区间观测，不推断单流覆盖或攻击结果。
package detectionquality

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/kkx600/StarBeacon/internal/normalize"
)

// MaxSampleGap 包含五秒原生采样、读取和调度余量；超过此间隔不建立连续区间。
const MaxSampleGap = 20 * time.Second

type Definition struct{ Key, Layer, Kind string }

// 只采用 Suricata 8.0.7 实际注册的总计数，不合并线程计数或推定未输出的零值。
var definitions = []Definition{
	{"capture.kernel_packets", "capture", "counter"}, {"capture.kernel_drops", "capture", "counter"}, {"capture.errors", "capture", "counter"},
	{"decoder.pkts", "volume", "counter"}, {"decoder.bytes", "volume", "counter"}, {"flow.active", "volume", "gauge"},
	{"tcp.ssn_memcap_drop", "inspection", "counter"}, {"tcp.segment_memcap_drop", "inspection", "counter"},
	{"tcp.stream_depth_reached", "inspection", "counter"}, {"tcp.reassembly_gap", "inspection", "counter"},
	{"tcp.pkt_on_wrong_thread", "inspection", "counter"}, {"tcp.ack_unseen_data", "inspection", "counter"},
	{"tcp.overlap_diff_data", "inspection", "counter"}, {"tcp.invalid_checksum", "inspection", "counter"}, {"tcp.midstream_pickups", "inspection", "counter"},
	{"defrag.max_trackers_reached", "inspection", "counter"}, {"defrag.max_frags_reached", "inspection", "counter"}, {"defrag.wrk.tracker_timeout", "inspection", "counter"},
	{"flow.memcap", "inspection", "counter"}, {"flow.emerg_mode_entered", "inspection", "counter"},
	{"detect.alert", "volume", "counter"}, {"detect.alert_queue_overflow", "alerting", "counter"},
	{"detect.alerts_suppressed", "policy", "counter"}, {"flow_bypassed.local_pkts", "policy", "counter"}, {"flow_bypassed.local_capture_pkts", "policy", "counter"},
}

type Counter struct {
	Key   string  `json:"key"`
	Layer string  `json:"layer"`
	Kind  string  `json:"kind"`
	Total *string `json:"total,omitempty"`
	Delta *string `json:"delta,omitempty"`
}

type Facet struct {
	State   string   `json:"state"`
	Reasons []string `json:"reasons"`
}

type Report struct {
	SchemaVersion     int        `json:"schema_version"`
	Scope             string     `json:"scope"`
	Source            string     `json:"source"`
	State             string     `json:"state"`
	EngineRunID       string     `json:"engine_run_id"`
	ConfigSHA256      string     `json:"config_sha256"`
	EvaluatedAt       time.Time  `json:"evaluated_at"`
	SampledAt         *time.Time `json:"sampled_at,omitempty"`
	ReceivedAt        *time.Time `json:"received_at,omitempty"`
	IntervalStartedAt *time.Time `json:"interval_started_at,omitempty"`
	ResetCounters     []string   `json:"reset_counters"`
	Counters          []Counter  `json:"counters"`
	Capture           Facet      `json:"capture"`
	Inspection        Facet      `json:"inspection"`
	Alerting          Facet      `json:"alerting"`
	Policy            Facet      `json:"policy"`
}

// Extract 不采用浮点解码，uint64 总量以十进制字符串保留精度；无效字段保持缺测。
func Extract(raw []byte) (map[string]string, bool) {
	var root map[string]json.RawMessage
	if len(raw) > 1024*1024 || json.Unmarshal(raw, &root) != nil || root == nil {
		return nil, false
	}
	values := make(map[string]string)
	for _, def := range definitions {
		value := json.RawMessage(raw)
		for _, part := range strings.Split(def.Key, ".") {
			var object map[string]json.RawMessage
			if json.Unmarshal(value, &object) != nil {
				value = nil
				break
			}
			value = object[part]
		}
		var number uint64
		if len(value) > 0 && value[0] != '"' && string(value) != "null" && json.Unmarshal(value, &number) == nil {
			values[def.Key] = strconv.FormatUint(number, 10)
		}
	}
	return values, true
}

// Tracker 的调用方串行化观察与读取；每次快照重新构造，调用方不能修改内部基线。
type Tracker struct {
	runID, configSHA            string
	started                     time.Time
	sampled, received, interval *time.Time
	values, deltas              map[string]string
	reset                       []string
	state                       string
}

func (t *Tracker) Start(runID, configSHA string, started time.Time) {
	*t = Tracker{runID: runID, configSHA: configSHA, started: started, state: "unavailable"}
}

// Observe 仅接收当前托管进程 EVE 的持久记录；回放、旧进程、重复、未来或乱序样本不能刷新健康状态。
func (t *Tracker) Observe(payload []byte, received time.Time) {
	if t.runID == "" || len(payload) > 1024*1024 {
		return
	}
	var event struct {
		Type      string          `json:"event_type"`
		Timestamp string          `json:"timestamp"`
		Stats     json.RawMessage `json:"stats"`
	}
	if json.Unmarshal(payload, &event) != nil || event.Type != "stats" {
		return
	}
	sampled, err := normalize.ParseTimestamp(event.Timestamp)
	if err != nil || sampled.Before(t.started) || sampled.After(received.Add(5*time.Second)) || t.sampled != nil && !sampled.After(*t.sampled) {
		return
	}
	values, valid := Extract(event.Stats)
	if !valid || len(values) == 0 {
		return
	}
	t.deltas, t.reset, t.interval = map[string]string{}, []string{}, nil
	t.state = "baseline"
	if t.sampled != nil {
		t.state = "observed"
		if sampled.Sub(*t.sampled) > MaxSampleGap || t.received != nil && (received.Before(*t.received) || received.Sub(*t.received) > MaxSampleGap) {
			t.state = "sample_gap"
		}
		for _, def := range definitions {
			current, have := values[def.Key]
			prior, had := t.values[def.Key]
			if def.Kind != "counter" || !have || !had {
				continue
			}
			v, _ := strconv.ParseUint(current, 10, 64)
			p, _ := strconv.ParseUint(prior, 10, 64)
			if v < p {
				t.reset = append(t.reset, def.Key)
			} else {
				t.deltas[def.Key] = strconv.FormatUint(v-p, 10)
			}
		}
		if len(t.reset) > 0 {
			t.state = "counter_reset"
		}
		if t.state == "observed" {
			previous := *t.sampled
			t.interval = &previous
		} else {
			t.deltas = map[string]string{}
		}
	}
	t.values, t.sampled, t.received = values, &sampled, &received
}

func (t *Tracker) Snapshot(now time.Time, running bool) Report {
	r := Report{SchemaVersion: 1, Scope: "sensor_interval", Source: "suricata_eve_stats", State: t.state, EngineRunID: t.runID, ConfigSHA256: t.configSHA, EvaluatedAt: now, ResetCounters: append([]string{}, t.reset...), Counters: []Counter{}}
	if r.State == "" {
		r.State = "unavailable"
	}
	if t.sampled != nil {
		v := *t.sampled
		r.SampledAt = &v
	}
	if t.received != nil {
		v := *t.received
		r.ReceivedAt = &v
	}
	if t.interval != nil {
		v := *t.interval
		r.IntervalStartedAt = &v
	}
	if !running {
		r.State = "stopped"
	} else if t.sampled != nil && (now.Sub(*t.sampled) > MaxSampleGap || now.Sub(*t.received) > MaxSampleGap || now.Before(t.received.Add(-5*time.Second)) || now.Before(t.sampled.Add(-5*time.Second))) {
		r.State = "stale"
	}
	for _, def := range definitions {
		c := Counter{Key: def.Key, Layer: def.Layer, Kind: def.Kind}
		if value, ok := t.values[def.Key]; ok {
			c.Total = &value
		}
		if value, ok := t.deltas[def.Key]; ok && r.State == "observed" {
			c.Delta = &value
		}
		r.Counters = append(r.Counters, c)
	}
	r.Capture, r.Inspection, r.Alerting, r.Policy = facet(r, "capture"), facet(r, "inspection"), facet(r, "alerting"), facet(r, "policy")
	return r
}

func facet(r Report, layer string) Facet {
	f := Facet{State: "no_reported_change", Reasons: []string{}}
	if r.State != "observed" {
		f.State = "unknown"
		return f
	}
	missing := layer == "capture" && r.Counters[0].Delta == nil
	for _, c := range r.Counters {
		if c.Layer != layer || c.Key == "capture.kernel_packets" {
			continue
		}
		if c.Delta == nil {
			missing = true
			continue
		}
		if *c.Delta != "0" {
			f.Reasons = append(f.Reasons, c.Key)
		}
	}
	if len(f.Reasons) > 0 {
		f.State = "limited"
		if layer == "policy" {
			f.State = "policy_applied"
		}
	} else if missing {
		f.State = "unknown"
	}
	return f
}
