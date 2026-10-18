package detectionquality

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func sample(at time.Time, values map[string]any) []byte {
	raw, _ := json.Marshal(map[string]any{"event_type": "stats", "timestamp": at.Format("2006-01-02T15:04:05.000000-0700"), "stats": values})
	return raw
}

func allValues(value uint64) map[string]any {
	raw := map[string]any{}
	for _, d := range definitions {
		parts := strings.Split(d.Key, ".")
		parent := raw
		for _, part := range parts[:len(parts)-1] {
			if parent[part] == nil {
				parent[part] = map[string]any{}
			}
			parent = parent[part].(map[string]any)
		}
		parent[parts[len(parts)-1]] = value
	}
	return raw
}

func TestNativeCounterExtractionKeepsPrecisionAndMissingValues(t *testing.T) {
	v, valid := Extract([]byte(`{"capture":{"kernel_packets":18446744073709551615,"kernel_drops":0},"detect":{"alert_queue_overflow":9007199254740993},"threads":{"capture":{"kernel_drops":999}}}`))
	if !valid || len(v) != 3 || v["capture.kernel_packets"] != "18446744073709551615" || v["detect.alert_queue_overflow"] != "9007199254740993" {
		t.Fatal(v, valid)
	}
	v, valid = Extract([]byte(`{"capture":{"kernel_packets":"1","kernel_drops":-1,"errors":null},"tcp":{"stream_depth_reached":1.5,"ssn_memcap_drop":18446744073709551616},"decoder":[]}`))
	if !valid || len(v) != 0 {
		t.Fatal("无效值或线程数据被补成总量", v)
	}
	for _, raw := range []string{"null", "[]", "1", "{", strings.Repeat(" ", 1024*1024+1)} {
		if _, ok := Extract([]byte(raw)); ok {
			t.Fatal("接受无效统计")
		}
	}
}

func TestQualitySeparatesLossPolicyGaugesAndUnknownCoverage(t *testing.T) {
	now := time.Date(2026, 10, 17, 9, 0, 0, 0, time.UTC)
	var tr Tracker
	tr.Start("engine_test", strings.Repeat("a", 64), now)
	if r := tr.Snapshot(now, true); r.State != "unavailable" || r.Capture.State != "unknown" {
		t.Fatal(r)
	}
	tr.Observe(sample(now.Add(time.Second), allValues(0)), now.Add(time.Second))
	if r := tr.Snapshot(now.Add(time.Second), true); r.State != "baseline" || r.IntervalStartedAt != nil || r.Counters[0].Delta != nil {
		t.Fatal(r)
	}
	tr.Observe(sample(now.Add(6*time.Second), allValues(0)), now.Add(6*time.Second))
	r := tr.Snapshot(now.Add(7*time.Second), true)
	if r.State != "observed" || r.Capture.State != "no_reported_change" || r.Inspection.State != "no_reported_change" || r.Alerting.State != "no_reported_change" || r.Policy.State != "no_reported_change" || r.IntervalStartedAt == nil {
		t.Fatal(r)
	}
	values := allValues(0)
	values["capture"].(map[string]any)["kernel_drops"] = uint64(2)
	values["tcp"].(map[string]any)["stream_depth_reached"] = uint64(1)
	values["detect"].(map[string]any)["alert_queue_overflow"] = uint64(3)
	values["detect"].(map[string]any)["alerts_suppressed"] = uint64(4)
	values["flow"].(map[string]any)["active"] = uint64(10)
	tr.Observe(sample(now.Add(11*time.Second), values), now.Add(12*time.Second))
	r = tr.Snapshot(now.Add(12*time.Second), true)
	if r.Capture.State != "limited" || r.Inspection.State != "limited" || r.Alerting.State != "limited" || r.Policy.State != "policy_applied" || len(r.Policy.Reasons) != 1 {
		t.Fatal(r)
	}
	// 业务层收到的是副本，不能改写下一次快照或让瞬时活跃流量形成复位。
	*r.Counters[1].Total, *r.Counters[1].Delta = "0", "0"
	*r.SampledAt, *r.IntervalStartedAt = now, now
	r.ResetCounters = append(r.ResetCounters, "invalid")
	values["flow"].(map[string]any)["active"] = uint64(1)
	tr.Observe(sample(now.Add(16*time.Second), values), now.Add(16*time.Second))
	r = tr.Snapshot(now.Add(16*time.Second), true)
	if r.State != "observed" || r.Capture.State != "no_reported_change" || *r.Counters[1].Total != "2" || *r.Counters[1].Delta != "0" || r.Counters[5].Delta != nil {
		t.Fatal(r)
	}
	values = map[string]any{"capture": map[string]any{"kernel_drops": 2}}
	tr.Observe(sample(now.Add(21*time.Second), values), now.Add(21*time.Second))
	r = tr.Snapshot(now.Add(21*time.Second), true)
	if r.Capture.State != "unknown" || r.Inspection.State != "unknown" || r.Alerting.State != "unknown" || r.Policy.State != "unknown" || r.Counters[0].Total != nil {
		t.Fatal(r)
	}
}

func TestQualityResetGapRestartStalenessAndInvalidSamples(t *testing.T) {
	now := time.Date(2026, 10, 17, 9, 0, 0, 0, time.UTC)
	var tr Tracker
	tr.Observe(sample(now, allValues(0)), now)
	if tr.Snapshot(now, true).State != "unavailable" {
		t.Fatal("无运行身份仍接受样本")
	}
	tr.Start("engine_first", "hash", now)
	tr.Observe(sample(now.Add(time.Second), allValues(99)), now.Add(time.Second))
	for _, raw := range [][]byte{[]byte("{"), []byte(`{"event_type":"alert"}`), []byte(`{"event_type":"stats","timestamp":"bad"}`), sample(now.Add(-time.Second), allValues(0)), sample(now.Add(time.Minute), allValues(0)), sample(now.Add(time.Second), allValues(0)), sample(now.Add(2*time.Second), nil), sample(now.Add(2*time.Second), map[string]any{}), []byte(strings.Repeat("a", 1024*1024+1))} {
		tr.Observe(raw, now.Add(2*time.Second))
		if tr.Snapshot(now.Add(2*time.Second), true).State != "baseline" {
			t.Fatal("无效样本刷新观测")
		}
	}
	tr.Observe(sample(now.Add(6*time.Second), allValues(0)), now.Add(6*time.Second))
	r := tr.Snapshot(now.Add(6*time.Second), true)
	if r.State != "counter_reset" || len(r.ResetCounters) != len(definitions)-1 || r.IntervalStartedAt != nil || r.Counters[0].Delta != nil {
		t.Fatal(r)
	}
	if r.Counters[1].ObservedResets == nil || *r.Counters[1].ObservedResets != "1" {
		t.Fatal("原生观测复位缺少持久水位")
	}
	tr.Observe(sample(now.Add(11*time.Second), allValues(1)), now.Add(11*time.Second))
	if tr.Snapshot(now.Add(11*time.Second), true).State != "observed" {
		t.Fatal("复位后不能重新形成基线")
	}
	if *tr.Snapshot(now.Add(11*time.Second), true).Counters[1].ObservedResets != "1" {
		t.Fatal("后续连续样本清除了已观测复位水位")
	}
	tr.Observe(sample(now.Add(32*time.Second), allValues(2)), now.Add(32*time.Second))
	if r = tr.Snapshot(now.Add(32*time.Second), true); r.State != "sample_gap" || r.Counters[0].Delta != nil {
		t.Fatal(r)
	}
	tr.Observe(sample(now.Add(37*time.Second), allValues(3)), now.Add(60*time.Second))
	if r = tr.Snapshot(now.Add(60*time.Second), true); r.State != "stale" || r.Capture.State != "unknown" || r.Counters[0].Delta != nil {
		t.Fatal(r)
	}
	if tr.Snapshot(now.Add(61*time.Second), false).State != "stopped" {
		t.Fatal("停止后仍显示活动质量")
	}
	if tr.Snapshot(now, true).State != "stale" {
		t.Fatal("墙钟回退后仍显示活动质量")
	}
	tr.Start("engine_second", "other_hash", now.Add(62*time.Second))
	tr.Observe(sample(now.Add(37*time.Second), allValues(9)), now.Add(63*time.Second))
	r = tr.Snapshot(now.Add(63*time.Second), true)
	if r.State != "unavailable" || r.EngineRunID != "engine_second" || r.Counters[0].Total != nil {
		t.Fatal("重启沿用旧统计", r)
	}
	tr.Observe(sample(now.Add(63*time.Second), allValues(10)), now.Add(65*time.Second))
	tr.Observe(sample(now.Add(64*time.Second), allValues(11)), now.Add(64*time.Second))
	if tr.Snapshot(now.Add(65*time.Second), true).State != "sample_gap" {
		t.Fatal("接收时钟回退没有隔离区间")
	}
}
