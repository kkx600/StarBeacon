package detectionquality

import (
	"encoding/json"
	"testing"
	"time"
)

func TestQualityReportValidationBindsNativeShapeAndConclusions(t *testing.T) {
	now := time.Date(2026, 10, 18, 0, 0, 0, 123456789, time.UTC)
	var tr Tracker
	tr.Start("engine_validation", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", now)
	assert := func(r Report) {
		t.Helper()
		if err := r.Validate(); err != nil {
			t.Fatalf("拒绝原生快照 %s: %v", r.State, err)
		}
	}
	assert(tr.Snapshot(now, true))
	assert(tr.Snapshot(now, false))
	tr.Observe(sample(now.Add(time.Second), allValues(0)), now.Add(time.Second))
	assert(tr.Snapshot(now.Add(time.Second), true))
	tr.Observe(sample(now.Add(6*time.Second), allValues(2)), now.Add(6*time.Second))
	valid := tr.Snapshot(now.Add(6*time.Second), true)
	assert(valid)
	clone := func() Report {
		var r Report
		raw, _ := json.Marshal(valid)
		if json.Unmarshal(raw, &r) != nil {
			t.Fatal("复制快照失败")
		}
		return r
	}
	str := func(s string) *string { return &s }
	changes := []func(*Report){
		func(r *Report) { r.SchemaVersion = 2 }, func(r *Report) { r.Scope = "flow" }, func(r *Report) { r.Source = "replay" }, func(r *Report) { r.State = "safe" }, func(r *Report) { r.EvaluatedAt = time.Time{} }, func(r *Report) { r.EvaluatedAt = now.Add(time.Hour) },
		func(r *Report) { r.EngineRunID = "forged" }, func(r *Report) { r.EngineRunID = "" }, func(r *Report) { r.ConfigSHA256 = "BAD" }, func(r *Report) { r.ConfigSHA256 = "" }, func(r *Report) { r.Counters = r.Counters[:24] }, func(r *Report) { r.Counters[1] = r.Counters[0] },
		func(r *Report) { r.Counters[0].Layer = "policy" }, func(r *Report) { r.Counters[0].Kind = "gauge" }, func(r *Report) { r.Counters[0].Total = str("01") }, func(r *Report) { r.Counters[0].Total = str("18446744073709551616") }, func(r *Report) { r.Counters[0].Total = str("-1") },
		func(r *Report) { r.Counters[0].Delta = str("3") }, func(r *Report) { r.Counters[0].Total = nil }, func(r *Report) { r.Counters[5].Delta = str("0") }, func(r *Report) { r.Counters[5].ObservedResets = str("0") }, func(r *Report) { r.Counters[0].ObservedResets = str("-1") }, func(r *Report) { r.ResetCounters = nil }, func(r *Report) { r.ResetCounters = []string{"private"} }, func(r *Report) { r.ResetCounters = []string{"flow.active"} }, func(r *Report) { r.ResetCounters = []string{"capture.errors", "capture.errors"} },
		func(r *Report) { r.IntervalStartedAt = nil }, func(r *Report) { r.IntervalStartedAt = r.SampledAt }, func(r *Report) { v := now.Add(-time.Minute); r.IntervalStartedAt = &v }, func(r *Report) { r.ReceivedAt = nil }, func(r *Report) { r.SampledAt = nil },
		func(r *Report) { v := now.Add(-time.Minute); r.ReceivedAt = &v }, func(r *Report) { r.Capture.State = "no_reported_change" }, func(r *Report) { r.Policy.Reasons = []string{"capture.errors"} }, func(r *Report) { r.State = "baseline" }, func(r *Report) { r.State = "unavailable" },
	}
	for i, change := range changes {
		r := clone()
		change(&r)
		if r.Validate() == nil {
			t.Errorf("接受无效投影 #%d", i)
		}
	}
	tr.Observe(sample(now.Add(11*time.Second), allValues(0)), now.Add(11*time.Second))
	assert(tr.Snapshot(now.Add(11*time.Second), true))
	tr.Observe(sample(now.Add(33*time.Second), allValues(1)), now.Add(33*time.Second))
	assert(tr.Snapshot(now.Add(33*time.Second), true))
	assert(tr.Snapshot(now.Add(time.Minute), true))
	assert(tr.Snapshot(now.Add(time.Minute), false))
	// 缺测保留未知，计数精度不经过浮点。
	tr.Observe(sample(now.Add(38*time.Second), map[string]any{"capture": map[string]any{"kernel_drops": uint64(18446744073709551615)}}), now.Add(38*time.Second))
	assert(tr.Snapshot(now.Add(38*time.Second), true))
	if !decimalGreater("10", "9") || !decimalGreater("12", "11") || decimalGreater("1", "2") || decimalGreater("1", "1") {
		t.Fatal("十进制比较不精确")
	}
}
