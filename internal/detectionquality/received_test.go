package detectionquality

import (
	"strings"
	"testing"
	"time"
)

func receivedSample(t *testing.T, at time.Time, drops uint64) Report {
	t.Helper()
	var tracker Tracker
	tracker.Start("engine_received", strings.Repeat("a", 64), at.Add(-10*time.Second))
	for _, sampled := range []time.Time{at.Add(-5 * time.Second), at} {
		values := allValues(0)
		values["capture"].(map[string]any)["kernel_drops"] = drops
		tracker.Observe(sample(sampled, values), sampled)
	}
	r := tracker.Snapshot(at, true)
	if r.Validate() != nil {
		t.Fatal("无效原生快照")
	}
	return r
}
func TestQualityReceivedSnapshotsDoNotSkipNativeIntervalsOrClearOnDuplicates(t *testing.T) {
	now := time.Date(2026, 10, 18, 0, 0, 20, 123456789, time.UTC)
	previous := receivedSample(t, now.Add(-10*time.Second), 0)
	current := receivedSample(t, now, 1)
	if *current.Counters[1].Delta != "0" {
		t.Fatal("夹具应为最新五秒未发生增量")
	}
	derived, comparable, err := ReceivedInterval(&previous, current)
	if err != nil || !comparable || derived.State != "observed" || *derived.Counters[1].Delta != "1" || derived.Capture.State != "limited" || !derived.IntervalStartedAt.Equal(*previous.SampledAt) || !derived.SampledAt.Equal(*current.SampledAt) {
		t.Fatal("心跳跳过原生中间增量", derived, err)
	}
	if *current.Counters[1].Delta != "0" || current.Capture.State != "no_reported_change" {
		t.Fatal("派生改变原生输入")
	}
	masked := receivedSample(t, now, 3)
	masked.Counters[1].ObservedResets = strPtr("1")
	resetPrior := receivedSample(t, now.Add(-10*time.Second), 2)
	reset, _, err := ReceivedInterval(&resetPrior, masked)
	if err != nil || reset.State != "counter_reset" || reset.Counters[1].Delta != nil || len(reset.ResetCounters) != 1 {
		t.Fatal("接收之间发生的原生复位被累计增长掩盖", err)
	}
	masked.Counters[1].Total = nil
	masked.Counters[1].Delta = nil
	masked.Capture = Facet{State: "unknown", Reasons: []string{}}
	if lost, _, err := ReceivedInterval(&resetPrior, masked); err != nil || lost.State != "counter_reset" {
		t.Fatal("缺测掩盖了已观察到的复位水位", err)
	}
	masked = receivedSample(t, now, 3)
	masked.Counters[1].ObservedResets = strPtr("0")
	resetPrior.Counters[1].ObservedResets = strPtr("1")
	if _, _, err := ReceivedInterval(&resetPrior, masked); err == nil {
		t.Fatal("同一进程的复位水位回退仍建立区间")
	}
	legacy := receivedSample(t, now, 1)
	legacy.Counters[1].ObservedResets = nil
	if out, _, err := ReceivedInterval(&previous, legacy); err != nil || !out.IntervalStartedAt.Equal(*legacy.IntervalStartedAt) || *out.Counters[1].Delta != "0" {
		t.Fatal("旧端缺少水位却拼接跨心跳区间", err)
	}
	if _, ok, err := ReceivedInterval(&current, current); err != nil || ok {
		t.Fatal("重复快照产生可比较区间", err)
	}
	quiet := receivedSample(t, now.Add(5*time.Second), 1)
	clear, ok, err := ReceivedInterval(&current, quiet)
	if err != nil || !ok || *clear.Counters[1].Delta != "0" {
		t.Fatal("后续累计不变区间未正确计算", err)
	}
	huge := receivedSample(t, now, 18446744073709551615)
	large, ok, err := ReceivedInterval(&previous, huge)
	if err != nil || !ok || *large.Counters[1].Delta != "18446744073709551615" {
		t.Fatal("累计差值失去 uint64 精度")
	}
	for _, which := range []string{"first", "process", "configuration", "baseline", "unavailable"} {
		r := current
		var prior *Report = &previous
		switch which {
		case "first":
			prior = nil
		case "process":
			r.EngineRunID = "engine_other"
		case "configuration":
			r.ConfigSHA256 = strings.Repeat("b", 64)
		case "baseline":
			var tr Tracker
			tr.Start(r.EngineRunID, r.ConfigSHA256, now.Add(-time.Second))
			tr.Observe(sample(now, allValues(0)), now)
			r = tr.Snapshot(now, true)
		case "unavailable":
			prior = &Report{}
		}
		_, ok, err := ReceivedInterval(prior, r)
		if which == "unavailable" {
			if err == nil {
				t.Fatal("接受无效前置水位")
			}
		} else if err != nil || !ok {
			t.Fatal(which, err)
		}
	}
	bad := current
	bad.Counters = nil
	if _, _, err := ReceivedInterval(nil, bad); err == nil {
		t.Fatal("接受无效当前快照")
	}
}

func TestQualityReceivedSnapshotsRespectResetGapMissingCountersAndGauges(t *testing.T) {
	now := time.Date(2026, 10, 18, 0, 0, 30, 0, time.UTC)
	prior := receivedSample(t, now.Add(-25*time.Second), 2)
	current := receivedSample(t, now, 1)
	out, _, err := ReceivedInterval(&prior, current)
	if err != nil || out.State != "counter_reset" || len(out.ResetCounters) != 1 || out.IntervalStartedAt != nil || out.Counters[1].Delta != nil {
		t.Fatal("复位被当作负数增量", err)
	}
	prior = receivedSample(t, now.Add(-25*time.Second), 0)
	out, _, err = ReceivedInterval(&prior, current)
	if err != nil || out.State != "sample_gap" || out.Capture.State != "unknown" || out.IntervalStartedAt != nil {
		t.Fatal("跨越过长接收间隔", err)
	}
	prior = receivedSample(t, now.Add(-10*time.Second), 0)
	prior.ReceivedAt = ptrTime(now.Add(time.Second))
	prior.EvaluatedAt = now.Add(time.Second)
	out, _, err = ReceivedInterval(&prior, current)
	if err != nil || out.State != "sample_gap" {
		t.Fatal("接收时钟回退仍建立区间", err)
	}
	prior = receivedSample(t, now.Add(-10*time.Second), 0)
	// 缺测指标不能借用最新五秒的增量填补跨心跳窗口。
	prior.Counters[1].Total = nil
	prior.Counters[1].Delta = nil
	prior.Capture.State = "unknown"
	out, _, err = ReceivedInterval(&prior, current)
	if err != nil || out.Counters[1].Delta != nil || out.Capture.State != "unknown" {
		t.Fatal("缺测补零", err)
	}
	prior = receivedSample(t, now, 1)
	prior.Counters[5].Total = strPtr("10")
	out, _, err = ReceivedInterval(&prior, receivedSample(t, now.Add(5*time.Second), 1))
	if err != nil || out.Counters[5].Delta != nil || out.State != "observed" {
		t.Fatal("瞬时值下降形成复位或增量")
	}
}
func ptrTime(v time.Time) *time.Time { return &v }
func strPtr(v string) *string        { return &v }
