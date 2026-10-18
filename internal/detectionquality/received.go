package detectionquality

import (
	"strconv"
)

// ReceivedInterval 以相邻已接收原生快照的累计值计算区间，避免心跳跳过五秒增量。
// 只跨同一进程与配置比较；缺测不补零，复位及超过二十秒的接收区间保持未知。
func ReceivedInterval(previous *Report, current Report) (Report, bool, error) {
	if err := current.Validate(); err != nil {
		return current, false, err
	}
	if previous == nil {
		return current, true, nil
	}
	if err := previous.Validate(); err != nil {
		return current, false, err
	}
	if previous.EngineRunID != current.EngineRunID || previous.ConfigSHA256 != current.ConfigSHA256 || previous.SampledAt == nil || current.SampledAt == nil || current.State != "observed" {
		return current, true, nil
	}
	// 重复心跳不能把先前跨快照的非零增量误清除，也不能重复计算同一个样本。
	if !current.SampledAt.After(*previous.SampledAt) {
		return current, false, nil
	}
	// 旧报告缺少复位水位时只采用其原生区间，不能假定中间未发生复位。
	for i, c := range current.Counters {
		if c.Kind == "counter" && (c.ObservedResets == nil || previous.Counters[i].ObservedResets == nil) {
			return current, true, nil
		}
	}
	out := current
	out.Counters = append([]Counter{}, current.Counters...)
	out.ResetCounters = []string{}
	started := *previous.SampledAt
	out.IntervalStartedAt = &started
	if current.SampledAt.Sub(*previous.SampledAt) > MaxSampleGap || current.ReceivedAt.Before(*previous.ReceivedAt) || current.ReceivedAt.Sub(*previous.ReceivedAt) > MaxSampleGap {
		out.State = "sample_gap"
	}
	for i, c := range out.Counters {
		out.Counters[i].Delta = nil
		prior := previous.Counters[i]
		if c.Kind != "counter" {
			continue
		}
		resets, _ := strconv.ParseUint(*c.ObservedResets, 10, 64)
		oldResets, _ := strconv.ParseUint(*prior.ObservedResets, 10, 64)
		if resets < oldResets {
			return current, false, ErrReport
		}
		if c.Total == nil || prior.Total == nil {
			if resets > oldResets {
				out.ResetCounters = append(out.ResetCounters, c.Key)
			}
			continue
		}
		total, _ := strconv.ParseUint(*c.Total, 10, 64)
		before, _ := strconv.ParseUint(*prior.Total, 10, 64)
		if total < before || resets > oldResets {
			out.ResetCounters = append(out.ResetCounters, c.Key)
		} else {
			delta := strconv.FormatUint(total-before, 10)
			out.Counters[i].Delta = &delta
		}
	}
	if len(out.ResetCounters) > 0 {
		out.State = "counter_reset"
	}
	if out.State != "observed" {
		out.IntervalStartedAt = nil
		for i := range out.Counters {
			out.Counters[i].Delta = nil
		}
	}
	out.Capture, out.Inspection, out.Alerting, out.Policy = facet(out, "capture"), facet(out, "inspection"), facet(out, "alerting"), facet(out, "policy")
	return out, true, out.Validate()
}
