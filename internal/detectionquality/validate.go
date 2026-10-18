package detectionquality

import (
	"encoding/hex"
	"errors"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/kkx600/StarBeacon/internal/contract"
)

var ErrReport = errors.New("检测质量观测格式无效")

// Validate 核对原生统计投影的结构与派生结论；它不证明上报设备或统计源可信。
func (r Report) Validate() error {
	if r.SchemaVersion != 1 || r.Scope != "sensor_interval" || r.Source != "suricata_eve_stats" || !slices.Contains([]string{"unavailable", "baseline", "observed", "sample_gap", "counter_reset", "stale", "stopped"}, r.State) || r.EvaluatedAt.Year() < 2000 || r.EvaluatedAt.Year() > 2100 || len(r.Counters) != len(definitions) || r.ResetCounters == nil {
		return ErrReport
	}
	if (r.EngineRunID == "") != (r.ConfigSHA256 == "") || r.EngineRunID != "" && (!contract.ValidID(r.EngineRunID) || !strings.HasPrefix(r.EngineRunID, "engine_")) || r.ConfigSHA256 != "" && !validDigest(r.ConfigSHA256) {
		return ErrReport
	}
	for i, c := range r.Counters {
		d := definitions[i]
		if c.Key != d.Key || c.Kind != d.Kind || c.Layer != d.Layer || c.Kind == "gauge" && (c.Delta != nil || c.ObservedResets != nil) || r.State != "observed" && c.Delta != nil {
			return ErrReport
		}
		for _, n := range []*string{c.Total, c.Delta, c.ObservedResets} {
			if n != nil {
				v, err := strconv.ParseUint(*n, 10, 64)
				if err != nil || strconv.FormatUint(v, 10) != *n {
					return ErrReport
				}
			}
		}
		if c.Delta != nil && (c.Total == nil || decimalGreater(*c.Delta, *c.Total)) {
			return ErrReport
		}
		if r.SampledAt == nil && c.Total != nil {
			return ErrReport
		}
	}
	seen := map[string]bool{}
	for _, key := range r.ResetCounters {
		found := false
		for _, d := range definitions {
			if d.Key == key && d.Kind == "counter" {
				found = true
			}
		}
		if !found || seen[key] {
			return ErrReport
		}
		seen[key] = true
	}
	if r.State == "observed" && (r.SampledAt == nil || r.ReceivedAt == nil || r.IntervalStartedAt == nil || r.EngineRunID == "" || r.ConfigSHA256 == "" || !r.SampledAt.After(*r.IntervalStartedAt) || r.SampledAt.Sub(*r.IntervalStartedAt) > MaxSampleGap || len(r.ResetCounters) != 0) {
		return ErrReport
	}
	if r.State != "observed" && r.IntervalStartedAt != nil && !slices.Contains([]string{"stale", "stopped"}, r.State) {
		return ErrReport
	}
	if (r.SampledAt == nil) != (r.ReceivedAt == nil) {
		return ErrReport
	}
	if r.State != "unavailable" && r.State != "stopped" && (r.SampledAt == nil || r.EngineRunID == "" || r.ConfigSHA256 == "") {
		return ErrReport
	}
	if r.State == "unavailable" && r.SampledAt != nil || r.State == "counter_reset" && len(r.ResetCounters) == 0 || slices.Contains([]string{"baseline", "observed", "sample_gap"}, r.State) && len(r.ResetCounters) > 0 {
		return ErrReport
	}
	if r.SampledAt != nil && (r.SampledAt.Year() < 2000 || r.SampledAt.Year() > 2100 || r.ReceivedAt.Year() < 2000 || r.ReceivedAt.Year() > 2100 || r.SampledAt.After(r.ReceivedAt.Add(5*time.Second))) {
		return ErrReport
	}
	if r.IntervalStartedAt != nil && (r.SampledAt == nil || !r.SampledAt.After(*r.IntervalStartedAt) || r.SampledAt.Sub(*r.IntervalStartedAt) > MaxSampleGap) {
		return ErrReport
	}
	if r.SampledAt != nil && r.State != "stale" && r.State != "stopped" && (r.EvaluatedAt.Before(r.SampledAt.Add(-5*time.Second)) || r.EvaluatedAt.Before(r.ReceivedAt.Add(-5*time.Second)) || r.EvaluatedAt.Sub(*r.SampledAt) > MaxSampleGap || r.EvaluatedAt.Sub(*r.ReceivedAt) > MaxSampleGap) {
		return ErrReport
	}
	for _, pair := range []struct {
		got   Facet
		layer string
	}{{r.Capture, "capture"}, {r.Inspection, "inspection"}, {r.Alerting, "alerting"}, {r.Policy, "policy"}} {
		if !reflect.DeepEqual(pair.got, facet(r, pair.layer)) {
			return ErrReport
		}
	}
	return nil
}

func decimalGreater(a, b string) bool { return len(a) > len(b) || len(a) == len(b) && a > b }
func validDigest(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == 32 && hex.EncodeToString(b) == s
}
