package enginehealth

import (
	"strings"
	"testing"
	"time"
)

func TestGateRequiresFreshNativeObservationAfterRelease(t *testing.T) {
	now := time.Now().UTC()
	after := now.Add(-time.Minute)
	sha := strings.Repeat("a", 64)
	good := Report{SchemaVersion: Schema, State: "observed", Source: "registered_process", ObservedAt: now, PID: 12, StartedAt: after.Add(-time.Minute), ConfigSHA256: strings.Repeat("b", 64), RulesSHA256: sha, FileRuleCount: 3, RulesLoaded: 3}
	if code := Gate(nil, sha, now, after); code != "waiting_for_engine" {
		t.Fatal("缺报被当作健康", code)
	}
	for _, tc := range []struct {
		name, want string
		change     func(*Report)
	}{
		{"原生观测", "", func(r *Report) {}},
		{"托管引擎", "", func(r *Report) { r.Source = "managed_process" }},
		{"未知格式", "waiting_for_engine", func(r *Report) { r.SchemaVersion = "future" }},
		{"缺观测时间", "waiting_for_engine", func(r *Report) { r.ObservedAt = time.Time{} }},
		{"发布前旧观测", "waiting_for_engine", func(r *Report) { r.ObservedAt = after.Add(-time.Nanosecond) }},
		{"过期观测", "waiting_for_engine", func(r *Report) { r.ObservedAt = now.Add(-91 * time.Second) }},
		{"未来观测", "waiting_for_engine", func(r *Report) { r.ObservedAt = now.Add(6 * time.Second) }},
		{"正在执行", "waiting_for_engine", func(r *Report) { r.State = "pending" }},
		{"尚未配置", "waiting_for_engine", func(r *Report) { r.State = "unconfigured" }},
		{"原生失败", "engine_health_failed", func(r *Report) { r.State = "unavailable" }},
		{"未知状态", "engine_health_failed", func(r *Report) { r.State = "unknown" }},
		{"残留错误", "engine_health_failed", func(r *Report) { r.Code = "engine_ruleset_mismatch" }},
		{"未绑定进程", "engine_health_failed", func(r *Report) { r.Source = "eve_reader_only" }},
		{"无进程标识", "engine_health_failed", func(r *Report) { r.PID = 0 }},
		{"无启动时间", "engine_health_failed", func(r *Report) { r.StartedAt = time.Time{} }},
		{"启动时间不符", "engine_health_failed", func(r *Report) { r.StartedAt = now.Add(time.Second) }},
		{"配置摘要无效", "engine_health_failed", func(r *Report) { r.ConfigSHA256 = "invalid" }},
		{"规则摘要变化", "engine_health_failed", func(r *Report) { r.RulesSHA256 = strings.Repeat("c", 64) }},
		{"空规则文件", "engine_health_failed", func(r *Report) { r.FileRuleCount = 0 }},
		{"装载数量不符", "engine_health_failed", func(r *Report) { r.RulesLoaded++ }},
		{"装载失败", "engine_health_failed", func(r *Report) { r.RulesFailed = 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := good
			tc.change(&r)
			if got := Gate(&r, sha, now, after); got != tc.want {
				t.Fatal(got, tc.want)
			}
		})
	}
	if Gate(&good, "invalid", now, after) != "engine_health_failed" {
		t.Fatal("接受无效批准摘要")
	}
	good.ObservedAt = now.Add(-90 * time.Second)
	if Gate(&good, sha, now, good.ObservedAt) != "" {
		t.Fatal("新鲜度边界未包含")
	}
}
