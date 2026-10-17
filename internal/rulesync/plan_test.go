package rulesync

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPlanInputBoundaries(t *testing.T) {
	base := Spec{Name: "办公网规则同步", SensorID: "sensor_office", RegistrationID: "registration_office", PackageID: "rules_office", PackageRevision: 1, PositiveSampleID: "sample_hit", NegativeSampleID: "sample_miss", IntervalSeconds: 30}
	if base.Validate() != nil {
		t.Fatal("合法计划被拒绝")
	}
	for _, change := range []func(*Spec){
		func(s *Spec) { s.Name = "" }, func(s *Spec) { s.Name = " 名称" }, func(s *Spec) { s.Name = "名称\n" }, func(s *Spec) { s.Name = strings.Repeat("名", 129) }, func(s *Spec) { s.Name = string([]byte{255}) },
		func(s *Spec) { s.SensorID = "a/b" }, func(s *Spec) { s.RegistrationID = "" }, func(s *Spec) { s.PackageID = "" }, func(s *Spec) { s.PackageRevision = 0 }, func(s *Spec) { s.PackageRevision = MaxRevision + 1 }, func(s *Spec) { s.PositiveSampleID = "" }, func(s *Spec) { s.NegativeSampleID = s.PositiveSampleID }, func(s *Spec) { s.NegativeSampleID = "bad/id" }, func(s *Spec) { s.IntervalSeconds = 29 }, func(s *Spec) { s.IntervalSeconds = 3601 },
	} {
		v := base
		change(&v)
		if v.Validate() == nil {
			t.Fatal("非法计划通过", v)
		}
	}
	for _, c := range []Change{{ID: "sync_office", Spec: base}, {ID: "sync_office", ExpectedRevision: MaxRevision - 1, Spec: base}} {
		if c.Validate() != nil {
			t.Fatal("有效修订被拒绝")
		}
	}
	for _, c := range []Change{{ID: "", Spec: base}, {ID: "sync_office", ExpectedRevision: -1, Spec: base}, {ID: "sync_office", ExpectedRevision: MaxRevision, Spec: base}} {
		if c.Validate() == nil {
			t.Fatal("非法修订被接受")
		}
	}
	for i, want := range []string{"rules.validate", "rules.replay", "rules.replay", "rules.apply"} {
		if Kind(i) != want || State(i) == "blocked" {
			t.Fatal("阶段映射错误")
		}
	}
	for _, i := range []int{-1, 4, 100} {
		if Kind(i) != "" || State(i) != "blocked" {
			t.Fatal("阶段越界")
		}
	}
	for _, s := range []string{"paused", "blocked", "succeeded"} {
		if !Terminal(s) {
			t.Fatal("终态错误")
		}
	}
	if Terminal("running") {
		t.Fatal("未结束状态误判")
	}
}

func TestAppliedRequiresActualReadback(t *testing.T) {
	sha := strings.Repeat("a", 64)
	v := map[string]any{"sha256": sha, "active_sha256": sha, "syntax": "passed", "engine_ruleset": []any{map[string]any{"rules_loaded": 1, "rules_failed": 0}}, "applied_at": "2026-10-17T01:00:00Z"}
	raw, _ := json.Marshal(v)
	if !Applied(raw, sha) {
		t.Fatal("实际回读被拒绝")
	}
	for key, bad := range map[string]any{"sha256": "foreign", "active_sha256": "foreign", "syntax": "failed", "engine_ruleset": nil, "applied_at": "invalid"} {
		copy := map[string]any{}
		for k, x := range v {
			copy[k] = x
		}
		copy[key] = bad
		raw, _ := json.Marshal(copy)
		if Applied(raw, sha) {
			t.Fatal("不完整回读通过", key)
		}
	}
	if Applied([]byte(`{`), sha) || Applied(raw, "short") {
		t.Fatal("损坏回读通过")
	}
	for _, stats := range []any{[]any{}, []any{map[string]any{"rules_loaded": 1}}, []any{map[string]any{"rules_loaded": 0, "rules_failed": 0}}, []any{map[string]any{"rules_loaded": 1, "rules_failed": 1}}} {
		v["engine_ruleset"] = stats
		raw, _ := json.Marshal(v)
		if Applied(raw, sha) {
			t.Fatal("无效装载统计通过")
		}
	}
}
