package playbook

import (
	"strings"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/model"
)

func TestPublishRequiresSeparateProtectionApprovalVerificationAndExpiry(t *testing.T) {
	b := PolicyBinding{ID: "review_owned", Revision: 1}
	d := Definition{Name: "网关响应", Steps: []Step{
		{Kind: "trigger", Name: "告警", MinimumSeverity: "high"},
		{Kind: "protection", Name: "检查名单"}, {Kind: "approval", Name: "人工确认"}, {Kind: "gateway", Name: "网关策略", Gateway: &b},
		{Kind: "verify", Name: "核验回执"}, {Kind: "compensate", Name: "记录到期"},
	}}
	if !d.ValidDraft() || len(d.Issues()) != 0 {
		t.Fatal("有效的限时动作闭环未通过")
	}
	for _, i := range []int{1, 2, 4, 5} {
		unsafe := d
		unsafe.Steps = append(append([]Step{}, d.Steps[:i]...), d.Steps[i+1:]...)
		if !unsafe.ValidDraft() || len(unsafe.Issues()) == 0 {
			t.Fatalf("缺少第 %d 个保护步骤仍可发布", i)
		}
	}
	unsafe := d
	unsafe.Steps = append(append([]Step{}, d.Steps...), d.Steps[3])
	if len(unsafe.Issues()) == 0 {
		t.Fatal("第二个动作沿用了第一个动作的确认")
	}
	unsafe.Steps[6].Kind = "shell"
	if unsafe.ValidDraft() {
		t.Fatal("接受了未登记的步骤类型")
	}
	unsafe.Steps[6] = d.Steps[0]
	if unsafe.ValidDraft() {
		t.Fatal("接受了第二个触发步骤")
	}
	a := model.Alert{EventID: strings.Repeat("a", 64), RawSHA256: strings.Repeat("b", 64), SensorID: "sensor_owned", RegistrationID: "registration_owned",
		Severity: "high", Source: model.Endpoint{IP: "::ffff:192.0.2.80"}, Destination: model.Endpoint{IP: "192.0.2.90"}}
	a.Event.Kind = "alert"
	source, err := BindAlert(d, a)
	if err != nil {
		t.Fatal(err)
	}
	ip, _, err := source.Endpoints()
	if err != nil || ip != "192.0.2.80" {
		t.Fatal("未规范化受检地址", ip, err)
	}
	a.Severity = "low"
	if _, err := BindAlert(d, a); err != ErrSource {
		t.Fatal("低于门槛仍可启动", err)
	}
	source.DestinationIP = "bad.ip"
	if _, _, err := source.Endpoints(); err != ErrSource {
		t.Fatal("无效地址通过保护检查")
	}
}

func TestStepKeyAndRunTerminalState(t *testing.T) {
	key := StepKey("pbr_owned", 2)
	if id, index, reserved, err := ParseStepKey(key); id != "pbr_owned" || index != 2 || !reserved || err != nil {
		t.Fatal(id, index, reserved, err)
	}
	for _, key := range []string{"pb_step_broken", "pb_step_pbr_owned_00", "pb_step_pbr_owned_16", "pb_step_bad_1"} {
		if _, _, reserved, err := ParseStepKey(key); !reserved || err != ErrInput {
			t.Fatal(key, reserved, err)
		}
	}
	if _, _, reserved, err := ParseStepKey("original_response"); reserved || err != nil {
		t.Fatal("干扰原业务请求")
	}
	now := time.Now().UTC()
	r := Run{ID: "pbr_owned", Definition: Definition{Steps: []Step{{Kind: "trigger"}, {Kind: "approval"}, {Kind: "gateway"}}},
		Results: []Result{{Kind: "trigger", At: now}, {Kind: "approval", At: now}}}
	r.RefreshState()
	if r.StepKey != key || !r.ApprovalActive(now) || r.ApprovalActive(now.Add(ApprovalWindow)) {
		t.Fatal("操作键或期限错误", r)
	}
	r.Results = append(r.Results, Result{Kind: "gateway", Outcome: "authorization_denied"})
	r.RefreshState()
	if r.State != "stopped" || r.StepKey != "" {
		t.Fatal("失败后的编排继续推进", r)
	}
	r.Results[2].Outcome = "authorized"
	r.RefreshState()
	if r.State != "completed" {
		t.Fatal("已完成步骤未到达结束状态", r)
	}
}

func TestDraftKeepsIncompleteBindingsWithPublicationIssues(t *testing.T) {
	trigger := Step{Kind: "trigger", Name: "告警"}
	model := ModelBinding{ID: "provider_owned", Revision: 1, MinimumConfidence: .9}
	for _, tc := range []struct {
		step  Step
		issue string
	}{
		{Step{Kind: "condition", Name: "条件"}, "triage_required"},
		{Step{Kind: "triage", Name: "研判"}, "model_binding"},
		{Step{Kind: "plugin", Name: "联动"}, "plugin_binding"},
		{Step{Kind: "gateway", Name: "网关"}, "gateway_binding"},
		{Step{Kind: "approval", Name: "确认"}, "unbound_guard"},
	} {
		d := Definition{Name: "待补配的方案", Steps: []Step{trigger, tc.step}}
		if !d.ValidDraft() || len(d.Issues()) == 0 || d.Issues()[0].Code != tc.issue {
			t.Fatal("草稿校验没有指出缺项", tc, d.Issues())
		}
	}
	d := Definition{Name: "未经发布的模型草稿", Steps: []Step{trigger, {Kind: "triage", Name: "研判", Model: &model}}}
	if len(d.Issues()) != 0 {
		t.Fatal(d.Issues())
	}
	model.MinimumConfidence = 0
	if len(d.Issues()) != 1 {
		t.Fatal("缺省门槛被当作已授权")
	}
	d.Steps[1].MinimumSeverity = "high"
	if d.ValidDraft() {
		t.Fatal("触发范围被放入了模型步骤")
	}
	start := Start{Revision: Revision{Revision: 1, SHA256: strings.Repeat("a", 64)}, EventID: strings.Repeat("b", 64), RawSHA256: strings.Repeat("c", 64)}
	if !start.Valid() {
		t.Fatal("有效的发布身份被拒绝")
	}
	start.Revision.Revision = MaxRevision + 1
	if start.Valid() {
		t.Fatal("接受了超出上限的修订")
	}
}
