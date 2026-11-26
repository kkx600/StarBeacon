package decision

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestDecisionAutomationLevelsAndImpact(t *testing.T) {
	levels := []Level{Observe, Approval, Conditional, Full}
	for i, ceiling := range levels {
		for j, scene := range levels {
			settings := AutomationSettings{Ceiling: ceiling}
			if got := settings.Effective(scene); got != levels[min(i, j)] {
				t.Fatalf("全局 %s 场景 %s 实际 %s", ceiling, scene, got)
			}
			settings.Paused = true
			if got := settings.Effective(scene); got != levels[min(i, j, 1)] {
				t.Fatalf("暂停后全局 %s 场景 %s 实际 %s", ceiling, scene, got)
			}
		}
	}
	if DefaultAutomationSettings().Ceiling != Approval {
		t.Fatal("升级默认上限未保护已有自动策略")
	}
	d := Definition{}
	for _, tc := range []struct {
		ip      string
		ttl     int
		managed bool
		small   bool
	}{
		{"192.0.2.2", 7200, false, true}, {"192.0.2.2", 7201, false, false}, {"192.0.2.2", 0, false, false},
		{"192.0.2.2", 60, true, false}, {"172.16.0.1", 60, false, false}, {"100.64.0.1", 60, false, false},
		{"::ffff:192.0.2.2", 60, false, false}, {"::", 60, false, false}, {"fc00::1", 60, false, false},
		{"2001:db8::2", 60, false, true}, {"未知", 60, false, false},
	} {
		if got := d.SmallSourceBlock(tc.ip, tc.ttl, tc.managed); got != tc.small {
			t.Fatal(tc, got)
		}
	}
	d.SmallBlockMaxSeconds = 30
	if d.SmallSourceBlock("192.0.2.2", 60, false) || !d.SmallSourceBlock("192.0.2.2", 30, false) {
		t.Fatal("场景未收紧小影响范围")
	}
	p, _, _ := automaticSource(t)
	for _, level := range []Level{Observe, Approval, "unknown"} {
		p.Definition.AutomationLevel = level
		if p.Definition.Validate() == nil {
			t.Fatal("运行模式与自动化级别冲突", level)
		}
	}
	p.Definition.AutomationLevel = Conditional
	if p.Definition.Validate() != nil || p.Definition.Level() != Conditional || p.Definition.ShadowCriteria().Level() != Observe {
		t.Fatal("条件自动的兼容模式或影子校验输入不正确")
	}
	p.Definition.SmallBlockMaxSeconds = 7201
	if p.Definition.Validate() == nil {
		t.Fatal("场景扩大了默认小影响上限")
	}
}

func TestDecisionAutomationBoundPlanConfirmation(t *testing.T) {
	p, job, now := automaticSource(t)
	source, err := Evaluate(context.Background(), p, job, now)
	if err != nil {
		t.Fatal(err)
	}
	e, err := (Evaluation{SchemaVersion: EvaluationSchema, TenantID: p.TenantID, ID: "evaluation_owned",
		CreatedBy: p.CreatedBy, Policy: p, Result: source, ExpiresAt: now.Add(time.Hour)}).Seal()
	if err != nil {
		t.Fatal(err)
	}
	a := p.Definition.Continuous.Automatic
	request := ResponseRequest{EvaluationSHA256: e.SHA256, SensorID: a.SensorID, RegistrationID: a.RegistrationID,
		ConnectorID: a.ConnectorID, ConfigSHA256: a.ConfigSHA256, TTLSeconds: a.TTLSeconds, Reason: "管理员核对告警后确认", Confirmed: true}
	deadline := now.Add(time.Minute)
	plan := SummarizePlan(Approval, "block_source", job.Evidence.SHA256, *job.Answer)
	plan.ConfirmUntil = &deadline
	run, err := (ContinuousRecord{SchemaVersion: ContinuousSchema, TenantID: p.TenantID, ID: "continuous_owned",
		CreatedBy: p.CreatedBy, EvaluationID: e.ID, EvaluationSHA256: e.SHA256, PolicyID: p.ID,
		PolicyRevision: p.Revision, DefinitionSHA256: p.DefinitionSHA256, TriageID: job.ID, EventID: job.Request.EventID,
		RawSHA256: job.Request.RawSHA256, TargetIP: source.TargetIP, Config: *p.Definition.Continuous, State: "awaiting_confirmation",
		Code: "manual_confirmation_required", CreatedAt: now, ExpiresAt: now.Add(time.Hour), Plan: plan}).Seal()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	intent, err := ConfirmPlanIntent(ctx, e, p, job, job.Evidence, request, run, now)
	if err != nil || intent.TargetIP != source.TargetIP || intent.Reason != request.Reason {
		t.Fatal(intent, err)
	}
	if _, err := ConfirmPlanIntent(ctx, e, p, job, job.Evidence, request, run, deadline); !errors.Is(err, ErrPlanClosed) {
		t.Fatal("到期时刻仍可确认", err)
	}
	changed := request
	changed.TTLSeconds++
	if _, err := ConfirmPlanIntent(ctx, e, p, job, job.Evidence, changed, run, now); !errors.Is(err, ErrSource) {
		t.Fatal("确认时替换期限", err)
	}
	wrong := run
	wrong.EvaluationSHA256 = strings.Repeat("a", 64)
	if _, err := ConfirmPlanIntent(ctx, e, p, job, job.Evidence, request, wrong, now); !errors.Is(err, ErrPermission) {
		t.Fatal("替换评估身份", err)
	}
	wrong.State, wrong.Code, wrong.TaskID = "queued", "policy_authorized", "task_owned"
	if _, err := wrong.Seal(); !errors.Is(err, ErrSource) {
		t.Fatal("待确认方案冒充已经授权的任务", err)
	}
	changedEvidence := job.Evidence
	changedEvidence.SHA256 = strings.Repeat("b", 64)
	if _, err := ConfirmPlanIntent(ctx, e, p, job, changedEvidence, request, run, now); !errors.Is(err, ErrSource) {
		t.Fatal("过期材料获得设备写入资格", err)
	}
}

func TestDecisionPlanManualEvidenceStillRequiresConclusionAndScore(t *testing.T) {
	p, job, _ := automaticSource(t)
	if code := ManualPlanReason(p, job); code != "" {
		t.Fatal("满足条件的证据未通过", code)
	}
	for _, tc := range []struct {
		code   string
		change func()
	}{
		{"conclusion_not_eligible", func() { job.Answer.Verdict = "false_positive" }},
		{"conclusion_not_eligible", func() { job.Answer.Outcome = "unknown" }},
		{"score_below_threshold", func() { job.Answer.Confidence = p.Definition.Threshold / 2 }},
		{"evidence_limited", func() { job.Evidence.Limited = true }},
		{"conclusion_not_eligible", func() { job.Answer = nil }},
	} {
		p, job, _ = automaticSource(t)
		tc.change()
		if code := ManualPlanReason(p, job); code != tc.code {
			t.Fatal("人工确认未保留证据门槛", code, tc.code)
		}
	}
}
