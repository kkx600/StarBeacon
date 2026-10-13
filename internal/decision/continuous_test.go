package decision

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/triage"
)

func automaticSource(t *testing.T) (Record, triage.Job, time.Time) {
	t.Helper()
	p, j, now := source(t)
	p.Definition.Mode = "automatic"
	p.Definition.CandidateAction = "block_source"
	p.Definition.Expression = "true"
	p.Definition.Continuous = &ContinuousConfig{ProviderID: j.Request.ProviderID, ProviderRevision: 1, Automatic: &AutomaticConfig{SensorID: "sensor_owned", RegistrationID: "epoch_owned", ConnectorID: "connector_owned", ConfigSHA256: strings.Repeat("b", 64), TTLSeconds: 300, CooldownSeconds: 3600, MaxHourlyActions: 10, AcceptUncalibratedScore: true}}
	p.DefinitionSHA256 = Digest(p.Definition)
	j.Answer.References = []string{"source.ip", "rule.id"}
	j.Answer.Recommendation = "block_source"
	return p, j, now
}

func TestAutomaticIntentCannotBypassScoreConclusionSourceOrProtection(t *testing.T) {
	for _, tc := range []struct {
		name, code string
		change     func(*Record, *triage.Job, *triage.Evidence)
	}{
		{"固定阈值不可被 true 绕过", "score_below_threshold", func(p *Record, j *triage.Job, e *triage.Evidence) { j.Answer.Confidence = .7 }},
		{"攻击结果未知", "conclusion_not_eligible", func(p *Record, j *triage.Job, e *triage.Evidence) { j.Answer.Outcome = "unknown" }},
		{"模型仅建议调查", "conclusion_not_eligible", func(p *Record, j *triage.Job, e *triage.Evidence) { j.Answer.Recommendation = "investigate" }},
		{"缺少目标引用", "references_incomplete", func(p *Record, j *triage.Job, e *triage.Evidence) { j.Answer.References = []string{"rule.id"} }},
		{"缺少规则引用", "references_incomplete", func(p *Record, j *triage.Job, e *triage.Evidence) { j.Answer.References = []string{"source.ip"} }},
		{"不同模型修订", "model_binding_changed", func(p *Record, j *triage.Job, e *triage.Evidence) { j.Request.ProviderRevision = 2 }},
		{"不同模型提供方", "model_binding_changed", func(p *Record, j *triage.Job, e *triage.Evidence) { j.Request.ProviderID = "provider_other" }},
		{"执行探针不匹配", "sensor_binding_changed", func(p *Record, j *triage.Job, e *triage.Evidence) {
			p.Definition.Continuous.Automatic.SensorID = "sensor_other"
		}},
		{"注册代次变化", "sensor_binding_changed", func(p *Record, j *triage.Job, e *triage.Evidence) {
			p.Definition.Continuous.Automatic.RegistrationID = "epoch_other"
		}},
		{"当前告警摘要变化", "evidence_changed", func(p *Record, j *triage.Job, e *triage.Evidence) {
			e.RawSHA256 = strings.Repeat("c", 64)
			*e, _ = triage.Seal(*e)
		}},
		{"当前材料损坏", "evidence_changed", func(p *Record, j *triage.Job, e *triage.Evidence) { e.SHA256 = "broken" }},
		{"字段受限", "evidence_limited", func(p *Record, j *triage.Job, e *triage.Evidence) {
			j.Evidence.Limited = true
			j.Evidence, _ = triage.Seal(j.Evidence)
			*e = j.Evidence
		}},
		{"保护网段", "policy_not_matched", func(p *Record, j *triage.Job, e *triage.Evidence) {
			p.Definition.ProtectedPrefixes = []string{"192.0.2.0/24"}
		}},
		{"不匹配表达式", "policy_not_matched", func(p *Record, j *triage.Job, e *triage.Evidence) { p.Definition.Expression = "false" }},
		{"策略已停用", "policy_not_matched", func(p *Record, j *triage.Job, e *triage.Evidence) { p.Active = false }},
		{"材料已过期", "policy_not_matched", func(p *Record, j *triage.Job, e *triage.Evidence) { j.ExpiresAt = p.CreatedAt }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, j, now := automaticSource(t)
			e := j.Evidence
			tc.change(&p, &j, &e)
			p.DefinitionSHA256 = Digest(p.Definition)
			intent, code, err := AutomaticIntent(context.Background(), p, j, e, now)
			if err != nil || code != tc.code || intent.TargetIP != "" {
				t.Fatal(code, err, intent)
			}
		})
	}
	p, j, now := automaticSource(t)
	intent, code, err := AutomaticIntent(context.Background(), p, j, j.Evidence, now)
	if err != nil || code != "policy_authorized" || intent.TargetIP != "192.0.2.10" || intent.TTLSeconds != 300 || intent.ConfigSHA256 != strings.Repeat("b", 64) {
		t.Fatal(code, err, intent)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := AutomaticIntent(ctx, p, j, j.Evidence, now); err == nil {
		t.Fatal("取消后仍产生授权")
	}
	p.Definition.Mode = "shadow"
	p.Definition.Continuous = nil
	p.DefinitionSHA256 = Digest(p.Definition)
	if _, _, err := AutomaticIntent(context.Background(), p, j, j.Evidence, now); err == nil {
		t.Fatal("影子策略获得自动授权")
	}
}

func TestContinuousConfigurationRequiresExplicitBoundedAuthority(t *testing.T) {
	for _, change := range []func(*Definition){
		func(d *Definition) { d.Continuous.ProviderID = "/" }, func(d *Definition) { d.Continuous.ProviderRevision = 0 }, func(d *Definition) { d.Continuous.ProviderRevision = 9007199254740992 },
		func(d *Definition) { d.Continuous.Automatic = nil }, func(d *Definition) { d.Continuous.Automatic.AcceptUncalibratedScore = false }, func(d *Definition) { d.Continuous.Automatic.SensorID = "/" }, func(d *Definition) { d.Continuous.Automatic.RegistrationID = "/" }, func(d *Definition) { d.Continuous.Automatic.ConnectorID = "/" }, func(d *Definition) { d.Continuous.Automatic.ConfigSHA256 = "bad" }, func(d *Definition) { d.Continuous.Automatic.TTLSeconds = 29 }, func(d *Definition) { d.Continuous.Automatic.TTLSeconds = 3601 }, func(d *Definition) { d.Continuous.Automatic.CooldownSeconds = 299 }, func(d *Definition) { d.Continuous.Automatic.CooldownSeconds = 86401 }, func(d *Definition) { d.Continuous.Automatic.MaxHourlyActions = 0 }, func(d *Definition) { d.Continuous.Automatic.MaxHourlyActions = 101 }, func(d *Definition) { d.CandidateAction = "investigate" }, func(d *Definition) { d.Threshold = .49 }, func(d *Definition) { d.Mode = "shadow" }, func(d *Definition) { d.Mode = "approval" },
	} {
		p, _, _ := automaticSource(t)
		change(&p.Definition)
		if p.Definition.Validate() == nil {
			t.Fatal("不完整或越界自动配置获准", p.Definition)
		}
	}
	p, _, _ := automaticSource(t)
	p.Definition.Mode = "approval"
	p.Definition.Continuous.Automatic = nil
	if p.Definition.Validate() != nil {
		t.Fatal("有模型绑定的持续人工确认模式无效")
	}
}

func TestAutomaticTriageRequiresSeparateDataPermissionAndBudget(t *testing.T) {
	p, _, _ := automaticSource(t)
	p.Definition.Continuous.Trigger = &TriageTrigger{Severities: []string{"critical", "high"}, MaxDailyJobs: 100, AllowModelContext: true}
	if p.Definition.Validate() != nil {
		t.Fatal("明确授权的有界自动研判被拒绝")
	}
	for _, trigger := range []TriageTrigger{{}, {Severities: []string{"high"}, MaxDailyJobs: 1}, {Severities: []string{"high", "high"}, MaxDailyJobs: 1, AllowModelContext: true}, {Severities: []string{"unknown"}, MaxDailyJobs: 1, AllowModelContext: true}, {Severities: []string{"high"}, MaxDailyJobs: 0, AllowModelContext: true}, {Severities: []string{"high"}, MaxDailyJobs: 1001, AllowModelContext: true}} {
		p.Definition.Continuous.Trigger = &trigger
		if p.Definition.Validate() == nil {
			t.Fatal("缺少许可或越界自动研判获准", trigger)
		}
	}
	p.Definition.Mode = "approval"
	p.Definition.Continuous.Automatic = nil
	p.Definition.Continuous.Trigger = &TriageTrigger{Severities: []string{"high"}, MaxDailyJobs: 1, AllowModelContext: true}
	if p.Definition.Validate() == nil {
		t.Fatal("人工确认模式获得自动告警提交许可")
	}
}

func TestContinuousArchiveSealsAuthorityAndNeverClaimsDeviceEffect(t *testing.T) {
	p, j, now := automaticSource(t)
	r := ContinuousRecord{SchemaVersion: ContinuousSchema, TenantID: p.TenantID, ID: "continuous_owned", CreatedBy: p.CreatedBy, EvaluationID: "evaluation_owned", EvaluationSHA256: strings.Repeat("c", 64), PolicyID: p.ID, PolicyRevision: p.Revision, DefinitionSHA256: p.DefinitionSHA256, TriageID: j.ID, EventID: j.Request.EventID, RawSHA256: j.Request.RawSHA256, TargetIP: "192.0.2.10", Config: *p.Definition.Continuous, State: "queued", Code: "policy_authorized", TaskID: "task_owned", CreatedAt: now, ExpiresAt: now.Add(180 * 24 * time.Hour)}
	sealed, err := r.Seal()
	if err != nil || sealed.SHA256 == "" {
		t.Fatal(err)
	}
	for _, change := range []func(*ContinuousRecord){func(r *ContinuousRecord) { r.ID = "/" }, func(r *ContinuousRecord) { r.TargetIP = "invalid" }, func(r *ContinuousRecord) { r.TaskID = "" }, func(r *ContinuousRecord) { r.State = "blocked" }, func(r *ContinuousRecord) { r.Code = "device_blocked" }, func(r *ContinuousRecord) { r.ExpiresAt = r.CreatedAt }, func(r *ContinuousRecord) { r.Config.Automatic = nil }, func(r *ContinuousRecord) { r.CreatedAt = r.CreatedAt.In(time.FixedZone("other", 3600)) }} {
		copy := r
		change(&copy)
		if _, err := copy.Seal(); err == nil {
			t.Fatal("越界状态或损坏档案获得资格", copy)
		}
	}
	r.State, r.Code, r.TaskID = "skipped", "target_cooldown", ""
	if _, err := r.Seal(); err != nil {
		t.Fatal(err)
	}
	r.State, r.Code = "awaiting_confirmation", "manual_confirmation_required"
	r.Config.Automatic = nil
	if _, err := r.Seal(); err != nil {
		t.Fatal(err)
	}
	r.Code = "policy_authorized"
	if _, err := r.Seal(); err == nil {
		t.Fatal("人工确认模式冒充自动授权")
	}
}
