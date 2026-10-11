package decision

import (
	"context"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/llm"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/triage"
)

func definition() Definition {
	return Definition{SchemaVersion: Schema, Mode: "shadow", Expression: `confidence >= threshold && verdict == "confirmed" && reference_count >= 1`, Threshold: .8, CandidateAction: "investigate", MaxAgeSeconds: 3600, ProtectedPrefixes: []string{}}
}

func source(t *testing.T) (Record, triage.Job, time.Time) {
	t.Helper()
	now := time.Date(2026, 10, 10, 2, 0, 0, 0, time.UTC)
	policy := Record{TenantID: "tenant_owned", ID: "policy_owned", Revision: 1, Name: "攻击尝试影子策略", Active: true, CreatedBy: "user_owned", CreatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(179 * 24 * time.Hour), Definition: definition()}
	policy.DefinitionSHA256 = Digest(policy.Definition)
	alert := model.Alert{EventID: "event_owned", RawSHA256: strings.Repeat("a", 64), SensorID: "sensor_owned", RegistrationID: "epoch_owned", Timestamp: now.Add(-time.Minute), ObservedAt: now.Add(-time.Minute)}
	alert.Event.Kind = "alert"
	alert.Source.IP = "192.0.2.10"
	alert.Network.Protocol = "http"
	alert.Rule.ID = "1000001"
	evidence, err := triage.Freeze(alert)
	if err != nil {
		t.Fatal(err)
	}
	job := triage.Job{ID: "triage_owned", Request: triage.Request{EventID: alert.EventID, RawSHA256: alert.RawSHA256, ProviderID: "provider_owned", ProviderRevision: 1, AllowContext: true}, State: "succeeded", Template: triage.TemplateVersion, Evidence: evidence, Answer: &triage.Answer{Verdict: "confirmed", Outcome: "attempt", Confidence: .87, Reason: "规则字段支持攻击尝试，仍需独立业务证据", References: []string{"rule.id"}, CounterEvidence: []string{"授权测试未排除"}, Missing: []string{"终端证据"}, Recommendation: "investigate", NeedsReview: true}, Result: llm.Result{State: "succeeded"}, ConfidenceKind: "self_reported", CreatedAt: now.Add(-30 * time.Second), ExpiresAt: now.Add(179 * 24 * time.Hour)}
	return policy, job, now
}

func TestShadowPolicyPreservesScoresSourcesAndNoExecutionAuthority(t *testing.T) {
	p, job, now := source(t)
	result, err := Evaluate(context.Background(), p, job, now)
	if err != nil || result.Status != "matched" || result.ExecutionAuthorized || result.Confidence == nil || *result.Confidence != .87 || result.Cost == nil || *result.Cost > MaxCost || result.ConfidenceKind != "self_reported" || result.PolicyRevision != 1 || result.DefinitionSHA256 != p.DefinitionSHA256 || result.EvidenceSHA256 != job.Evidence.SHA256 || result.ProviderRevision != 1 || len(result.Limitations) != len(job.Evidence.Limitations)+2 {
		t.Fatal("影子评估丢失来源、分数语义或执行边界", result, err)
	}
	p.Definition.Threshold = .99
	p.DefinitionSHA256 = Digest(p.Definition)
	result, err = Evaluate(context.Background(), p, job, now)
	if err != nil || result.Status != "not_matched" || result.ExecutionAuthorized {
		t.Fatal("阈值未参与实际计算", result, err)
	}
	p.Definition.Expression = "1 / 0 == 0"
	p.DefinitionSHA256 = Digest(p.Definition)
	result, err = Evaluate(context.Background(), p, job, now)
	if err != nil || result.Status != "abstained" || len(result.Reasons) != 1 || result.Reasons[0] != "expression_evaluation_failed" {
		t.Fatal("表达式运行失败未拒绝判断", result, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Evaluate(ctx, p, job, now); !errors.Is(err, context.Canceled) {
		t.Fatal("已取消请求继续求值", err)
	}
}

func TestShadowPolicyAbstainsForInactiveIncompleteExpiredAndStaleSources(t *testing.T) {
	for _, kind := range []string{"inactive", "queued", "failed", "result_failed", "cancelled", "missing_answer", "expired", "stale", "future"} {
		t.Run(kind, func(t *testing.T) {
			p, job, now := source(t)
			switch kind {
			case "inactive":
				p.Active = false
			case "queued", "failed":
				job.State = kind
			case "result_failed":
				job.Result.State = "failed"
			case "cancelled":
				job.CancelRequested = true
			case "missing_answer":
				job.Answer = nil
			case "expired":
				job.ExpiresAt = now
			case "stale":
				now = now.Add(2 * time.Hour)
			case "future":
				now = now.Add(-2 * time.Minute)
			}
			result, err := Evaluate(context.Background(), p, job, now)
			if err != nil || result.Status != "abstained" || result.Confidence != nil || result.Cost != nil || len(result.Reasons) == 0 || result.ExecutionAuthorized {
				t.Fatal("不完整来源仍产生候选或伪造数值", result, err)
			}
		})
	}
}

func TestShadowPolicyRejectsCorruptionAndFalseCalibration(t *testing.T) {
	for _, kind := range []string{"policy", "time", "job", "request", "template", "event", "raw", "calibrated", "evidence", "seal", "answer"} {
		t.Run(kind, func(t *testing.T) {
			p, job, now := source(t)
			switch kind {
			case "policy":
				p.DefinitionSHA256 = strings.Repeat("b", 64)
			case "time":
				now = time.Time{}
			case "job":
				job.ID = "/"
			case "request":
				job.Request.AllowContext = false
			case "template":
				job.Template = "untrusted"
			case "event":
				job.Request.EventID = "event_foreign"
			case "raw":
				job.Request.RawSHA256 = strings.Repeat("c", 64)
			case "calibrated":
				job.ConfidenceKind = "calibrated"
			case "evidence":
				job.Evidence.Facts = nil
			case "seal":
				job.Evidence.SHA256 = strings.Repeat("d", 64)
			case "answer":
				job.Answer.Outcome = "success"
			}
			if _, err := Evaluate(context.Background(), p, job, now); !errors.Is(err, ErrSource) {
				t.Fatal("来源损坏或自报校准被接受", err)
			}
		})
	}
}

func TestShadowPolicyChecksSourceAddressAndProtectedPrefixes(t *testing.T) {
	for _, address := range []string{"192.0.2.10", "2001:db8::10", "127.0.0.1", "::", "224.0.0.1", "::ffff:192.0.2.10", "invalid", ""} {
		t.Run(address, func(t *testing.T) {
			p, job, now := source(t)
			p.Definition.CandidateAction = "block_source"
			p.Definition.ProtectedPrefixes = []string{"192.0.2.0/24", "2001:db8::/32"}
			p.DefinitionSHA256 = Digest(p.Definition)
			for i := range job.Evidence.Facts {
				if job.Evidence.Facts[i].ID == "source.ip" {
					job.Evidence.Facts[i].Value = address
				}
			}
			if address == "" {
				job.Evidence.Facts = append(job.Evidence.Facts[:3:3], job.Evidence.Facts[4:]...)
			}
			var err error
			job.Evidence, err = triage.Seal(job.Evidence)
			if err != nil {
				t.Fatal(err)
			}
			result, err := Evaluate(context.Background(), p, job, now)
			want := "abstained"
			if address == "192.0.2.10" || address == "2001:db8::10" {
				want = "protected"
			}
			if err != nil || result.Status != want || result.ExecutionAuthorized || len(result.Reasons) != 1 {
				t.Fatal(result, err)
			}
		})
	}
	p, job, now := source(t)
	p.Definition.CandidateAction = "block_source"
	p.DefinitionSHA256 = Digest(p.Definition)
	result, err := Evaluate(context.Background(), p, job, now)
	if err != nil || result.Status != "matched" || result.TargetIP != "192.0.2.10" || result.ExecutionAuthorized {
		t.Fatal("影子目标被误作封禁授权", result, err)
	}
}

func TestPolicyExpressionTypesRecursionMacrosAndCostLimits(t *testing.T) {
	for _, expression := range []string{"", "true ", "1", "confidence", "unknown > 0", `confidence >= "1"`, "[1].all(x, x > 0)", strings.Repeat("x", 2049), strings.Repeat("(", 40) + "true" + strings.Repeat(")", 40)} {
		if _, err := Compile(expression); !errors.Is(err, ErrInput) {
			t.Fatal("未拒绝类型、宏或预算越界", expression, err)
		}
	}
	p, job, now := source(t)
	p.Definition.Expression = "protocol.matches('" + strings.Repeat("a", 1800) + "')"
	p.DefinitionSHA256 = Digest(p.Definition)
	for i := range job.Evidence.Facts {
		if job.Evidence.Facts[i].ID == "network.protocol" {
			job.Evidence.Facts[i].Value = strings.Repeat("a", 2048)
		}
	}
	var err error
	job.Evidence, err = triage.Seal(job.Evidence)
	if err != nil {
		t.Fatal(err)
	}
	result, err := Evaluate(context.Background(), p, job, now)
	if err != nil || result.Status != "abstained" || len(result.Reasons) != 1 || result.Reasons[0] != "expression_evaluation_failed" {
		t.Fatal("CEL 计算成本未受限", result, err)
	}
}

func TestPolicyDefinitionsVersionsAndDirectoryBounds(t *testing.T) {
	for _, alter := range []func(*Definition){
		func(d *Definition) { d.SchemaVersion = "invalid" }, func(d *Definition) { d.Mode = "invalid" },
		func(d *Definition) { d.Threshold = 0 }, func(d *Definition) { d.Threshold = 1.1 }, func(d *Definition) { d.Threshold = math.NaN() }, func(d *Definition) { d.Threshold = math.Inf(1) },
		func(d *Definition) { d.CandidateAction = "isolate_host" }, func(d *Definition) { d.MaxAgeSeconds = 59 }, func(d *Definition) { d.MaxAgeSeconds = 86401 },
		func(d *Definition) { d.ProtectedPrefixes = nil }, func(d *Definition) { d.ProtectedPrefixes = make([]string, 33) },
		func(d *Definition) { d.ProtectedPrefixes = []string{"bad"} }, func(d *Definition) { d.ProtectedPrefixes = []string{"192.0.2.1/24"} },
		func(d *Definition) { d.ProtectedPrefixes = []string{"::ffff:192.0.2.0/120"} }, func(d *Definition) { d.ProtectedPrefixes = []string{"192.0.2.0/24", "192.0.2.0/24"} },
		func(d *Definition) { d.Expression = "confidence" },
	} {
		d := definition()
		alter(&d)
		if !errors.Is(d.Validate(), ErrInput) {
			t.Fatal("无效策略定义被接受", d)
		}
	}
	for _, mode := range []string{"approval", "automatic"} {
		d := definition()
		d.Mode = mode
		if !errors.Is(d.Validate(), ErrMode) {
			t.Fatal("未获得资格的执行模式被接受")
		}
	}
	p, _, _ := source(t)
	if p.Validate() != nil {
		t.Fatal("有效策略修订被拒绝")
	}
	for _, alter := range []func(*Record){func(r *Record) { r.TenantID = "/" }, func(r *Record) { r.ID = "/" }, func(r *Record) { r.CreatedBy = "/" }, func(r *Record) { r.Revision = 0 }, func(r *Record) { r.Revision = MaxRevision + 1 }, func(r *Record) { r.Name = " " }, func(r *Record) { r.Description = "\x00" }, func(r *Record) { r.CreatedAt = time.Time{} }, func(r *Record) { r.ExpiresAt = r.CreatedAt }, func(r *Record) { r.DefinitionSHA256 = "bad" }} {
		r := p
		alter(&r)
		if r.Validate() == nil {
			t.Fatal("无效修订被接受", r)
		}
	}
	on, off := true, false
	c := Change{ID: p.ID, Name: p.Name, Active: &on, Definition: p.Definition}
	if c.Validate() != nil {
		t.Fatal("有效提交被拒绝")
	}
	for _, alter := range []func(*Change){func(c *Change) { c.ID = "/" }, func(c *Change) { c.ExpectedRevision = -1 }, func(c *Change) { c.ExpectedRevision = MaxRevision }, func(c *Change) { c.Name = "" }, func(c *Change) { c.Name = strings.Repeat("a", 129) }, func(c *Change) { c.Name = "\xff" }, func(c *Change) { c.Description = "a\nb" }, func(c *Change) { c.Active = nil }, func(c *Change) { c.Active = &off }} {
		x := c
		alter(&x)
		if x.Validate() == nil {
			t.Fatal("无效提交被接受", x)
		}
	}
	for _, q := range []ListQuery{{Limit: 0}, {Limit: 101}, {Limit: 20, Cursor: "/"}, {Limit: 20, Keyword: " bad"}, {Limit: 20, Active: "yes"}} {
		if q.Validate() == nil {
			t.Fatal("目录预算或字段未校验")
		}
	}
	if (ListQuery{Limit: 100, Cursor: p.ID, Keyword: "影子", Active: "false"}).Validate() != nil {
		t.Fatal("有效目录被拒绝")
	}
	if (EvaluateRequest{ExpectedRevision: 1, TriageID: "triage_owned"}).Validate() != nil {
		t.Fatal("有效材料引用被拒绝")
	}
	for _, r := range []EvaluateRequest{{ExpectedRevision: 0, TriageID: "triage_owned"}, {ExpectedRevision: MaxRevision + 1, TriageID: "triage_owned"}, {ExpectedRevision: 1, TriageID: "/"}} {
		if r.Validate() == nil {
			t.Fatal("无效材料引用被接受")
		}
	}
}
