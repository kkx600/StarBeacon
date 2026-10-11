package decision

import (
	"context"
	"encoding/json"
	"math"
	"testing"
	"time"
)

func archived(t *testing.T) Evaluation {
	t.Helper()
	p, job, now := source(t)
	r, err := Evaluate(context.Background(), p, job, now)
	if err != nil {
		t.Fatal(err)
	}
	e, err := (Evaluation{SchemaVersion: EvaluationSchema, TenantID: p.TenantID, ID: "evaluation_owned", CreatedBy: "user_owned", ExpiresAt: now.Add(180 * 24 * time.Hour), Policy: p, Result: r}).Seal()
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestEvaluationArchiveSealsHistoricalPolicyAndAllResultStates(t *testing.T) {
	e := archived(t)
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	var roundtrip Evaluation
	if json.Unmarshal(raw, &roundtrip) != nil {
		t.Fatal("档案无法解码")
	}
	sealed, err := roundtrip.Seal()
	if err != nil || sealed.SHA256 != e.SHA256 || sealed.Result.ExecutionAuthorized {
		t.Fatal("档案来源或执行边界不同", err)
	}
	for _, kind := range []string{"false", "inactive", "protected", "runtime_error"} {
		p, job, now := source(t)
		switch kind {
		case "false":
			p.Definition.Expression = "false"
		case "inactive":
			p.Active = false
		case "protected":
			p.Definition.CandidateAction = "block_source"
			p.Definition.ProtectedPrefixes = []string{"192.0.2.0/24"}
		case "runtime_error":
			p.Definition.Expression = "1 / 0 == 0"
		}
		p.DefinitionSHA256 = Digest(p.Definition)
		r, err := Evaluate(context.Background(), p, job, now)
		if err != nil {
			t.Fatal(err)
		}
		e.Policy, e.Result = p, r
		if _, err = e.Seal(); err != nil {
			t.Fatal("合法历史结果被拒绝", kind, err)
		}
	}
}

func TestEvaluationArchiveRejectsCorruptionAuthorityAndMissingValues(t *testing.T) {
	changes := []func(*Evaluation){
		func(e *Evaluation) { e.SchemaVersion = "other" }, func(e *Evaluation) { e.ID = "/" }, func(e *Evaluation) { e.TenantID = "foreign" }, func(e *Evaluation) { e.CreatedBy = "/" }, func(e *Evaluation) { e.Policy.DefinitionSHA256 = "bad" }, func(e *Evaluation) { e.ExpiresAt = e.Result.EvaluatedAt }, func(e *Evaluation) { e.Result.EvaluatedAt = time.Time{} }, func(e *Evaluation) { e.Result.PolicyRevision++ }, func(e *Evaluation) { e.Result.TriageID = "/" }, func(e *Evaluation) { e.Result.ProviderRevision = 0 }, func(e *Evaluation) { e.Result.ProviderRevision = 9007199254740992 }, func(e *Evaluation) { e.Result.EventID = "/" }, func(e *Evaluation) { e.Result.RawSHA256 = "bad" }, func(e *Evaluation) { e.Result.ConfidenceKind = "calibrated" }, func(e *Evaluation) { e.Result.ExecutionAuthorized = true }, func(e *Evaluation) { e.Result.Limitations = nil }, func(e *Evaluation) { e.Result.Limitations[0] = "\x00" }, func(e *Evaluation) { e.Result.Limitations[6] = "已授权执行" }, func(e *Evaluation) { e.Result.Reasons = nil }, func(e *Evaluation) { e.Result.Reasons = []string{"expression_matched", "expression_matched"} }, func(e *Evaluation) { e.Result.Reasons = []string{"execute"} }, func(e *Evaluation) { e.Result.Confidence = nil }, func(e *Evaluation) { v := math.NaN(); e.Result.Confidence = &v }, func(e *Evaluation) { v := 2.0; e.Result.Confidence = &v }, func(e *Evaluation) { e.Result.Cost = nil }, func(e *Evaluation) { v := uint64(1001); e.Result.Cost = &v }, func(e *Evaluation) { e.Result.TargetIP = "invalid" }, func(e *Evaluation) { e.Result.TargetIP = "192.0.2.10" }, func(e *Evaluation) { e.Result.Status = "approved" }, func(e *Evaluation) { e.Result.Status = "abstained" }, func(e *Evaluation) { e.Result.Status = "protected"; e.Result.Reasons = []string{"protected_source"} }, func(e *Evaluation) { e.Policy.CreatedAt = e.Result.EvaluatedAt.Add(time.Hour) },
	}
	for i, change := range changes {
		e := archived(t)
		change(&e)
		if _, err := e.Seal(); err == nil {
			t.Fatal("损坏档案被接受", i)
		}
	}
	e := archived(t)
	e.Result.Status = "protected"
	e.Result.Cost = nil
	e.Result.CandidateAction = "block_source"
	e.Policy.Definition.CandidateAction = "block_source"
	e.Policy.DefinitionSHA256 = Digest(e.Policy.Definition)
	e.Result.DefinitionSHA256 = e.Policy.DefinitionSHA256
	e.Result.TargetIP = "192.0.2.10"
	e.Result.Reasons = []string{"protected_source"}
	if _, err := e.Seal(); err == nil {
		t.Fatal("不在保护范围的地址被归类为保护")
	}
}

func TestEvaluationRequestsAndDirectoryAreBounded(t *testing.T) {
	if (EvaluationRequest{PolicyID: "policy_owned", ExpectedRevision: 1, TriageID: "triage_owned"}).Validate() != nil {
		t.Fatal("合法请求被拒绝")
	}
	for _, r := range []EvaluationRequest{{PolicyID: "/", ExpectedRevision: 1, TriageID: "triage_owned"}, {PolicyID: "policy_owned", ExpectedRevision: 0, TriageID: "triage_owned"}, {PolicyID: "policy_owned", ExpectedRevision: 1, TriageID: "/"}} {
		if r.Validate() == nil {
			t.Fatal("无效引用被接受")
		}
	}
	if (EvaluationQuery{Limit: 100, Cursor: "evaluation_owned", PolicyID: "policy_owned", TriageID: "triage_owned", Status: "matched"}).Validate() != nil {
		t.Fatal("合法目录被拒绝")
	}
	for _, q := range []EvaluationQuery{{Limit: 0}, {Limit: 101}, {Limit: 1, Cursor: "/"}, {Limit: 1, PolicyID: "/"}, {Limit: 1, TriageID: "/"}, {Limit: 1, Status: "approved"}} {
		if q.Validate() == nil {
			t.Fatal("无界目录被接受")
		}
	}
}
