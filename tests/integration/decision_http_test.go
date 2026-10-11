//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/accounts"
	"github.com/kkx600/StarBeacon/internal/decision"
	"github.com/kkx600/StarBeacon/internal/platform"
	"github.com/kkx600/StarBeacon/internal/triage"
)

func TestDecisionPolicyHTTPIsolationRevisionsSyntaxAndNoUnsupportedExecution(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Second)
	defer cancel()
	f, u, foreign, password := accountFixture(t, ctx)
	active := true
	viewerUser, err := f.Runtime.CreateUser(ctx, u, "decision_viewer_create", accounts.Create{Username: "decision_viewer", Password: password, Role: "viewer", Active: &active})
	require(t, err)
	a := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime}, u.Username, password)
	b := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime}, foreign.Username, password)
	v := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime}, viewerUser.Username, password)
	c := decisionPolicyInput("policy_owned")
	var first, repeated decision.Record
	a.request("POST", "/decision-policies", "policy_create", c, &first, 200)
	a.request("POST", "/decision-policies", "policy_create", c, &repeated, 200)
	if first.Validate() != nil || repeated.Revision != first.Revision || !repeated.CreatedAt.Equal(first.CreatedAt) || first.TenantID != u.TenantID || first.CreatedBy != u.ID || first.ExpiresAt.Sub(first.CreatedAt) != 180*24*time.Hour {
		t.Fatal("修订、租户、原提交或保留期不同")
	}
	changed := c
	changed.Name = "不同输入"
	a.request("POST", "/decision-policies", "policy_create", changed, nil, 409)
	v.request("POST", "/decision-policies", "policy_viewer_create", c, nil, 403)
	noCSRF := *a
	noCSRF.csrf = ""
	noCSRF.request("POST", "/decision-policies", "policy_no_csrf", c, nil, 403)
	b.request("GET", "/decision-policies/policy_owned/revisions/1", "", nil, nil, 404)
	v.request("GET", "/decision-policies/policy_owned/revisions/1", "", nil, &repeated, 200)
	var page decision.Page
	b.request("GET", "/decision-policies", "", nil, &page, 200)
	if len(page.Items) != 0 {
		t.Fatal("策略目录跨租户泄露")
	}
	v.request("POST", "/decision-policies/validate", "", map[string]any{"definition": c.Definition}, nil, 200)
	c.Definition.Expression = "confidence"
	a.request("POST", "/decision-policies", "policy_wrong_expression", c, nil, 400)
	c = decisionPolicyInput("policy_second")
	a.request("POST", "/decision-policies", "policy_second_create", c, &repeated, 200)
	a.request("GET", "/decision-policies?limit=1", "", nil, &page, 200)
	if len(page.Items) != 1 || page.NextCursor != first.ID {
		t.Fatal("首个策略目录游标不一致")
	}
	a.request("GET", "/decision-policies?limit=1&cursor="+page.NextCursor, "", nil, &page, 200)
	if len(page.Items) != 1 || page.Items[0].ID != c.ID || page.NextCursor != "" {
		t.Fatal("策略后续页不一致")
	}
	off := false
	edit := decisionPolicyEdit(repeated)
	edit.Active = &off
	a.request("POST", "/decision-policies", "policy_second_disable", edit, &repeated, 200)
	a.request("POST", "/decision-policies", "policy_stale_edit", edit, nil, 409)
	a.request("GET", "/decision-policies/policy_second/revisions/1", "", nil, &repeated, 200)
	if !repeated.Active || repeated.Revision != 1 {
		t.Fatal("策略历史被改写")
	}
	a.request("GET", "/decision-policies?active=false&keyword=攻击", "", nil, &page, 200)
	if len(page.Items) != 1 || page.Items[0].Active {
		t.Fatal("策略筛选未生效")
	}
	a.request("POST", "/decision-policies", "policy_no_change", decisionPolicyEdit(page.Items[0]), nil, 400)
	a.request("POST", "/decision-policies/policy_owned/evaluate", "", decision.EvaluateRequest{ExpectedRevision: 1, TriageID: "triage_missing"}, nil, 404)
	a.request("POST", "/decision-policies/policy_owned/evaluate", "", decision.EvaluateRequest{ExpectedRevision: 2, TriageID: "triage_missing"}, nil, 409)
	v.request("POST", "/decision-policies/policy_owned/evaluate", "", decision.EvaluateRequest{ExpectedRevision: 1, TriageID: "triage_missing"}, nil, 403)
	a.request("POST", "/decision-policies", "policy_create", decisionPolicyInput("policy_owned"), &repeated, 200)
	for _, mode := range []string{"approval", "automatic"} {
		unsupported := decisionPolicyInput("policy_unsupported")
		unsupported.Definition.Mode = mode
		a.request("POST", "/decision-policies", "policy_unsupported_"+mode, unsupported, nil, 409)
	}
}

// 该辅助验证随实际 ZIP 的原生采集链路运行，复用一次真实 HTTPS 研判结果。
func verifyNativeDecisionPolicy(t *testing.T, client *liveHTTP, job triage.Job) {
	t.Helper()
	c := decisionPolicyInput("policy_native_shadow")
	c.Definition.CandidateAction = "investigate"
	c.Definition.MaxAgeSeconds = 86400
	var record decision.Record
	client.request("POST", "/decision-policies", "native_policy_create", c, &record, 200)
	input := decision.EvaluateRequest{ExpectedRevision: record.Revision, TriageID: job.ID}
	var result decision.Result
	client.request("POST", "/decision-policies/"+record.ID+"/evaluate", "", input, &result, 200)
	if result.Status != "matched" || result.ExecutionAuthorized || result.ConfidenceKind != "self_reported" || result.Confidence == nil || *result.Confidence != job.Answer.Confidence || result.EvidenceSHA256 != job.Evidence.SHA256 || result.RawSHA256 != job.Request.RawSHA256 || result.ProviderRevision != job.Request.ProviderRevision || result.PolicyRevision != record.Revision || result.Cost == nil {
		t.Fatal("原生影子策略未绑定实际研判与执行边界", result)
	}
	var archived, confirmed decision.Evaluation
	archiveInput := decision.EvaluationRequest{PolicyID: record.ID, ExpectedRevision: record.Revision, TriageID: job.ID}
	client.request("POST", "/decision-evaluations", "native_evaluation_archive", archiveInput, &archived, 200)
	client.request("GET", "/decision-evaluations/"+archived.ID, "", nil, &confirmed, 200)
	sealed, err := confirmed.Seal()
	require(t, err)
	if confirmed.ID != archived.ID || sealed.SHA256 != archived.SHA256 || confirmed.Result.Status != "matched" || confirmed.Result.EvidenceSHA256 != job.Evidence.SHA256 || confirmed.Result.ExecutionAuthorized {
		t.Fatal("原生研判的持久评估档案不同")
	}
	var history decision.EvaluationPage
	client.request("GET", "/decision-evaluations?triage_id="+job.ID, "", nil, &history, 200)
	if len(history.Items) != 2 || history.Items[0].ID != archived.ID {
		t.Fatal("原生评估未进入本人目录")
	}
	edit := decisionPolicyEdit(record)
	off := false
	edit.Active = &off
	client.request("POST", "/decision-policies", "native_policy_disable", edit, &record, 200)
	client.request("POST", "/decision-evaluations", "native_evaluation_archive", archiveInput, &confirmed, 200)
	if confirmed.SHA256 != archived.SHA256 || !confirmed.Policy.Active {
		t.Fatal("停用策略改变了原生历史判断")
	}
	client.request("POST", "/decision-policies/"+record.ID+"/evaluate", "", input, nil, 409)
	input.ExpectedRevision = record.Revision
	client.request("POST", "/decision-policies/"+record.ID+"/evaluate", "", input, &result, 200)
	if result.Status != "abstained" || result.ExecutionAuthorized || len(result.Reasons) != 1 || result.Reasons[0] != "policy_inactive" {
		t.Fatal("停用策略仍产生候选", result)
	}
}
