package decision

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/triage"
)

func responseMaterial(t *testing.T) (Evaluation, Record, triage.Job, ResponseRequest, time.Time) {
	t.Helper()
	p, job, now := source(t)
	p.Definition.CandidateAction = "block_source"
	p.DefinitionSHA256 = Digest(p.Definition)
	r, err := Evaluate(context.Background(), p, job, now)
	if err != nil {
		t.Fatal(err)
	}
	e, err := (Evaluation{SchemaVersion: EvaluationSchema, TenantID: p.TenantID, ID: "evaluation_owned", CreatedBy: "user_owned", ExpiresAt: now.Add(180 * 24 * time.Hour), Policy: p, Result: r}).Seal()
	if err != nil {
		t.Fatal(err)
	}
	request := ResponseRequest{EvaluationSHA256: e.SHA256, SensorID: "sensor_owned", RegistrationID: "registration_owned", ConnectorID: "connector_owned", ConfigSHA256: strings.Repeat("a", 64), TTLSeconds: 300, Reason: "管理员核对异常通信", Confirmed: true}
	return e, p, job, request, now
}

func TestDecisionResponseRequiresCurrentMaterialsAndExplicitConfirmation(t *testing.T) {
	e, p, job, request, now := responseMaterial(t)
	original := Digest(e)
	intent, err := ResponseIntent(context.Background(), e, p, job, job.Evidence, request, now)
	if err != nil || intent.TargetIP != e.Result.TargetIP || intent.TTLSeconds != 300 || Digest(e) != original || e.Result.ExecutionAuthorized {
		t.Fatal("人工确认未绑定原来源或改写影子结果", intent, err)
	}
	for _, kind := range []string{"unconfirmed", "archive_digest", "expired", "not_matched", "notify", "policy_revision", "policy_disabled", "policy_corrupt", "automatic_current", "automatic_archive", "job_identity", "job_expired", "cancelled", "material_changed", "material_corrupt", "stale", "zero_time", "invalid_reason", "future_evaluation", "provider_changed", "score_changed", "current_not_matched"} {
		t.Run(kind, func(t *testing.T) {
			e, p, job, request, now := responseMaterial(t)
			material := job.Evidence
			switch kind {
			case "unconfirmed":
				request.Confirmed = false
			case "archive_digest":
				request.EvaluationSHA256 = strings.Repeat("b", 64)
			case "expired":
				e.ExpiresAt = now
			case "not_matched":
				e.Result.Status = "not_matched"
			case "notify":
				e.Result.CandidateAction = "notify"
			case "policy_revision":
				p.Revision++
			case "policy_disabled":
				p.Active = false
			case "policy_corrupt":
				p.DefinitionSHA256 = strings.Repeat("b", 64)
			case "automatic_current":
				p.Definition.Mode = "automatic"
			case "automatic_archive":
				e.Policy.Definition.Mode = "automatic"
			case "job_identity":
				job.ID = "triage_other"
			case "job_expired":
				job.ExpiresAt = now
			case "cancelled":
				job.CancelRequested = true
			case "material_changed":
				material.ObservedAt = material.ObservedAt.Add(time.Second)
				material, _ = triage.Seal(material)
			case "material_corrupt":
				material.SHA256 = "bad"
			case "stale":
				now = now.Add(2 * time.Hour)
			case "zero_time":
				now = time.Time{}
			case "invalid_reason":
				request.Reason = "理由\x00"
			case "future_evaluation":
				now = now.Add(-time.Second)
			case "provider_changed":
				job.Request.ProviderRevision++
			case "score_changed":
				copy := *job.Answer
				copy.Confidence = .9
				job.Answer = &copy
			case "current_not_matched":
				copy := *job.Answer
				copy.Confidence = .5
				job.Answer = &copy
			}
			if _, err := ResponseIntent(context.Background(), e, p, job, material, request, now); err == nil {
				t.Fatal("过期、变化或未确认材料仍授权任务")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ResponseIntent(ctx, e, p, job, job.Evidence, request, now); err == nil {
		t.Fatal("取消请求仍授权任务")
	}
}

func TestDecisionResponseRequestsAndIndependentRecordIntegrity(t *testing.T) {
	e, p, job, request, now := responseMaterial(t)
	for _, change := range []func(*ResponseRequest){func(v *ResponseRequest) { v.EvaluationSHA256 = "bad" }, func(v *ResponseRequest) { v.SensorID = "/" }, func(v *ResponseRequest) { v.RegistrationID = "/" }, func(v *ResponseRequest) { v.ConnectorID = "/" }, func(v *ResponseRequest) { v.ConfigSHA256 = "bad" }, func(v *ResponseRequest) { v.TTLSeconds = 29 }, func(v *ResponseRequest) { v.TTLSeconds = 3601 }, func(v *ResponseRequest) { v.Reason = " " }, func(v *ResponseRequest) { v.Reason = strings.Repeat("中", 501) }, func(v *ResponseRequest) { v.Confirmed = false }} {
		value := request
		change(&value)
		if value.Validate() == nil {
			t.Fatal("请求边界未校验")
		}
	}
	r, err := (ResponseRecord{SchemaVersion: ResponseSchema, TenantID: e.TenantID, ID: "decision_response_owned", CreatedBy: e.CreatedBy, CreatedAt: now, ExpiresAt: now.Add(180 * 24 * time.Hour), EvaluationID: e.ID, EvaluationSHA256: e.SHA256, PolicyID: p.ID, PolicyRevision: p.Revision, DefinitionSHA256: p.DefinitionSHA256, TriageID: job.ID, EvidenceSHA256: job.Evidence.SHA256, TargetIP: e.Result.TargetIP, Request: request, TaskID: "task_owned"}).Seal()
	if err != nil || len(r.SHA256) != 64 {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(r)
	var copy ResponseRecord
	if json.Unmarshal(raw, &copy) != nil {
		t.Fatal("档案无法解码")
	}
	sealed, err := copy.Seal()
	if err != nil || sealed.SHA256 != r.SHA256 {
		t.Fatal("档案序列化改变内容摘要", err)
	}
	for _, change := range []func(*ResponseRecord){func(v *ResponseRecord) { v.SchemaVersion = "other" }, func(v *ResponseRecord) { v.TenantID = "/" }, func(v *ResponseRecord) { v.ID = "/" }, func(v *ResponseRecord) { v.CreatedBy = "/" }, func(v *ResponseRecord) { v.CreatedAt = time.Time{} }, func(v *ResponseRecord) { v.ExpiresAt = v.CreatedAt }, func(v *ResponseRecord) { v.EvaluationID = "/" }, func(v *ResponseRecord) { v.EvaluationSHA256 = "bad" }, func(v *ResponseRecord) { v.PolicyID = "/" }, func(v *ResponseRecord) { v.PolicyRevision = 0 }, func(v *ResponseRecord) { v.DefinitionSHA256 = "bad" }, func(v *ResponseRecord) { v.TriageID = "/" }, func(v *ResponseRecord) { v.EvidenceSHA256 = "bad" }, func(v *ResponseRecord) { v.TargetIP = "127.0.0.1" }, func(v *ResponseRecord) { v.TaskID = "/" }, func(v *ResponseRecord) { v.Request.EvaluationSHA256 = strings.Repeat("c", 64) }, func(v *ResponseRecord) { v.Request.Confirmed = false }} {
		value := r
		change(&value)
		if _, err := value.Seal(); err == nil {
			t.Fatal("损坏授权档案被接受")
		}
	}
}
