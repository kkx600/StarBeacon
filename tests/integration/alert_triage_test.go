//go:build integration

package integration

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/admin"
	"github.com/kkx600/StarBeacon/internal/assessment"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/jobs"
	"github.com/kkx600/StarBeacon/internal/llm"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/outbound"
	"github.com/kkx600/StarBeacon/internal/platform"
	"github.com/kkx600/StarBeacon/internal/secrets"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/triage"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
)

// 受控提供方只检验 HTTPS、严格输出与引用协议，不代表真实模型的领域效果。
func newTriageProvider(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	calls := &atomic.Int32{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var request struct {
			Model string `json:"model"`
			Input string `json:"input"`
			Store *bool  `json:"store"`
			Text  struct {
				Format struct {
					Type   string `json:"type"`
					Name   string `json:"name"`
					Strict bool   `json:"strict"`
				} `json:"format"`
			} `json:"text"`
		}
		if json.NewDecoder(io.LimitReader(r.Body, 65537)).Decode(&request) != nil || r.Header.Get("Authorization") != "Bearer owned-triage-key" || request.Store == nil || *request.Store || request.Model != "owned-triage-model" || request.Text.Format.Type != "json_schema" || request.Text.Format.Name != "starbeacon_alert_triage" || !request.Text.Format.Strict || strings.Contains(request.Input, "must-not-send") {
			w.WriteHeader(400)
			return
		}
		var prompt struct {
			Note     string          `json:"note"`
			Material triage.Evidence `json:"material"`
		}
		if json.Unmarshal([]byte(request.Input), &prompt) != nil || len(prompt.Material.Facts) < 3 {
			w.WriteHeader(400)
			return
		}
		answer := triage.Answer{Verdict: "confirmed", Outcome: "attempt", Confidence: 0.87, Reason: "规则和请求路径共同支持攻击尝试建议，尚无业务成功证据", References: []string{"rule.id", "http.path"}, CounterEvidence: []string{"现有字段未排除授权测试"}, Missing: []string{"终端与业务日志"}, Recommendation: "investigate", NeedsReview: true}
		if strings.Contains(prompt.Note, "[invalid_output]") {
			answer.Outcome = "success"
		}
		if strings.Contains(prompt.Note, "[cancel_after_send]") {
			<-r.Context().Done()
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(prompt.Note, "[uncertain]") {
			w.WriteHeader(503)
			_, _ = w.Write([]byte(`{"error":{"message":"controlled failure","type":"server_error"}}`))
			return
		}
		text, _ := json.Marshal(answer)
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "owned-triage-response", "object": "response", "model": "owned-triage-model", "status": "completed", "output": []any{map[string]any{"id": "owned-triage-message", "type": "message", "role": "assistant", "status": "completed", "content": []any{map[string]any{"type": "output_text", "text": string(text), "annotations": []any{}}}}}, "usage": map[string]any{"input_tokens": 3, "output_tokens": 4, "total_tokens": 7}})
	}))
	return server, calls
}

func verifyNativeAlertTriage(t *testing.T, ctx context.Context, client *liveHTTP, alert model.Alert, providerURL string, calls *atomic.Int32) triage.Job {
	t.Helper()
	var provider llm.Provider
	config := llm.Config{Name: "原生告警研判协议验收", Kind: "openai_responses", BaseURL: providerURL + "/v1", Model: "owned-triage-model", Enabled: true, APIKey: "owned-triage-key", MaxOutputTokens: 512, TimeoutSeconds: 5, DailyRequests: 1}
	client.request("POST", "/models/providers", "", store.ModelChange{ID: "provider_triage_live", ReplaceKey: true, Config: config}, &provider, 200)
	input := triage.Request{EventID: alert.EventID, RawSHA256: alert.RawSHA256, ProviderID: provider.ID, ProviderRevision: provider.Revision, Note: "依据原生检测告警判断，并指出缺失信息", AllowContext: true}
	var job triage.Job
	path := "/alerts/" + alert.EventID + "/triage"
	client.request("POST", path, "native_triage_owned", input, &job, 202)
	id := job.ID
	eventually(t, ctx, "原生告警经过真实模型研判队列", func() bool {
		client.request("GET", "/alert-triage/jobs/"+id, "", nil, &job, 200)
		if job.State != "queued" && job.State != "running" && job.State != "succeeded" {
			t.Fatal("原生研判未完成", job.State, job.Result.Code)
		}
		return job.State == "succeeded"
	})
	expected, err := triage.Freeze(alert)
	require(t, err)
	if job.Answer == nil || job.Answer.Outcome != "attempt" || job.Answer.Verdict != "confirmed" || !job.Answer.NeedsReview || job.ConfidenceKind != "self_reported" || job.Evidence.SHA256 != expected.SHA256 || job.Result.Usage == nil || calls.Load() != 1 {
		t.Fatal("原生告警研判失去来源、引用或复核边界")
	}
	var repeated triage.Job
	client.request("POST", path, "native_triage_owned", input, &repeated, 200)
	if repeated.ID != id || calls.Load() != 1 {
		t.Fatal("原生研判重复调用模型")
	}
	client.request("POST", "/models/providers/"+provider.ID+"/test", "native_triage_budget", map[string]any{"expected_revision": provider.Revision}, nil, 429)
	var page store.TriagePage
	client.request("GET", path+"?sha256="+alert.RawSHA256, "", nil, &page, 200)
	if len(page.Items) != 1 || page.Items[0].ID != id || !page.Available {
		t.Fatal("原生研判历史或执行服务状态不准确")
	}
	var manual assessment.Record
	client.request("GET", "/alerts/"+alert.EventID+"/assessment?sha256="+alert.RawSHA256, "", nil, &manual, 200)
	if manual.Revision != 0 || manual.Spec.Verdict != "unreviewed" {
		t.Fatal("模型建议改写人工研判")
	}
	verifyNativeDecisionPolicy(t, client, job)
	return job
}

func TestAlertTriageRealQueueEvidenceOwnershipCancellationAndRecovery(t *testing.T) {
	ctx, stop := context.WithTimeout(context.Background(), 120*time.Second)
	defer stop()
	f := newIsolatedDatabase(t, ctx)
	tenant, foreign, password := store.RandomID("it_triage_"), store.RandomID("it_triage_other_"), store.Token()
	for _, entry := range []struct{ tenant, name, role string }{{tenant, tenant, "admin"}, {tenant, tenant + "_other", "admin"}, {tenant, tenant + "_viewer", "viewer"}, {foreign, foreign, "admin"}} {
		require(t, admin.Bootstrap(ctx, f.Owner, entry.tenant, "模型研判验收", entry.name, password, entry.role))
	}
	u, _, err := f.Runtime.Password(ctx, tenant)
	require(t, err)
	vault, err := secrets.New(store.Token())
	require(t, err)
	provider, calls := newTriageProvider(t)
	defer provider.Close()
	networks, err := outbound.ParseNetworks("127.0.0.0/8")
	require(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(provider.Certificate())
	policy := outbound.Policy{PrivateNetworks: networks, Roots: roots}
	config := llm.Config{Name: "告警研判协议验收", Kind: "openai_responses", BaseURL: provider.URL + "/v1", Model: "owned-triage-model", Enabled: true, APIKey: "owned-triage-key", MaxOutputTokens: 512, TimeoutSeconds: 10, DailyRequests: 1000}
	_, err = f.Runtime.SaveModelProvider(ctx, u, store.ModelChange{ID: "provider_owned", ReplaceKey: true, Config: config}, vault, policy, "seed")
	require(t, err)
	es, err := store.OpenES(os.Getenv("SB_ES_URL"), "")
	require(t, err)
	now := time.Now().UTC()
	index, err := contract.IndexName(tenant, "alerts", now.Format("2006-01-02"))
	require(t, err)
	require(t, es.EnsureIndex(ctx, index, now.Format("2006-01-02")))
	t.Cleanup(func() {
		clean, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		res, err := es.API.Indices.Delete([]string{index}, es.API.Indices.Delete.WithContext(clean))
		require(t, err)
		defer res.Body.Close()
		if res.IsError() {
			t.Error("研判验收索引清理失败", res.StatusCode)
		}
	})
	alert := model.Alert{EventID: "event_owned", TenantID: tenant, RawSHA256: control.Digest([]byte("owned original")), SensorID: "sensor_owned", RegistrationID: "registration_owned", Timestamp: now, ObservedAt: now, ReceivedAt: now, Source: model.Endpoint{IP: "192.0.2.1"}, Destination: model.Endpoint{IP: "198.51.100.2"}}
	alert.Event.Kind, alert.Event.Original = "alert", `{"private":"must-not-send"}`
	alert.Rule.ID, alert.Rule.Name, alert.HTTP.Path = "1000001", "路径检测", "/.git/config"
	for _, err := range es.Bulk(ctx, index, []model.Alert{alert}) {
		require(t, err)
	}
	refresh, err := es.API.Indices.Refresh(es.API.Indices.Refresh.WithIndex(index), es.API.Indices.Refresh.WithContext(ctx))
	require(t, err)
	if refresh.IsError() {
		t.Fatal("研判索引刷新失败", refresh.StatusCode)
	}
	refresh.Body.Close()
	evidence, err := triage.Freeze(alert)
	require(t, err)
	queue, err := jobs.NewAnalysisWithTriage(f.Runtime, vault, policy, es)
	require(t, err)
	a := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime, ES: es, Vault: vault, Jobs: queue}, tenant, password)
	b := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime, ES: es, Vault: vault, Jobs: queue}, tenant+"_other", password)
	c := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime, ES: es, Vault: vault, Jobs: queue}, foreign, password)
	viewer := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime, ES: es, Vault: vault, Jobs: queue}, tenant+"_viewer", password)
	input := triage.Request{EventID: alert.EventID, RawSHA256: alert.RawSHA256, ProviderID: "provider_owned", ProviderRevision: 1, Note: "依据现有观测研判", AllowContext: true}
	path := "/alerts/" + alert.EventID + "/triage"
	var queued triage.Job
	a.request("POST", path, "queued_owned", input, &queued, 202)
	if queued.State != "queued" || queued.Result.State != "queued" || queued.Result.DurationMS != nil || queued.ConfidenceKind != "self_reported" || queued.Evidence.SHA256 != evidence.SHA256 {
		t.Fatal("冻结、未执行状态或置信度来源错误")
	}
	var repeated triage.Job
	a.request("POST", path, "queued_owned", input, &repeated, 200)
	if repeated.ID != queued.ID || calls.Load() != 0 {
		t.Fatal("排队幂等请求产生副作用")
	}
	for _, client := range []*liveHTTP{b, c} {
		client.request("GET", "/alert-triage/jobs/"+queued.ID, "", nil, nil, 404)
		client.request("POST", "/alert-triage/jobs/"+queued.ID+"/cancel", "", struct{}{}, nil, 404)
	}
	viewer.request("POST", path, "denied", input, nil, 403)
	viewer.request("GET", path+"?sha256="+input.RawSHA256, "", nil, nil, 403)
	wrong := input
	wrong.EventID = "another_event"
	a.request("POST", path, "wrong_path", wrong, nil, 400)
	wrong = input
	wrong.RawSHA256 = control.Digest([]byte("different"))
	a.request("POST", path, "wrong_digest", wrong, nil, 409)
	wrong = input
	wrong.Note = "changed"
	a.request("POST", path, "queued_owned", wrong, nil, 409)
	a.request("POST", "/alert-triage/jobs/"+queued.ID+"/cancel", "", struct{}{}, &queued, 200)
	if queued.State != "cancelled" || !queued.CancelRequested || calls.Load() != 0 {
		t.Fatal("排队取消仍调用模型")
	}
	work, cancelWork := context.WithCancel(context.WithoutCancel(ctx))
	defer cancelWork()
	require(t, queue.Start(work))
	defer func() {
		clean, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		require(t, queue.StopAndCancel(clean))
	}()
	wait := func(id string) triage.Job {
		var j triage.Job
		eventually(t, ctx, "真实研判进入终态", func() bool {
			a.request("GET", "/alert-triage/jobs/"+id, "", nil, &j, 200)
			return j.State != "queued" && j.State != "running"
		})
		return j
	}
	create := func(key string, input triage.Request) triage.Job {
		var j triage.Job
		a.request("POST", path, key, input, &j, 202)
		return wait(j.ID)
	}
	good := create("success_owned", input)
	if good.State != "succeeded" || good.Answer == nil || good.Answer.Verdict != "confirmed" || good.Answer.Outcome != "attempt" || !good.Answer.NeedsReview || good.Result.Text != "" || good.Result.Usage == nil || calls.Load() != 1 {
		t.Fatal("真实模型协议、引用或复核边界错误", good.State, good.Result.Code)
	}
	var manual assessment.Record
	a.request("GET", "/alerts/"+alert.EventID+"/assessment?sha256="+alert.RawSHA256, "", nil, &manual, 200)
	if manual.Revision != 0 || manual.Spec.Verdict != "unreviewed" {
		t.Fatal("模型结论覆盖了人工研判")
	}
	input.Note = "[invalid_output] 未观察的入侵成功"
	bad := create("bad_owned", input)
	if bad.State != "failed" || bad.Result.Code != "invalid_triage_output" || bad.Answer != nil || calls.Load() != 2 {
		t.Fatal("不受证据支持的输出被保存为成功")
	}
	input.Note = "[uncertain] 调用结果未知"
	unknown := create("unknown_owned", input)
	if unknown.State != "uncertain" || unknown.Answer != nil || calls.Load() != 3 {
		t.Fatal("未知模型结果被当成可重试失败")
	}
	a.request("POST", path, "unknown_owned", input, &repeated, 200)
	if repeated.ID != unknown.ID || calls.Load() != 3 {
		t.Fatal("未知请求再次收费")
	}
	input.Note = "[cancel_after_send] 取消已发送调用"
	var running triage.Job
	a.request("POST", path, "cancel_running_owned", input, &running, 202)
	eventually(t, ctx, "提供方确已收到研判", func() bool {
		a.request("GET", "/alert-triage/jobs/"+running.ID, "", nil, &running, 200)
		return running.State == "running" && calls.Load() == 4
	})
	a.request("POST", "/alert-triage/jobs/"+running.ID+"/cancel", "", struct{}{}, nil, 200)
	running = wait(running.ID)
	if running.State != "uncertain" || !running.CancelRequested || calls.Load() != 4 {
		t.Fatal("已发送取消没有保留未知结果")
	}
	var page store.TriagePage
	a.request("GET", path+"?sha256="+input.RawSHA256, "", nil, &page, 200)
	if len(page.Items) != 5 || page.Next != "" {
		t.Fatal("研判历史丢失或重复", len(page.Items))
	}
	a.request("GET", path+"?sha256="+input.RawSHA256+"&before=bad/id", "", nil, nil, 400)
	a.request("GET", path+"?sha256="+input.RawSHA256+"&before=missing_owned", "", nil, nil, 404)
	require(t, queue.StopAndCancel(ctx))
	input.Note = "源告警回收后不能出站"
	var missing triage.Job
	a.request("POST", path, "missing_source_owned", input, &missing, 202)
	deleted, err := es.API.Delete(index, alert.EventID, es.API.Delete.WithRefresh("true"), es.API.Delete.WithContext(ctx))
	require(t, err)
	if deleted.IsError() {
		t.Fatal("源告警删除夹具失败", deleted.StatusCode)
	}
	deleted.Body.Close()
	var riverID int64
	require(t, f.Owner.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT river_job_id FROM alert_triage_jobs WHERE tenant_id=$1 AND id=$2`, tenant, missing.ID).Scan(&riverID)
	}))
	worker := jobs.AlertTriageWorker{DB: f.Runtime, Vault: vault, Client: llm.Client{Policy: policy}, Source: es}
	require(t, worker.Work(ctx, &river.Job[triage.Args]{JobRow: &rivertype.JobRow{ID: riverID}, Args: triage.Args{TenantID: tenant, JobID: missing.ID}}))
	missing = wait(missing.ID)
	if missing.State != "failed" || missing.Result.Code != "alert_source_unavailable" || calls.Load() != 4 {
		t.Fatal("排队材料过期仍发送模型")
	}
	if _, err := f.Runtime.StartAlertTriage(ctx, triage.Args{TenantID: tenant, JobID: missing.ID}, riverID+1, vault); !errors.Is(err, store.ErrConflict) {
		t.Fatal("错误队列身份获得调用权限", err)
	}
	t.Log("真实 ES、PG、River 与 HTTPS SDK 验证通过；模型结论为建议，不改写人工记录或执行设备动作。")
}
