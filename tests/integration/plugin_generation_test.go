//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/admin"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/jobs"
	"github.com/kkx600/StarBeacon/internal/llm"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/outbound"
	"github.com/kkx600/StarBeacon/internal/platform"
	"github.com/kkx600/StarBeacon/internal/plugingen"
	"github.com/kkx600/StarBeacon/internal/response"
	"github.com/kkx600/StarBeacon/internal/secrets"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/transport"
)

const pluginGenerationPath = "/response-plugin-generation/jobs"
const healthTemplate = `{"schema_version":"response.template.v1","health":{"method":"GET","path":"/health","accept":{"status":[200],"field":"healthy","equals":true}}}`

func pluginProviderFixture(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	calls := &atomic.Int32{}
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		raw, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
		var body struct {
			Input string          `json:"input"`
			Model string          `json:"model"`
			Store *bool           `json:"store"`
			Tools json.RawMessage `json:"tools"`
			Text  struct {
				Format struct {
					Strict bool   `json:"strict"`
					Name   string `json:"name"`
					Type   string `json:"type"`
				} `json:"format"`
			} `json:"text"`
		}
		if err != nil || json.Unmarshal(raw, &body) != nil || r.Method != http.MethodPost || r.URL.Path != "/v1/responses" ||
			body.Model != "fixture-plugin-model" || r.Header.Get("Authorization") != "Bearer fixture-generation-key" ||
			body.Store == nil || *body.Store || len(body.Tools) != 0 || body.Text.Format.Name != "starbeacon_response_plugin_draft" ||
			body.Text.Format.Type != "json_schema" || !body.Text.Format.Strict ||
			bytes.Contains(raw, []byte("fixture-generation-key")) || bytes.Contains(raw, []byte("local-device-credential")) {
			t.Error("模型请求带入设备或凭据材料，或未使用严格输出")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var prompt struct {
			Device   string   `json:"device_type"`
			Entries  []string `json:"required_entries"`
			Document string   `json:"documentation"`
		}
		reader := json.NewDecoder(strings.NewReader(body.Input))
		reader.DisallowUnknownFields()
		if reader.Decode(&prompt) != nil || !slices.Equal(prompt.Entries, []string{"health"}) || !strings.Contains(prompt.Document, "GET /health") {
			t.Error("模型收到超过用户提供接口文档的材料")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(prompt.Document, "[unknown_result]") {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":{"message":"fixture timeout","type":"server_error"}}`))
			return
		}
		format, definition, name, entries := "template", healthTemplate, "健康检查生成草稿", []string{}
		samples := []map[string]any{{"method": "GET", "path": "/health", "query": "", "request": "", "status": 200, "response": `{"healthy":true}`}}
		switch {
		case strings.Contains(prompt.Document, "[insufficient]"):
			format, definition, name, samples = "insufficient", "", "", []map[string]any{}
		case strings.Contains(prompt.Document, "[unusable]"):
			format, definition = "template", "invalid"
		case prompt.Device == "EDR":
			format, definition, entries = "script", "def health(ctx):\n    return http.get('/health').status == 200\n", []string{"health"}
		}
		text, _ := json.Marshal(map[string]any{"format": format, "definition": definition, "name": name, "entries": entries, "examples": samples})
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": "fixture-response", "object": "response", "model": "fixture-plugin-model", "status": "completed",
			"output": []any{map[string]any{"id": "fixture-result", "type": "message", "role": "assistant", "status": "completed",
				"content": []any{map[string]any{"type": "output_text", "text": string(text), "annotations": []any{}}}}},
			"usage": map[string]any{"input_tokens": 4, "output_tokens": 12, "total_tokens": 16},
		})
	}))
	return s, calls
}

func setupPluginModel(t *testing.T, ctx context.Context, f *isolatedDatabase, owner model.Principal, origin *httptest.Server) (*secrets.Vault, outbound.Policy, llm.Config) {
	t.Helper()
	vault, err := secrets.New(store.Token())
	require(t, err)
	nets, err := outbound.ParseNetworks("127.0.0.0/8")
	require(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(origin.Certificate())
	policy := outbound.Policy{PrivateNetworks: nets, Roots: roots}
	config := llm.Config{Name: "受控插件模型", Kind: "openai_responses", BaseURL: origin.URL + "/v1",
		Model: "fixture-plugin-model", APIKey: "fixture-generation-key", Enabled: true, TimeoutSeconds: 5, MaxOutputTokens: 1024, DailyRequests: 20}
	_, err = f.Runtime.SaveModelProvider(ctx, owner, store.ModelChange{ID: "fixture_model", Config: config, ReplaceKey: true}, vault, policy, "plugin_model_seed")
	require(t, err)
	return vault, policy, config
}

func pluginGenerationInput() plugingen.Request {
	return plugingen.Request{ProviderID: "fixture_model", ProviderRevision: 1, DeviceType: "firewall", Abilities: []string{"health"},
		Documentation: "GET /health 返回 200 和 healthy 布尔状态。", AllowContext: true}
}

func TestPluginGenerationUsesOnlyDocumentationAndKeepsTrialGate(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 120*time.Second)
	defer cancel()
	f, owner, foreign, password := accountFixture(t, ctx)
	require(t, admin.Bootstrap(ctx, f.Owner, owner.TenantID, "生成审阅", "plugin_peer", password, "admin"))
	require(t, admin.Bootstrap(ctx, f.Owner, owner.TenantID, "生成审阅", "plugin_viewer", password, "viewer"))
	provider, calls := pluginProviderFixture(t)
	defer provider.Close()
	vault, policy, _ := setupPluginModel(t, ctx, f, owner, provider)
	queue, err := jobs.NewAnalysis(f.Runtime, vault, policy, nil)
	require(t, err)
	pub, signer, err := ed25519.GenerateKey(rand.Reader)
	require(t, err)
	var ready atomic.Bool
	ready.Store(true)
	app := &platform.API{DB: f.Runtime, Vault: vault, Jobs: queue, JobsReady: ready.Load, Outbound: policy, Signer: signer}
	user := authenticatedFaultHTTP(t, ctx, f.Runtime, app, owner.Username, password)
	peer := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime, Vault: vault, Jobs: queue}, "plugin_peer", password)
	other := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime, Vault: vault, Jobs: queue}, foreign.Username, password)
	viewer := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime}, "plugin_viewer", password)
	input := pluginGenerationInput()
	bad := input
	bad.Documentation += "\nAuthorization: Bearer local-device-credential"
	user.request("POST", pluginGenerationPath, "plaintext_rejected", bad, nil, 400)
	bad = input
	bad.AllowContext = false
	user.request("POST", pluginGenerationPath, "missing_consent", bad, nil, 400)
	viewer.request("POST", pluginGenerationPath, "viewer_cannot_create", input, nil, 403)
	viewer.request("GET", pluginGenerationPath, "", nil, nil, 403)
	user.request("GET", pluginGenerationPath+"?before=1&before=2", "", nil, nil, 400)
	user.request("POST", pluginGenerationPath, "unknown_request_fields", map[string]any{"device_secret": "fixture"}, nil, 400)
	var first plugingen.Job
	user.request("POST", pluginGenerationPath, "generate_health", input, &first, 202)
	if first.State != "queued" || first.Model != "fixture-plugin-model" || first.DocumentationSHA256 != plugingen.DocumentSHA256(input.Documentation) || first.Candidate != nil {
		t.Fatal("新记录未保留文档摘要、模型与生成排队状态")
	}
	ready.Store(false)
	var replayed plugingen.Job
	user.request("POST", pluginGenerationPath, "generate_health", input, &replayed, 200)
	user.request("POST", pluginGenerationPath, "queue_temporarily_unavailable", input, nil, 503)
	if replayed.ID != first.ID {
		t.Fatal("重复提交创建新记录")
	}
	ready.Store(true)
	bad = input
	bad.Documentation += " 返回字段示例。"
	user.request("POST", pluginGenerationPath, "generate_health", bad, nil, 409)
	user.request("POST", "/models/providers/fixture_model/test", "shared_model_budget", map[string]int{"expected_revision": 1}, nil, 429)
	for _, visitor := range []*liveHTTP{peer, other} {
		visitor.request("GET", pluginGenerationPath+"/"+first.ID, "", nil, nil, 404)
	}
	var peerPage plugingen.Page
	peer.request("GET", pluginGenerationPath, "", nil, &peerPage, 200)
	if len(peerPage.Items) != 0 || calls.Load() != 0 {
		t.Fatal("排队作业未按所有者隔离，或提前调用了模型")
	}
	run, stop := context.WithCancel(context.WithoutCancel(ctx))
	defer stop()
	require(t, queue.Start(run))
	defer func() {
		finish, exit := context.WithTimeout(context.Background(), 5*time.Second)
		defer exit()
		require(t, queue.StopAndCancel(finish))
	}()
	wait := func(id string) plugingen.Job {
		var job plugingen.Job
		eventually(t, ctx, "插件生成作业进入终态", func() bool {
			user.request("GET", pluginGenerationPath+"/"+id, "", nil, &job, 200)
			return job.State != "queued" && job.State != "running"
		})
		return job
	}
	first = wait(first.ID)
	if first.State != "succeeded" || first.Candidate == nil || first.Candidate.Script != nil ||
		first.Candidate.Template.SchemaVersion != response.TemplateSchema || len(first.Candidate.Examples) != 1 || first.Result.Text != "" {
		t.Fatal("声明式模板未保留样例、状态或经过输出过滤")
	}
	for _, tc := range []struct{ kind, doc, state, code string }{
		{"edr", "", "succeeded", ""},
		{"firewall", " [unusable]", "failed", "invalid_plugin_generation_output"},
		{"firewall", " [insufficient]", "failed", "insufficient_documentation"},
		{"firewall", " [unknown_result]", "uncertain", "provider_result_unknown"},
	} {
		next := input
		next.DeviceType, next.Documentation = tc.kind, input.Documentation+tc.doc
		var job plugingen.Job
		user.request("POST", pluginGenerationPath, store.RandomID("generation_"), next, &job, 202)
		job = wait(job.ID)
		if job.State != tc.state || tc.code != "" && job.Result.Code != tc.code ||
			tc.kind == "edr" && (job.Candidate == nil || job.Candidate.Script == nil) ||
			tc.state != "succeeded" && job.Candidate != nil {
			t.Fatal("生成结果或未知状态错误", tc.kind, job.State, job.Result.Code)
		}
	}
	var page plugingen.Page
	user.request("GET", pluginGenerationPath+"?limit=10", "", nil, &page, 200)
	if len(page.Items) != 5 || !page.Available || page.Items[0].Candidate != nil || calls.Load() != 5 {
		t.Fatal("历史页或模型调用次数与真实执行不一致", len(page.Items), calls.Load())
	}
	require(t, f.Runtime.TenantTx(ctx, owner.TenantID, func(tx pgx.Tx) error {
		var docs, drafts, sensorTasks int
		err := tx.QueryRow(ctx, `SELECT
		 (SELECT count(*) FROM response_plugin_generations WHERE tenant_id=$1 AND (input ? 'documentation' OR result ? 'text')),
		 (SELECT count(*) FROM response_plugin_versions WHERE tenant_id=$1),
		 (SELECT count(*) FROM sensor_tasks WHERE tenant_id=$1)`, owner.TenantID).Scan(&docs, &drafts, &sensorTasks)
		if docs != 0 || drafts != 0 || sensorTasks != 0 {
			return errors.New("模型执行保留原文或自动创建插件与设备任务")
		}
		return err
	}))
	candidate := first.Candidate
	var draft response.PluginVersion
	user.request("POST", "/response-plugins", "reviewed_plugin_draft", response.PluginDraft{
		ID: "reviewed_generation", Name: candidate.Name, Device: candidate.Device, Template: candidate.Template, Examples: candidate.Examples,
	}, &draft, 201)
	if draft.State != "draft" || draft.Version != 1 {
		t.Fatal("人工审阅未进入常规草稿入口")
	}
	identity := transport.SensorIdentity{TenantID: owner.TenantID, SensorID: "generation_sensor", RegistrationID: "generation_registration"}
	health, _ := json.Marshal(model.HostHealth{ObservedAt: time.Now().UTC(), CommandSignerSHA256: control.Digest(pub),
		TaskCapabilities: []string{response.PluginTrialCommand, response.PluginApplyCommand}, PluginBindings: []response.PluginBinding{
			{PluginID: draft.ID, DeviceID: "fixture_device", BindingSHA256: strings.Repeat("a", 64)},
		}})
	require(t, f.Owner.TenantTx(ctx, owner.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO sensors(tenant_id,id,name,registration_id,last_seen,health) VALUES($1,$2,'生成验收探针',$3,now(),$4)`,
			identity.TenantID, identity.SensorID, identity.RegistrationID, health)
		return err
	}))
	ops := "/response-plugins/" + draft.ID + "/operations"
	user.request("POST", ops, "unsigned_generated_draft", response.PluginOperation{SensorID: identity.SensorID, Version: 1, Action: response.PluginPublish}, nil, 409)
}

func TestPluginGenerationRechecksQueuedInputsAndNeverRepeatsUnknownCalls(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	f, owner, foreign, _ := accountFixture(t, ctx)
	provider, calls := pluginProviderFixture(t)
	defer provider.Close()
	vault, policy, config := setupPluginModel(t, ctx, f, owner, provider)
	queue, err := jobs.NewAnalysis(f.Runtime, vault, policy, nil)
	require(t, err)
	input := pluginGenerationInput()
	newTask := func() (plugingen.Args, int64) {
		t.Helper()
		job, created, err := f.Runtime.CreatePluginGeneration(ctx, owner, input, store.RandomID("plugin_job_"), queue, vault, "plugin_generation_fixture")
		require(t, err)
		if !created {
			t.Fatal("新请求未登记为独立作业")
		}
		args := plugingen.Args{TenantID: owner.TenantID, JobID: job.ID}
		var riverID int64
		require(t, f.Owner.TenantTx(ctx, args.TenantID, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT river_job_id FROM response_plugin_generations WHERE id=$1`, args.JobID).Scan(&riverID)
		}))
		return args, riverID
	}
	change := func(statement, id string) {
		t.Helper()
		require(t, f.Owner.TenantTx(ctx, owner.TenantID, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, statement, id)
			return err
		}))
	}
	read := func(args plugingen.Args, state, code string) {
		t.Helper()
		job, err := f.Runtime.PluginGeneration(ctx, owner, args.JobID)
		require(t, err)
		if job.State != state || job.Result.Code != code || job.FinishedAt == nil {
			t.Fatal("作业恢复状态不正确", job.State, job.Result.Code)
		}
	}
	absent := input
	absent.ProviderID = "absent"
	if _, _, err := f.Runtime.CreatePluginGeneration(ctx, owner, absent, "nonexistent_provider", queue, vault, "missing"); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("未登记提供方进入生成队列", err)
	}
	args, id := newTask()
	config.APIKey, config.Model = "", "fixture-plugin-model-v2"
	_, err = f.Runtime.SaveModelProvider(ctx, owner, store.ModelChange{ID: "fixture_model", ExpectedRevision: 1, Config: config}, vault, policy, "revision_change")
	require(t, err)
	if lease, err := f.Runtime.StartPluginGeneration(ctx, args, id, vault); err != nil || lease.Token != "" {
		t.Fatal("模型修订变化后排队作业仍被执行", err)
	}
	read(args, "failed", "provider_revision_changed")
	if _, _, err := f.Runtime.CreatePluginGeneration(ctx, owner, input, "stale_request", queue, vault, "stale"); !errors.Is(err, store.ErrConflict) {
		t.Fatal("客户端仍能提交过期模型修订", err)
	}
	input.ProviderRevision = 2
	for _, code := range []string{"authorization_revoked", "provider_config_unavailable", "generation_input_invalid", "queue_wait_expired"} {
		args, id := newTask()
		currentVault := vault
		switch code {
		case "authorization_revoked":
			change(`UPDATE users SET active=false WHERE id=$1`, owner.ID)
		case "provider_config_unavailable":
			currentVault = nil
		case "generation_input_invalid":
			change(`UPDATE response_plugin_generations SET input=jsonb_set(input,'{documentation}','"变化后的接口文档材料"') WHERE id=$1`, args.JobID)
		case "queue_wait_expired":
			change(`UPDATE response_plugin_generations SET deadline=now()-interval '1 second' WHERE id=$1`, args.JobID)
			_, err := f.Runtime.SweepHistory(ctx)
			require(t, err)
			require(t, f.Runtime.TenantTx(ctx, owner.TenantID, func(tx pgx.Tx) error {
				var state, result string
				var hasDocument bool
				if err := tx.QueryRow(ctx, `SELECT state,result->>'code',input ? 'documentation'
					FROM response_plugin_generations WHERE id=$1`, args.JobID).Scan(&state, &result, &hasDocument); err != nil {
					return err
				}
				if state != "failed" || result != code || hasDocument {
					t.Fatal("历史清理未回收过期请求和接口文档")
				}
				return nil
			}))
		}
		if lease, err := f.Runtime.StartPluginGeneration(ctx, args, id, currentVault); err != nil || lease.Token != "" {
			t.Fatal("资格失效的作业取得执行租约", code, err)
		}
		if code == "authorization_revoked" {
			change(`UPDATE users SET active=true WHERE id=$1`, owner.ID)
		}
		read(args, "failed", code)
	}
	running, riverID := newTask()
	if _, err := f.Runtime.StartPluginGeneration(ctx, running, riverID+10, vault); !errors.Is(err, store.ErrConflict) {
		t.Fatal("作业绑定不同的队列编号", err)
	}
	lease, err := f.Runtime.StartPluginGeneration(ctx, running, riverID, vault)
	require(t, err)
	if lease.Token == "" || lease.Request.Documentation != input.Documentation {
		t.Fatal("合法作业未取得一次性调用租约")
	}
	if again, err := f.Runtime.StartPluginGeneration(ctx, running, riverID, vault); err != nil || again.Token != "" {
		t.Fatal("同一作业取得了第二个调用租约", err)
	}
	foreignArgs := running
	foreignArgs.TenantID = foreign.TenantID
	fail := llm.Result{State: "failed", Code: "fixture_failure"}
	if err := f.Runtime.FinishPluginGeneration(ctx, foreignArgs, lease, fail, nil); !errors.Is(err, store.ErrConflict) {
		t.Fatal("跨租户保存生成结果", err)
	}
	if err := f.Runtime.FinishPluginGeneration(ctx, running, lease, llm.Result{State: "succeeded"}, nil); !errors.Is(err, plugingen.ErrOutput) {
		t.Fatal("没有候选的成功响应落库", err)
	}
	change(`UPDATE response_plugin_generations SET deadline=now()-interval '1 second' WHERE id=$1`, running.JobID)
	if err := f.Runtime.FinishPluginGeneration(ctx, running, lease, fail, nil); !errors.Is(err, store.ErrConflict) {
		t.Fatal("过期租约覆盖了可能已提交的请求状态", err)
	}
	read(running, "uncertain", "provider_result_unknown")
	if again, err := f.Runtime.StartPluginGeneration(ctx, running, riverID, vault); err != nil || again.Token != "" {
		t.Fatal("未知任务被重新调用", err)
	}
	page, err := f.Runtime.PluginGenerations(ctx, owner, "", 2)
	require(t, err)
	if len(page.Items) != 2 || page.NextCursor != page.Items[1].ID {
		t.Fatal("生成历史游标未在返回页冻结")
	}
	next, err := f.Runtime.PluginGenerations(ctx, owner, page.NextCursor, 2)
	require(t, err)
	if len(next.Items) != 2 || next.Items[0].ID == page.Items[1].ID || calls.Load() != 0 {
		t.Fatal("记录续页重复或已失效作业访问了模型")
	}
	if _, err := f.Runtime.PluginGenerations(ctx, foreign, page.NextCursor, 2); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("游标越过租户边界", err)
	}
	if _, err := f.Runtime.PluginGenerations(ctx, owner, "unknown/cursor", 10); !errors.Is(err, plugingen.ErrInput) {
		t.Fatal("非法游标进入查询", err)
	}
}
