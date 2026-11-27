//go:build integration

package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/decision"
	"github.com/kkx600/StarBeacon/internal/gatewayblock"
	"github.com/kkx600/StarBeacon/internal/jobs"
	"github.com/kkx600/StarBeacon/internal/llm"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/outbound"
	"github.com/kkx600/StarBeacon/internal/platform"
	"github.com/kkx600/StarBeacon/internal/playbook"
	responseapi "github.com/kkx600/StarBeacon/internal/response"
	"github.com/kkx600/StarBeacon/internal/secrets"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/transport"
	"github.com/kkx600/StarBeacon/internal/triage"
	"github.com/kkx600/StarBeacon/internal/watchlist"
)

func protectedPlaybookSteps(action playbook.Step) []playbook.Step {
	return []playbook.Step{
		{Kind: "protection", Name: "保护名单检查"}, {Kind: "approval", Name: "人工确认"}, action,
		{Kind: "verify", Name: "设备核验"}, {Kind: "compensate", Name: "记录租约到期"},
	}
}

func TestPlaybookManualTriageAndPluginShareDecisionAuthorization(t *testing.T) {
	ctx, stop := context.WithTimeout(t.Context(), 100*time.Second)
	defer stop()
	f, u, signer, connector, password := responseTaskFixture(t, ctx)
	es, err := store.OpenES(os.Getenv("SB_ES_URL"), os.Getenv("SB_ES_API_KEY"))
	require(t, err)
	partition := time.Now().UTC().Format("2006-01-02")
	index := sharedEventIndex(t, "alerts", partition)
	require(t, es.EnsureIndex(ctx, index, partition))
	t.Cleanup(func() { deleteTenantEvents(t, es, u.TenantID) })
	now := time.Now().UTC()
	event := model.Alert{SchemaVersion: "alert.v1", TenantID: u.TenantID, EventID: store.Hash(store.Token()), RawSHA256: store.Hash(store.Token()),
		SensorID: "sensor_response", RegistrationID: "registration_response", Timestamp: now, ObservedAt: now, ReceivedAt: now,
		Severity: "high", Source: model.Endpoint{IP: "192.0.2.28", Port: 42109}, Destination: model.Endpoint{IP: "192.0.2.34", Port: 8080}}
	event.Event.Kind, event.Event.Dataset = "alert", "suricata.eve"
	event.Rule.ID, event.Rule.Revision, event.Rule.Name = "1000001", "1", "本地 HTTP 验收告警"
	event.Network.Protocol, event.Network.Transport = "http", "tcp"
	for _, e := range es.Bulk(ctx, index, []model.Alert{event}) {
		require(t, e)
	}
	refresh, err := es.API.Indices.Refresh(es.API.Indices.Refresh.WithIndex(index), es.API.Indices.Refresh.WithContext(ctx))
	require(t, err)
	require(t, refresh.Body.Close())
	if refresh.IsError() {
		t.Fatal("发布的告警未成功刷新")
	}

	provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			Input string `json:"input"`
			Store bool   `json:"store"`
		}
		if json.NewDecoder(r.Body).Decode(&payload) != nil || payload.Store || !strings.Contains(payload.Input, "192.0.2.28") {
			w.WriteHeader(400)
			return
		}
		answer := `{"verdict":"confirmed","outcome":"attempt","confidence":0.95,"reason":"核对本次事件的原始规则引用","references":["source.ip","rule.id"],"counter_evidence":["需独立核对授权场景"],"missing":["终端结果"],"recommendation":"block_source","needs_review":true}`
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "response_playbook", "object": "response", "status": "completed", "model": "owned",
			"output": []any{map[string]any{"type": "message", "role": "assistant", "id": "message_playbook", "status": "completed",
				"content": []any{map[string]any{"type": "output_text", "text": answer, "annotations": []any{}}}}},
			"usage": map[string]int{"input_tokens": 20, "output_tokens": 30, "total_tokens": 50}})
	}))
	defer provider.Close()
	networks, err := outbound.ParseNetworks("127.0.0.0/8")
	require(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(provider.Certificate())
	outgoing := outbound.Policy{PrivateNetworks: networks, Roots: roots}
	vault, err := secrets.New(store.Token())
	require(t, err)
	queue, err := jobs.NewAnalysis(f.Runtime, vault, outgoing, es)
	require(t, err)
	require(t, queue.Start(ctx))
	defer func() {
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		require(t, queue.Stop(shutdown))
	}()
	client := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime, ES: es, Signer: signer, Vault: vault, Outbound: outgoing, Jobs: queue}, u.Username, password)
	const modelID = "provider_playbook"
	config := llm.Config{Name: "编排验收模型", Kind: "openai_responses", BaseURL: provider.URL + "/v1", Model: "owned", APIKey: "owned-fixture", Enabled: true, MaxOutputTokens: 512, TimeoutSeconds: 8, DailyRequests: 20}
	client.request("POST", "/models/providers", "", store.ModelChange{ID: modelID, Config: config, ReplaceKey: true}, nil, 200)
	input := triage.Request{EventID: event.EventID, RawSHA256: event.RawSHA256, ProviderID: modelID, ProviderRevision: 1, AllowContext: true}
	waitJob := func(id string) triage.Job {
		t.Helper()
		deadline := time.Now().Add(15 * time.Second)
		for {
			var out triage.Job
			client.request("GET", "/alert-triage/jobs/"+id, "", nil, &out, 200)
			if out.State == "succeeded" {
				return out
			}
			if out.State != "queued" && out.State != "running" || time.Now().After(deadline) {
				t.Fatal("受控模型未生成研判", out.State, out.Result.Code)
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	triagePath := "/alerts/" + event.EventID + "/triage"
	var prior, job triage.Job
	client.request("POST", triagePath, "playbook_shadow_evidence", input, &prior, 202)
	prior = waitJob(prior.ID)
	proposal := decisionPolicyInput("policy_playbook")
	proposal.Definition.Continuous = &decision.ContinuousConfig{ProviderID: modelID, ProviderRevision: 1}
	shadow, err := f.Runtime.SaveDecisionPolicy(ctx, u, "playbook_shadow_policy", proposal)
	require(t, err)
	eval := decision.EvaluationRequest{PolicyID: shadow.ID, ExpectedRevision: shadow.Revision, TriageID: prior.ID}
	_, err = f.Runtime.CreateDecisionEvaluation(ctx, u, "playbook_shadow_judgment", eval)
	require(t, err)
	promote := decisionPolicyEdit(shadow)
	promote.Definition.Mode = "approval"
	policy, err := f.Runtime.SaveDecisionPolicy(ctx, u, "playbook_approval_policy", promote)
	require(t, err)
	device := playbook.PluginBinding{Policy: playbook.PolicyBinding{ID: policy.ID, Revision: policy.Revision}, SensorID: event.SensorID,
		RegistrationID: event.RegistrationID, ConnectorID: connector.ConnectorID, ConfigSHA256: connector.ConfigSHA256, TTLSeconds: 60}
	def := playbook.Definition{Name: "从真实告警人工联动", Steps: append([]playbook.Step{
		{Kind: "trigger", Name: "告警触发"}, {Kind: "triage", Name: "AI 研判", Model: &playbook.ModelBinding{ID: modelID, Revision: 1, MinimumConfidence: .9}},
		{Kind: "condition", Name: "核对结论"},
	}, protectedPlaybookSteps(playbook.Step{Kind: "plugin", Name: "授权联动", Plugin: &device})...)}
	def.Steps = append(def.Steps, playbook.Step{Kind: "notify", Name: "人工通知"})
	var saved playbook.Record
	client.request("POST", "/playbooks", "playbook_plugin_save", playbook.Change{Definition: def}, &saved, 200)
	path := "/playbooks/" + saved.ID
	revision := playbook.Revision{Revision: saved.Revision, SHA256: saved.SHA256}
	client.request("POST", path+"/publish", "", revision, &saved, 200)
	var run playbook.Run
	client.request("POST", path+"/runs", "playbook_plugin_start", playbook.Start{Revision: revision, EventID: event.EventID, RawSHA256: event.RawSHA256}, &run, 201)
	client.request("POST", triagePath, run.StepKey, input, nil, 409)
	input.ManualOnly = true
	client.request("POST", triagePath, run.StepKey, input, &job, 202)
	job = waitJob(job.ID)
	candidates, err := f.Runtime.ContinuousDecisionCandidates(ctx, u.TenantID)
	require(t, err)
	for _, candidate := range candidates {
		if candidate.TriageID == job.ID {
			t.Fatal("编排研判进入自动候选")
		}
	}
	stepPath := "/playbook-runs/" + run.ID + "/steps"
	advance := func(i int, status int) {
		t.Helper()
		var result any
		if status == 200 {
			result = &run
		}
		client.request("POST", stepPath, "", playbook.Acknowledge{Step: i, Confirmed: true}, result, status)
	}
	for _, i := range []int{1, 2, 3, 4} {
		advance(i, 200)
	}
	eval.ExpectedRevision, eval.TriageID = policy.Revision, job.ID
	evaluation, err := f.Runtime.CreateDecisionEvaluation(ctx, u, "playbook_authorization_eval", eval)
	require(t, err)
	candidate := store.DecisionCandidate{Principal: u, Policy: policy, TriageID: job.ID}
	if _, err := f.Runtime.CompleteContinuousDecision(ctx, candidate, evaluation.ID, job.Evidence, signer); err == nil {
		t.Fatal("手工研判通过直接持续处置入口")
	}
	confirmation := decision.ResponseRequest{EvaluationSHA256: evaluation.SHA256, SensorID: device.SensorID, RegistrationID: device.RegistrationID,
		ConnectorID: device.ConnectorID, ConfigSHA256: device.ConfigSHA256, TTLSeconds: device.TTLSeconds, Reason: "核对本次限定设备和原事件", Confirmed: true}
	responsePath := "/decision-evaluations/" + evaluation.ID + "/response"
	changed := confirmation
	changed.TTLSeconds++
	client.request("POST", responsePath, run.StepKey, changed, nil, 409)
	identity := transport.SensorIdentity{TenantID: u.TenantID, SensorID: event.SensorID, RegistrationID: event.RegistrationID}
	seen := time.Now().UTC()
	require(t, f.Runtime.Heartbeat(ctx, identity, model.HostHealth{ObservedAt: seen,
		CommandSignerSHA256: control.Digest(signer.Public().(ed25519.PublicKey)), TaskCapabilities: []string{"response.block", "response.read", "response.revoke"},
		ResponseConnectors: []responseapi.Health{{ConnectorID: device.ConnectorID, DeviceID: "device_protocol", Version: "protocol-fixture/1",
			ConfigSHA256: device.ConfigSHA256, Status: "ready", ObservedAt: seen, MaxTTLSeconds: 3600}}}))
	var authorization decision.ResponseRecord
	client.request("POST", responsePath, run.StepKey, confirmation, &authorization, 202)
	action := assertFrozenResponseProtection(t, ctx, f, u.TenantID, authorization.TaskID).ResponseAction
	advance(5, 200)
	advance(6, 409)
	delivery, err := f.Runtime.NextTask(ctx, identity)
	require(t, err)
	if delivery == nil || delivery.ID != authorization.TaskID {
		t.Fatal("原签名任务不可投递")
	}
	finished := time.Now().UTC()
	result, err := json.Marshal(responseapi.Result{SchemaVersion: "response.result.v1", ConnectorID: action.ConnectorID, ConfigSHA256: action.ConfigSHA256, Verified: true, Effect: "not_observed",
		Observation: responseapi.Lease{SchemaVersion: responseapi.LeaseSchema, DeviceID: action.DeviceID, LeaseID: action.LeaseID, OwnerSHA256: action.OwnerSHA256, TargetIP: action.TargetIP, State: "active", ExpiresAt: action.ExpiresAt, ObservedAt: finished}})
	require(t, err)
	require(t, f.Runtime.SaveReceipt(ctx, identity, control.Receipt{CommandID: delivery.ID, CommandSHA256: control.Digest(delivery.Command), State: "succeeded",
		Result: result, StartedAt: finished.Add(-time.Millisecond), FinishedAt: &finished}))
	for _, i := range []int{6, 7, 8} {
		advance(i, 200)
	}
	if run.State != "completed" || run.Results[6].Outcome != "plugin_readback" || run.Results[7].LeaseUntil == nil ||
		!run.Results[7].LeaseUntil.Equal(action.ExpiresAt) {
		t.Fatal("运行未保留真实联动回执和范围", run)
	}
	strict := def
	strict.Steps = slices.Clone(def.Steps)
	strict.Steps[1].Model = &playbook.ModelBinding{ID: modelID, Revision: 1, MinimumConfidence: 1}
	client.request("PUT", path, "playbook_higher_threshold", playbook.Change{ExpectedRevision: revision.Revision, Definition: strict}, &saved, 200)
	revision = playbook.Revision{Revision: saved.Revision, SHA256: saved.SHA256}
	client.request("POST", path+"/publish", "", revision, &saved, 200)
	client.request("POST", path+"/runs", "playbook_higher_start", playbook.Start{Revision: revision, EventID: event.EventID, RawSHA256: event.RawSHA256}, &run, 201)
	client.request("POST", triagePath, run.StepKey, input, &job, 202)
	_ = waitJob(job.ID)
	client.request("POST", "/playbook-runs/"+run.ID+"/steps", "", playbook.Acknowledge{Step: 1, Confirmed: true}, &run, 200)
	if run.State != "stopped" || run.Results[1].Outcome != "below_threshold" {
		t.Fatal("低于所选门槛仍继续执行", run)
	}
}

func TestPlaybookPublicationAndGatewayAuthorizationReceipt(t *testing.T) {
	ctx, stop := context.WithTimeout(t.Context(), 90*time.Second)
	defer stop()
	scope := gatewayblock.Scope{Sources: []netip.Prefix{netip.MustParsePrefix("10.203.35.0/24")}, Destinations: []netip.Prefix{netip.MustParsePrefix("10.203.36.0/24")}}
	f := newGatewayFixture(t, ctx, scope)
	f.settings(true, 8)
	f.policies(20)
	health := (gatewayblock.LocalConfig{Enabled: true, Scope: scope}).Binding()
	f.heartbeat(&health)
	definition := playbook.Definition{Name: "真实告警网关编排", Steps: append([]playbook.Step{{Kind: "trigger", Name: "告警触发"}}, protectedPlaybookSteps(playbook.Step{Kind: "gateway", Name: "网关阻断", Gateway: &playbook.PolicyBinding{ID: testReviewPolicy, Revision: 1}})...)}
	invalid := definition
	invalid.Steps = slices.Delete(slices.Clone(invalid.Steps), 4, 5)
	var saved playbook.Record
	f.client.request("POST", "/playbooks", "playbook_create_gateway", playbook.Change{Definition: invalid}, &saved, 200)
	path := "/playbooks/" + saved.ID
	f.client.request("POST", path+"/publish", "", playbook.Revision{Revision: 1, SHA256: saved.SHA256}, nil, 409)
	f.client.request("GET", path, "", nil, &saved, 200)
	if saved.PublishedRevision != 0 {
		t.Fatal("未核验修订却已发布")
	}
	var validation struct {
		Issues []playbook.Issue `json:"issues"`
	}
	f.client.request("POST", "/playbooks/validate", "", invalid, &validation, 200)
	if len(validation.Issues) == 0 {
		t.Fatal("缺少设备核验未报告")
	}
	change := playbook.Change{ExpectedRevision: 1, Definition: definition}
	f.client.request("PUT", path, "playbook_gateway_update", change, &saved, 200)
	f.client.request("PUT", path, "playbook_gateway_update", change, &saved, 200)
	f.client.request("PUT", path, "playbook_expected_stale", change, nil, 409)
	binding := playbook.Revision{Revision: 2, SHA256: saved.SHA256}
	f.client.request("POST", path+"/publish", "", binding, &saved, 200)
	f.client.request("POST", path+"/publish", "", binding, &saved, 200)
	f.viewer.request("GET", "/playbooks", "", nil, nil, 403)
	f.peer.request("GET", path, "", nil, nil, 404)
	var page playbook.Page[playbook.Record]
	f.client.request("GET", "/playbooks?limit=10", "", nil, &page, 200)
	if len(page.Items) != 1 || page.Items[0].PublishedSHA256 != binding.SHA256 {
		t.Fatal("发布修订缺少稳定身份", page)
	}

	start := func(event model.Alert, key string) playbook.Run {
		t.Helper()
		f.indexAlerts(event)
		input := playbook.Start{Revision: binding, EventID: event.EventID, RawSHA256: event.RawSHA256}
		wrong := input
		wrong.RawSHA256 = strings.Repeat("b", 64)
		f.client.request("POST", path+"/runs", key, wrong, nil, 409)
		var run, again playbook.Run
		f.client.request("POST", path+"/runs", key, input, &run, 201)
		f.client.request("POST", path+"/runs", key, input, &again, 201)
		if again.ID != run.ID || len(run.Results) != 1 || run.Results[0].Reference != event.EventID {
			t.Fatal("恢复原提交改变了运行材料", run, again)
		}
		return run
	}
	ack := func(run *playbook.Run, index, status int) {
		t.Helper()
		var next any
		if status == 200 {
			next = run
		}
		f.client.request("POST", "/playbook-runs/"+run.ID+"/steps", "", playbook.Acknowledge{Step: index, Confirmed: true}, next, status)
	}
	prepare := func(run *playbook.Run, event model.Alert) gatewayblock.ReviewRequest {
		t.Helper()
		request := f.assessment(event, 0, "confirmed")
		f.client.request("POST", "/alerts/"+event.EventID+"/gateway-blocks", playbook.StepKey(run.ID, 3), request, nil, 409)
		ack(run, 2, 409)
		ack(run, 1, 200)
		ack(run, 2, 200)
		return request
	}
	event := f.observe("1003341", "10.203.35.8", "10.203.36.8", 42601)
	run := start(event, "playbook_gateway_start")
	request := prepare(&run, event)
	f.peer.request("GET", "/playbook-runs/"+run.ID, "", nil, nil, 404)
	endpoint := "/alerts/" + event.EventID + "/gateway-blocks"
	f.client.request("POST", endpoint, "pb_step_invalid_key", request, nil, 409)
	f.client.request("POST", endpoint, playbook.StepKey("pbr_"+strings.Repeat("a", 32), 3), request, nil, 409)
	var gateway gatewayblock.Request
	f.client.request("POST", endpoint, run.StepKey, request, &gateway, 202)
	ack(&run, 3, 200)
	ack(&run, 4, 409)
	delivery := f.next()
	_, cmd := f.command(delivery, gatewayblock.Review)
	f.receipt(delivery, gatewayblock.Result{RequestID: cmd.RequestID, ConfigSHA256: cmd.ConfigSHA256, Flow: cmd.Flow, LeaseUntil: cmd.LeaseUntil, VerifiedAt: time.Now().UTC()}, false)
	ack(&run, 4, 200)
	ack(&run, 5, 200)
	ack(&run, 5, 200)
	if r := run.Results[5]; run.State != "completed" || r.Outcome != "expiry_recorded" || r.LeaseUntil == nil || !r.LeaseUntil.Equal(cmd.LeaseUntil) {
		t.Fatal("到期记录没有绑定原设备回执", run)
	}
	var runs playbook.Page[playbook.Run]
	f.client.request("GET", "/playbook-runs?limit=10", "", nil, &runs, 200)
	if len(runs.Items) != 1 || runs.Items[0].ID != run.ID {
		t.Fatal("运行目录未关联回执", runs)
	}

	event2 := f.observe("1003341", "10.203.35.9", "10.203.36.9", 42602)
	stopRun := start(event2, "playbook_observe_start")
	request2 := prepare(&stopRun, event2)
	endpoint2 := "/alerts/" + event2.EventID + "/gateway-blocks"
	f.client.request("POST", endpoint2, stopRun.StepKey, request2, &gateway, 202)
	ack(&stopRun, 3, 200)
	paused := false
	f.client.request("PUT", "/decision-automation", "", decision.AutomationChange{Ceiling: decision.Observe, Paused: &paused}, nil, 200)
	f.blocked(event2.EventID, "authorization_revoked")
	ack(&stopRun, 4, 200)
	if stopRun.State != "stopped" || stopRun.Results[4].Outcome != "authorization_denied" {
		t.Fatal("切换到仅观察后仍签发编排任务", stopRun)
	}
	// 源和目标中的任何一个命中保护名单，均不能进入人工确认。
	protected := watchlistInput("playbook_protected")
	protected.Definition.Values = []string{"10.203.36.7"}
	protected.Definition.Sensors = []watchlist.Sensor{{SensorID: f.id.SensorID, RegistrationID: f.id.RegistrationID}}
	f.client.request("POST", "/watchlists", "playbook_target_protect", protected, nil, 200)
	event3 := f.observe("1003341", "10.203.35.9", "10.203.36.7", 42603)
	protectRun := start(event3, "playbook_protect_start")
	ack(&protectRun, 1, 200)
	if protectRun.State != "stopped" || protectRun.Results[1].Outcome != "protected" {
		t.Fatal("保护名单未停止编排", protectRun)
	}
	var settings decision.AutomationState
	f.client.request("GET", "/decision-automation", "", nil, &settings, 200)
	if settings.Settings.Ceiling != decision.Observe {
		t.Fatal("验收未使用实际仅观察状态")
	}
}

func TestPlaybookTransactionsKeepFrozenRevisionAndScopedProgress(t *testing.T) {
	ctx, stop := context.WithTimeout(t.Context(), 100*time.Second)
	defer stop()
	scope := gatewayblock.Scope{Sources: []netip.Prefix{netip.MustParsePrefix("10.203.35.0/24")}, Destinations: []netip.Prefix{netip.MustParsePrefix("10.203.36.0/24")}}
	f := newGatewayFixture(t, ctx, scope)
	f.settings(true, 8)
	f.policies(20)
	binding := playbook.PolicyBinding{ID: testReviewPolicy, Revision: 1}
	def := playbook.Definition{Name: "原始发布修订", Steps: append([]playbook.Step{{Kind: "trigger", Name: "告警"}},
		protectedPlaybookSteps(playbook.Step{Kind: "gateway", Name: "确认网关策略", Gateway: &binding})...)}
	u := f.user
	tenant := u.TenantID
	event := f.observe("1003341", "10.203.35.12", "10.203.36.12", 42612)
	f.indexAlerts(event)
	event, err := f.es.ReadAlertEvidence(ctx, tenant, event.EventID, event.RawSHA256)
	require(t, err)

	snapshot := func() string {
		t.Helper()
		var value string
		require(t, f.db.Owner.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT jsonb_build_array(
				(SELECT jsonb_agg(to_jsonb(h) ORDER BY id) FROM playbooks h WHERE tenant_id=$1),
				(SELECT jsonb_agg(to_jsonb(v) ORDER BY playbook_id,revision) FROM playbook_revisions v WHERE tenant_id=$1),
				(SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM playbook_runs r WHERE tenant_id=$1)
			)::text`, tenant).Scan(&value)
		}))
		return value
	}
	fail := func(name string, prefixes []string, run func(*store.Postgres) error) {
		t.Helper()
		for _, prefix := range prefixes {
			t.Run(name+"/"+prefix, func(t *testing.T) {
				before := snapshot()
				db, trace := disconnectedStore(t, ctx, f.db.RuntimeDSN, prefix)
				if err := run(db); err == nil || !trace.fired.Load() {
					t.Fatalf("故障未在目标事务内生效：%v", err)
				}
				if snapshot() != before {
					t.Fatal("失败请求留下了编排或运行变更")
				}
			})
		}
	}
	create := playbook.Change{Definition: def}
	fail("草稿创建", []string{"SELECT u.active,u.role", "SELECT pg_advisory_xact_lock(", "SELECT count(*) FROM playbooks", "INSERT INTO playbooks", "INSERT INTO playbook_revisions", "INSERT INTO operation_audits"},
		func(db *store.Postgres) error {
			_, err := db.SavePlaybook(ctx, u, "", "playbook_fault_create", create)
			return err
		})
	record, err := f.db.Runtime.SavePlaybook(ctx, u, "", "playbook_frozen_create", create)
	require(t, err)
	fail("目录", []string{"SELECT u.active,u.role", "SELECT h.id,h.owner_id"}, func(db *store.Postgres) error {
		_, err := db.Playbooks(ctx, u, "", 20)
		return err
	})
	fail("详情", []string{"SELECT u.active,u.role", "SELECT h.id,h.owner_id"}, func(db *store.Postgres) error {
		_, err := db.Playbook(ctx, u, record.ID)
		return err
	})
	fail("校验", []string{"SELECT u.active,u.role"}, func(db *store.Postgres) error {
		_, err := db.ValidatePlaybook(ctx, u, def)
		return err
	})
	version := playbook.Revision{Revision: record.Revision, SHA256: record.SHA256}
	fail("发布", []string{"SELECT h.id,h.owner_id", "UPDATE playbooks SET published_revision", "INSERT INTO operation_audits"},
		func(db *store.Postgres) error {
			_, _, err := db.PublishPlaybook(ctx, u, record.ID, version)
			return err
		})
	_, issues, err := f.db.Runtime.PublishPlaybook(ctx, u, record.ID, version)
	require(t, err)
	if len(issues) != 0 {
		t.Fatal(issues)
	}
	input := playbook.Start{Revision: version, EventID: event.EventID, RawSHA256: event.RawSHA256}
	fail("启动", []string{"SELECT pg_advisory_xact_lock(", "SELECT v.definition", "SELECT count(*) FROM playbook_runs", "INSERT INTO playbook_runs", "INSERT INTO operation_audits"},
		func(db *store.Postgres) error {
			_, err := db.StartPlaybookRun(ctx, u, record.ID, "playbook_fault_start", input, event)
			return err
		})
	run, err := f.db.Runtime.StartPlaybookRun(ctx, u, record.ID, "playbook_frozen_start", input, event)
	require(t, err)
	change := playbook.Change{ExpectedRevision: version.Revision, Definition: def}
	change.Definition.Name = "后续编辑"
	fail("草稿更新", []string{"UPDATE playbooks SET revision=revision+1", "INSERT INTO playbook_revisions"},
		func(db *store.Postgres) error {
			_, err := db.SavePlaybook(ctx, u, record.ID, "playbook_fault_change", change)
			return err
		})
	updated, err := f.db.Runtime.SavePlaybook(ctx, u, record.ID, "playbook_frozen_edit", change)
	require(t, err)
	if updated.Revision != 2 || updated.PublishedRevision != 1 {
		t.Fatal("编辑覆盖了已发布修订")
	}
	frozen, err := f.db.Runtime.PlaybookRun(ctx, u, run.ID)
	require(t, err)
	if frozen.Definition.Name != def.Name || frozen.SHA256 != version.SHA256 {
		t.Fatal("运行原版本被后续编辑改写")
	}
	ack := playbook.Acknowledge{Step: 1, Confirmed: true}
	fail("推进", []string{"SELECT r.id,r.playbook_id", "SELECT current_setting(", "UPDATE playbook_runs SET results", "INSERT INTO operation_audits"},
		func(db *store.Postgres) error { _, err := db.AcknowledgePlaybookStep(ctx, u, run.ID, ack); return err })
	_, err = f.db.Runtime.AcknowledgePlaybookStep(ctx, u, run.ID, ack)
	require(t, err)
	second, err := f.db.Runtime.StartPlaybookRun(ctx, u, record.ID, "playbook_frozen_next", input, event)
	require(t, err)
	firstPage, err := f.db.Runtime.PlaybookRuns(ctx, u, "", 1)
	require(t, err)
	secondPage, err := f.db.Runtime.PlaybookRuns(ctx, u, firstPage.NextCursor, 1)
	require(t, err)
	if len(firstPage.Items) != 1 || len(secondPage.Items) != 1 || firstPage.Items[0].ID != second.ID || secondPage.Items[0].ID != run.ID {
		t.Fatal("运行分页重复或失序")
	}
	fail("运行列表", []string{"SELECT created_at FROM playbook_runs", "SELECT r.id,r.playbook_id"}, func(db *store.Postgres) error {
		_, err := db.PlaybookRuns(ctx, u, firstPage.NextCursor, 1)
		return err
	})
	fail("运行详情", []string{"SELECT r.id,r.playbook_id"}, func(db *store.Postgres) error {
		_, err := db.PlaybookRun(ctx, u, run.ID)
		return err
	})

	stale := slices.Clone(def.Steps)
	stale[3].Gateway = &playbook.PolicyBinding{ID: testReviewPolicy, Revision: 2}
	missing, err := f.db.Runtime.ValidatePlaybook(ctx, u, playbook.Definition{Name: "网关配置来自历史修订", Steps: stale})
	require(t, err)
	if len(missing) != 1 || missing[0].Code != "gateway_current" {
		t.Fatal("当前网关绑定变更未阻止发布", missing)
	}
	// 已有提交键不可绑定到修改过的定义或新的真实告警。
	if _, err = f.db.Runtime.SavePlaybook(ctx, u, "", "playbook_frozen_create", playbook.Change{Definition: change.Definition}); !errors.Is(err, store.ErrConflict) {
		t.Fatal(err)
	}
	wrongVersion := version
	wrongVersion.SHA256 = strings.Repeat("0", 64)
	if _, _, err = f.db.Runtime.PublishPlaybook(ctx, u, record.ID, wrongVersion); !errors.Is(err, store.ErrConflict) {
		t.Fatal(err)
	}
	p := f.db.Runtime
	viewer := u
	viewer.Role = "viewer"
	for _, op := range []struct {
		name     string
		expected error
		call     func() error
	}{
		{"编排错误游标", playbook.ErrInput, func() error { _, e := p.Playbooks(ctx, u, "bad.cursor", 20); return e }},
		{"非法详情编号", playbook.ErrInput, func() error { _, e := p.Playbook(ctx, u, "bad.id"); return e }},
		{"非法草稿", playbook.ErrInput, func() error { _, e := p.SavePlaybook(ctx, u, "", "invalid_draft", playbook.Change{}); return e }},
		{"非法校验配置", playbook.ErrInput, func() error { _, e := p.ValidatePlaybook(ctx, u, playbook.Definition{}); return e }},
		{"非法发布修订", playbook.ErrInput, func() error { _, _, e := p.PublishPlaybook(ctx, u, record.ID, playbook.Revision{}); return e }},
		{"非法运行查询", playbook.ErrInput, func() error { _, e := p.PlaybookRuns(ctx, u, "bad.cursor", 20); return e }},
		{"非法运行编号", playbook.ErrInput, func() error { _, e := p.PlaybookRun(ctx, u, "bad.id"); return e }},
		{"非法运行告警", playbook.ErrInput, func() error {
			_, e := p.StartPlaybookRun(ctx, u, record.ID, "invalid_start", input, model.Alert{})
			return e
		}},
		{"缺少人工确认", playbook.ErrInput, func() error {
			_, e := p.AcknowledgePlaybookStep(ctx, u, run.ID, playbook.Acknowledge{Step: 1})
			return e
		}},
		{"查看者不能启动", playbook.ErrPermission, func() error {
			_, e := p.StartPlaybookRun(ctx, viewer, record.ID, "viewer_start", input, event)
			return e
		}},
		{"查看者不能读运行目录", playbook.ErrPermission, func() error { _, e := p.PlaybookRuns(ctx, viewer, "", 20); return e }},
		{"查看者不能读运行详情", playbook.ErrPermission, func() error { _, e := p.PlaybookRun(ctx, viewer, run.ID); return e }},
		{"查看者不能推进", playbook.ErrPermission, func() error { _, e := p.AcknowledgePlaybookStep(ctx, viewer, run.ID, ack); return e }},
		{"查看者不能发布", playbook.ErrPermission, func() error { _, _, e := p.PublishPlaybook(ctx, viewer, record.ID, version); return e }},
	} {
		t.Run(op.name, func(t *testing.T) {
			if err := op.call(); !errors.Is(err, op.expected) {
				t.Fatalf("期望 %v，实际 %v", op.expected, err)
			}
		})
	}

	// 模拟损坏的持久状态。即便记录仍存在，错误来源也不能当作可读草稿或运行证据。
	require(t, f.db.Owner.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE playbook_runs SET results=jsonb_set(results,'{0,kind}','"plugin"'::jsonb) WHERE tenant_id=$1 AND id=$2`, tenant, run.ID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE playbook_revisions SET sha256=$3 WHERE tenant_id=$1 AND playbook_id=$2`, tenant, record.ID, wrongVersion.SHA256)
		return err
	}))
	if _, err = p.PlaybookRun(ctx, u, run.ID); !errors.Is(err, playbook.ErrSource) {
		t.Fatal("损坏运行绑定仍被接受", err)
	}
	if _, err = p.Playbook(ctx, u, record.ID); !errors.Is(err, playbook.ErrSource) {
		t.Fatal("损坏草稿仍被接受", err)
	}
	input.Revision = wrongVersion
	if _, err = p.StartPlaybookRun(ctx, u, record.ID, "corrupt_revision_start", input, event); !errors.Is(err, playbook.ErrSource) {
		t.Fatal("损坏发布仍启动运行", err)
	}
}
