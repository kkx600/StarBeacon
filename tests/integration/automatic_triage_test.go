//go:build integration

package integration

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	sensorv1 "github.com/kkx600/StarBeacon/api/sensor/v1"
	"github.com/kkx600/StarBeacon/internal/bus"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/decision"
	"github.com/kkx600/StarBeacon/internal/jobs"
	"github.com/kkx600/StarBeacon/internal/llm"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/normalize"
	"github.com/kkx600/StarBeacon/internal/outbound"
	"github.com/kkx600/StarBeacon/internal/platform"
	"github.com/kkx600/StarBeacon/internal/secrets"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/triage"
	"github.com/kkx600/StarBeacon/internal/worker"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestAutomaticTriageIndexedEvidenceConcurrencyQuotaAndContinuousDecision(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	f, u, signer, response, password := responseTaskFixture(t, ctx)
	vault, err := secrets.New(store.Token())
	require(t, err)
	provider, calls := newTriageProvider(t)
	defer provider.Close()
	roots := x509.NewCertPool()
	roots.AddCert(provider.Certificate())
	networks, err := outbound.ParseNetworks("127.0.0.0/8")
	require(t, err)
	outboundPolicy := outbound.Policy{Roots: roots, PrivateNetworks: networks}
	config := llm.Config{Name: "自动告警研判协议", Kind: "openai_responses", BaseURL: provider.URL + "/v1", Model: "owned-triage-model", Enabled: true, APIKey: "owned-triage-key", MaxOutputTokens: 512, TimeoutSeconds: 5, DailyRequests: 1}
	_, err = f.Runtime.SaveModelProvider(ctx, u, store.ModelChange{ID: "provider_auto", ReplaceKey: true, Config: config}, vault, outboundPolicy, "seed")
	require(t, err)
	change := decisionPolicyInput("policy_auto")
	change.Definition.Mode = "automatic"
	change.Definition.Continuous = &decision.ContinuousConfig{ProviderID: "provider_auto", ProviderRevision: 1, Automatic: &decision.AutomaticConfig{SensorID: "sensor_response", RegistrationID: "registration_response", ConnectorID: response.ConnectorID, ConfigSHA256: response.ConfigSHA256, TTLSeconds: 60, CooldownSeconds: 3600, MaxHourlyActions: 1, AcceptUncalibratedScore: true}, Trigger: &decision.TriageTrigger{Severities: []string{"high"}, MaxDailyJobs: 2, AllowModelContext: true}}
	policy, err := f.Runtime.SaveDecisionPolicy(ctx, u, "auto_enable", change)
	require(t, err)
	es, err := store.OpenES(os.Getenv("SB_ES_URL"), "")
	require(t, err)
	now := time.Now().UTC()
	index, err := contract.IndexName(u.TenantID, "alerts", now.Format("2006-01-02"))
	require(t, err)
	require(t, es.EnsureIndex(ctx, index, now.Format("2006-01-02")))
	t.Cleanup(func() {
		c, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		res, err := es.API.Indices.Delete([]string{index}, es.API.Indices.Delete.WithContext(c))
		require(t, err)
		res.Body.Close()
	})
	alert := model.Alert{EventID: "event_auto", TenantID: u.TenantID, RawSHA256: store.Hash("automatic-evidence"), SensorID: "sensor_response", RegistrationID: "registration_response", Timestamp: now, ObservedAt: now, ReceivedAt: now, Severity: "high", Source: model.Endpoint{IP: "192.0.2.10"}, Destination: model.Endpoint{IP: "198.51.100.20"}}
	alert.Event.Kind, alert.Event.Original, alert.Rule.ID = "alert", `{"private":"must-not-send"}`, "1000001"
	data := []byte(fmt.Sprintf(`{"timestamp":%q,"event_type":"alert","src_ip":"192.0.2.10","dest_ip":"198.51.100.20","proto":"TCP","alert":{"signature_id":1000001,"severity":1},"private":"must-not-send"}`, now.Format(time.RFC3339Nano)))
	digest := sha256.Sum256(data)
	record := &sensorv1.EventRecord{EventId: contract.EventID(u.TenantID, alert.RegistrationID, "generation_auto", 0, 0), SourceGenerationId: "generation_auto", Sequence: 1, Payload: data, RawSha256: digest[:], PayloadSha256: digest[:], PayloadSchema: "suricata.eve.v1", ContentType: "application/json", EventType: "alert", EventTime: timestamppb.New(now), ObservedAt: timestamppb.New(now)}
	alert, err = normalize.Normalize(u.TenantID, alert.SensorID, alert.RegistrationID, record, now)
	require(t, err)
	nats, err := bus.OpenNamespace(ctx, os.Getenv("SB_NATS_URL"), store.RandomID("it_auto_"))
	require(t, err)
	require(t, nats.Ensure(ctx, 1, 16<<20))
	t.Cleanup(func() {
		c, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		defer nats.Close()
		for _, stream := range []string{bus.Alerts, bus.Context, bus.Quarantine, bus.Indexed} {
			require(t, nats.JS.DeleteStream(c, nats.StreamName(stream)))
		}
	})
	batch := &sensorv1.EventBatch{SensorId: alert.SensorID, SensorRegistrationId: alert.RegistrationID, StreamId: "alerts", ProducerEpoch: "epoch_auto", SchemaVersion: "1.0", RouteToken: "owned-route", Records: []*sensorv1.EventRecord{record}}
	contract.Seal(batch)
	encoded, err := proto.Marshal(batch)
	require(t, err)
	envelope, err := json.Marshal(bus.Envelope{TenantID: u.TenantID, Batch: encoded, Partition: now.Format("2006-01-02"), ReceivedAt: now})
	require(t, err)
	indexer := &worker.Indexer{Bus: nats, ES: es, DB: f.Runtime}
	indexAlert := func(v model.Alert) {
		for _, err := range es.Bulk(ctx, index, []model.Alert{v}) {
			require(t, err)
		}
		res, err := es.API.Indices.Refresh(es.API.Indices.Refresh.WithIndex(index), es.API.Indices.Refresh.WithContext(ctx))
		require(t, err)
		if res.IsError() {
			t.Fatal("自动研判材料刷新失败", res.StatusCode)
		}
		res.Body.Close()
	}
	for _, alter := range []func(*model.Alert){func(v *model.Alert) { v.SensorID = "sensor_other" }, func(v *model.Alert) { v.RegistrationID = "new_registration" }, func(v *model.Alert) { v.TenantID = "other" }, func(v *model.Alert) { v.Severity = "low" }, func(v *model.Alert) { v.ObservedAt = policy.CreatedAt.Add(-time.Minute) }, func(v *model.Alert) { v.ReceivedAt = policy.CreatedAt.Add(-time.Minute) }} {
		other := alert
		alter(&other)
		require(t, f.Runtime.RecordAutomaticTriage(ctx, u.TenantID, []model.Alert{other}))
	}
	before, err := f.Runtime.AutomaticTriageCandidates(ctx, u.TenantID)
	require(t, err)
	if len(before) != 0 {
		t.Fatal("历史、异租户、其他探针或非指定等级触发了研判")
	}
	require(t, indexer.Process(ctx, envelope))
	require(t, indexer.Process(ctx, envelope))
	res, err := es.API.Indices.Refresh(es.API.Indices.Refresh.WithIndex(index), es.API.Indices.Refresh.WithContext(ctx))
	require(t, err)
	res.Body.Close()
	var wg sync.WaitGroup
	failures := make(chan error, 2)
	for range 2 {
		wg.Go(func() { failures <- f.Runtime.RecordAutomaticTriage(ctx, u.TenantID, []model.Alert{alert}) })
	}
	wg.Wait()
	for range 2 {
		require(t, <-failures)
	}
	candidates, err := f.Runtime.AutomaticTriageCandidates(ctx, u.TenantID)
	require(t, err)
	if len(candidates) != 1 {
		t.Fatal("并发索引重投未形成唯一触发", len(candidates))
	}
	queue, err := jobs.NewAnalysisWithTriage(f.Runtime, vault, outboundPolicy, es)
	require(t, err)
	evidence, err := triage.Freeze(alert)
	require(t, err)
	type outcome struct {
		job triage.Job
		err error
	}
	jobsCreated := make(chan outcome, 2)
	for range 2 {
		wg.Go(func() {
			j, err := f.Runtime.CreateAutomaticAlertTriage(ctx, candidates[0], evidence, queue, vault)
			jobsCreated <- outcome{j, err}
		})
	}
	wg.Wait()
	var job triage.Job
	passed, conflicts := 0, 0
	for range 2 {
		result := <-jobsCreated
		if result.err == nil {
			passed++
			job = result.job
		} else if errors.Is(result.err, store.ErrConflict) {
			conflicts++
		} else {
			t.Fatal(result.err)
		}
	}
	if passed != 1 || conflicts != 1 || job.ID == "" || calls.Load() != 0 {
		t.Fatal("重复提交或未经队列开始就调用模型")
	}
	require(t, queue.Start(ctx))
	t.Cleanup(func() {
		c, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		require(t, queue.StopAndCancel(c))
	})
	eventually(t, ctx, "索引告警自动进入真实 HTTPS 模型队列", func() bool {
		var err error
		job, err = f.Runtime.AlertTriage(ctx, u, job.ID)
		require(t, err)
		return job.State == "succeeded"
	})
	if calls.Load() != 1 || job.Answer == nil || job.Answer.Outcome != "attempt" || job.Evidence.SHA256 != evidence.SHA256 {
		t.Fatal("自动研判次数、结论或材料来源不一致")
	}
	api := &platform.API{DB: f.Runtime, ES: es, Vault: vault, Jobs: queue, Signer: signer}
	_, _, err = api.SweepContinuousDecisions(ctx, "")
	require(t, err)
	page, err := f.Runtime.DecisionEvaluations(ctx, u, decision.EvaluationQuery{PolicyID: policy.ID, TriageID: job.ID, Limit: 20})
	require(t, err)
	if len(page.Items) != 1 {
		t.Fatal("自动研判没有进入持续判断")
	}
	run, err := f.Runtime.ContinuousDecision(ctx, u, page.Items[0].ID)
	require(t, err)
	if run == nil || run.State != "queued" || run.TaskID == "" {
		t.Fatal("未形成独立签名任务授权", run)
	}
	second := alert
	second.EventID, second.RawSHA256 = "event_auto_second", store.Hash("second-evidence")
	indexAlert(second)
	require(t, f.Runtime.RecordAutomaticTriage(ctx, u.TenantID, []model.Alert{second}))
	submitted, err := api.SweepAutomaticTriages(ctx, u.TenantID)
	require(t, err)
	if submitted != 0 || calls.Load() != 1 {
		t.Fatal("模型每日费用额度没有共享")
	}
	var quotaCode string
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT code FROM decision_triage_triggers WHERE tenant_id=$1 AND event_id=$2`, u.TenantID, second.EventID).Scan(&quotaCode))
	if quotaCode != "model_quota" {
		t.Fatal("模型额度拒绝没有持久反馈", quotaCode)
	}
	third := alert
	third.EventID, third.RawSHA256 = "event_auto_third", store.Hash("third-evidence")
	require(t, f.Runtime.RecordAutomaticTriage(ctx, u.TenantID, []model.Alert{third}))
	var count int
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT count(*) FROM decision_triage_triggers WHERE tenant_id=$1`, u.TenantID).Scan(&count))
	if count != 2 {
		t.Fatal("自动研判每日登记额度被绕过", count)
	}
	pageTriggers, err := f.Runtime.AutomaticTriages(ctx, u, policy.ID, policy.Revision, "")
	require(t, err)
	if len(pageTriggers.Items) != 2 || pageTriggers.Next != "" {
		t.Fatal("触发记录不能反映已提交与额度拒绝")
	}
	client := authenticatedFaultHTTP(t, ctx, f.Runtime, api, u.Username, password)
	client.request("GET", "/decision-policies/"+policy.ID+"/revisions/1/triggers", "", nil, &pageTriggers, 200)
	if len(pageTriggers.Items) != 2 {
		t.Fatal("自动研判 HTTP 目录缺失")
	}
	other := u
	other.Role = "viewer"
	if _, err := f.Runtime.AutomaticTriages(ctx, other, policy.ID, policy.Revision, ""); !errors.Is(err, decision.ErrPermission) {
		t.Fatal("只读账号读取了私有自动研判记录", err)
	}
	if f.Runtime.RecordAutomaticTriage(ctx, "/", nil) == nil || f.Runtime.RecordAutomaticTriage(ctx, u.TenantID, make([]model.Alert, 501)) == nil {
		t.Fatal("无效租户或超预算批次进入触发登记")
	}
	if err := f.Runtime.SkipAutomaticTriage(ctx, candidates[0], "arbitrary"); err == nil {
		t.Fatal("不受控跳过原因被接受")
	}
}

func TestAutomaticTriageRevocationBeforeChargingAndNoHistoricalReactivation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	f, u, _, response, _ := responseTaskFixture(t, ctx)
	vault, err := secrets.New(store.Token())
	require(t, err)
	config := llm.Config{Name: "待执行许可核对", Kind: "openai_responses", BaseURL: "https://models.example.com/v1", Model: "owned", Enabled: true, APIKey: "owned-key", MaxOutputTokens: 512, TimeoutSeconds: 5, DailyRequests: 1000}
	_, err = f.Runtime.SaveModelProvider(ctx, u, store.ModelChange{ID: "provider_revocation", ReplaceKey: true, Config: config}, vault, outbound.Policy{}, "seed")
	require(t, err)
	change := decisionPolicyInput("policy_revocation")
	change.Definition.Mode = "automatic"
	change.Definition.Continuous = &decision.ContinuousConfig{ProviderID: "provider_revocation", ProviderRevision: 1, Automatic: &decision.AutomaticConfig{SensorID: "sensor_response", RegistrationID: "registration_response", ConnectorID: response.ConnectorID, ConfigSHA256: response.ConfigSHA256, TTLSeconds: 60, CooldownSeconds: 3600, MaxHourlyActions: 1, AcceptUncalibratedScore: true}, Trigger: &decision.TriageTrigger{Severities: []string{"high"}, MaxDailyJobs: 10, AllowModelContext: true}}
	policy, err := f.Runtime.SaveDecisionPolicy(ctx, u, "revocation_enable", change)
	require(t, err)
	queue, err := jobs.NewAnalysisWithTriage(f.Runtime, vault, outbound.Policy{}, nil)
	require(t, err)
	admit := func(event string) (store.AutomaticTriageCandidate, triage.Evidence) {
		now := time.Now().UTC()
		alert := model.Alert{EventID: event, TenantID: u.TenantID, RawSHA256: store.Hash(event), SensorID: "sensor_response", RegistrationID: "registration_response", Timestamp: now, ObservedAt: now, ReceivedAt: now, Severity: "high"}
		alert.Event.Kind = "alert"
		require(t, f.Runtime.RecordAutomaticTriage(ctx, u.TenantID, []model.Alert{alert}))
		rows, err := f.Runtime.AutomaticTriageCandidates(ctx, u.TenantID)
		require(t, err)
		for _, c := range rows {
			if c.EventID == event {
				e, err := triage.Freeze(alert)
				require(t, err)
				return c, e
			}
		}
		t.Fatal("许可范围内的新告警未登记")
		return store.AutomaticTriageCandidate{}, triage.Evidence{}
	}
	first, evidence := admit("event_before_revision")
	job, err := f.Runtime.CreateAutomaticAlertTriage(ctx, first, evidence, queue, vault)
	require(t, err)
	edit := decisionPolicyEdit(policy)
	edit.Description = "仅在本修订范围内处理"
	policy, err = f.Runtime.SaveDecisionPolicy(ctx, u, "revocation_revision", edit)
	require(t, err)
	var riverID int64
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT river_job_id FROM alert_triage_jobs WHERE tenant_id=$1 AND id=$2`, u.TenantID, job.ID).Scan(&riverID))
	lease, err := f.Runtime.StartAlertTriage(ctx, triage.Args{TenantID: u.TenantID, JobID: job.ID}, riverID, vault)
	require(t, err)
	job, err = f.Runtime.AlertTriage(ctx, u, job.ID)
	require(t, err)
	if lease.Execute || job.State != "failed" || job.Result.Code != "authorization_revoked" {
		t.Fatal("策略修订后仍尝试收费执行", lease.Execute, job.State, job.Result.Code)
	}
	second, evidence := admit("event_before_stop")
	edit = decisionPolicyEdit(policy)
	inactive := false
	edit.Active = &inactive
	policy, err = f.Runtime.SaveDecisionPolicy(ctx, u, "revocation_stop", edit)
	require(t, err)
	if _, err := f.Runtime.CreateAutomaticAlertTriage(ctx, second, evidence, queue, vault); !errors.Is(err, store.ErrConflict) {
		t.Fatal("登记后撤回许可仍提交模型队列", err)
	}
	rows, err := f.Runtime.AutomaticTriageCandidates(ctx, u.TenantID)
	require(t, err)
	if len(rows) != 0 {
		t.Fatal("已停用触发仍等待执行")
	}
	edit = decisionPolicyEdit(policy)
	active := true
	edit.Active = &active
	policy, err = f.Runtime.SaveDecisionPolicy(ctx, u, "revocation_reenable", edit)
	require(t, err)
	rows, err = f.Runtime.AutomaticTriageCandidates(ctx, u.TenantID)
	require(t, err)
	if len(rows) != 0 {
		t.Fatal("重新启用补发了旧许可的收费作业")
	}
	third, evidence := admit("event_stale")
	require(t, f.Owner.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE decision_triage_triggers SET created_at=now()-interval '16 minutes' WHERE tenant_id=$1 AND id=$2`, u.TenantID, third.ID)
		return err
	}))
	if _, err := f.Runtime.CreateAutomaticAlertTriage(ctx, third, evidence, queue, vault); !errors.Is(err, store.ErrConflict) {
		t.Fatal("过期登记仍提交收费队列", err)
	}
	count, err := (&platform.API{DB: f.Runtime}).SweepAutomaticTriages(ctx, u.TenantID)
	require(t, err)
	var staleState string
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT state FROM decision_triage_triggers WHERE tenant_id=$1 AND id=$2`, u.TenantID, third.ID).Scan(&staleState))
	if count != 0 || staleState != "skipped" {
		t.Fatal("执行服务不可用时过期许可未停止等待", count, staleState)
	}
	rows, err = f.Runtime.AutomaticTriageCandidates(ctx, u.TenantID)
	require(t, err)
	if len(rows) != 0 {
		t.Fatal("过期登记没有明确失去执行资格")
	}
	bad := third
	bad.RawSHA256 = store.Hash("changed")
	if _, err := f.Runtime.CreateAutomaticAlertTriage(ctx, bad, evidence, queue, vault); !errors.Is(err, decision.ErrSource) {
		t.Fatal("原材料摘要变化被接受", err)
	}
}
