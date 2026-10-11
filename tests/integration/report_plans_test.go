//go:build integration

package integration

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/admin"
	"github.com/kkx600/StarBeacon/internal/analytics"
	"github.com/kkx600/StarBeacon/internal/assistant"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/jobs"
	"github.com/kkx600/StarBeacon/internal/llm"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/outbound"
	"github.com/kkx600/StarBeacon/internal/platform"
	"github.com/kkx600/StarBeacon/internal/secrets"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/redis/go-redis/v9"
)

// 日历边界由纯单元测试核对；此处只在专属测试数据库移动到期槽位，不等待自然日。
// 调度、统计、租户作用域、队列恢复和模型协议仍经真实 PG/Redis/ES 与 HTTP 执行。
func TestReportPlansDurableCalendarRecoveryOwnershipAndModelBudget(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	fixture := newIsolatedDatabase(t, ctx)
	db, owner := fixture.Runtime, fixture.Owner
	tenant, foreign, password := store.RandomID("it_plan_"), store.RandomID("it_plan_b_"), store.Token()
	for _, account := range []struct{ tenant, username, role string }{{tenant, tenant, "admin"}, {tenant, tenant + "_other", "admin"}, {tenant, tenant + "_viewer", "viewer"}, {foreign, foreign, "admin"}} {
		require(t, admin.Bootstrap(ctx, owner, account.tenant, "报告计划验收", account.username, password, account.role))
	}
	es, err := store.OpenES(os.Getenv("SB_ES_URL"), os.Getenv("SB_ES_API_KEY"))
	require(t, err)
	options, err := redis.ParseURL(os.Getenv("SB_REDIS_URL"))
	require(t, err)
	options.DB = 12
	cache := redis.NewClient(options)
	defer cache.Close()
	vault, err := secrets.New(store.Token())
	require(t, err)
	var calls atomic.Int32
	provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var input struct {
			Model string `json:"model"`
			Input string `json:"input"`
			Store bool   `json:"store"`
		}
		if r.URL.Path != "/v1/responses" || r.Header.Get("Authorization") != "Bearer owned-plan-key" || json.NewDecoder(io.LimitReader(r.Body, 32769)).Decode(&input) != nil || input.Model != "owned-plan-model" || input.Store || !strings.Contains(input.Input, "alerts.total") {
			w.WriteHeader(400)
			return
		}
		text := `{"summary":"检测记录需要结合原始证据核实。","observations":[{"text":"规则命中不代表攻击成功。","sources":["alerts.total"]}],"recommendations":[{"text":"核对探针覆盖与原始证据。","sources":["window"]}]}`
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "plan_response", "object": "response", "status": "completed", "model": "owned-plan-model", "output": []any{map[string]any{"type": "message", "role": "assistant", "id": "plan_message", "status": "completed", "content": []any{map[string]any{"type": "output_text", "text": text, "annotations": []any{}}}}}, "usage": map[string]int{"input_tokens": 30, "output_tokens": 40, "total_tokens": 70}})
	}))
	defer provider.Close()
	networks, err := outbound.ParseNetworks("127.0.0.0/8")
	require(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(provider.Certificate())
	policy := outbound.Policy{PrivateNetworks: networks, Roots: roots}
	auth := httpapi.NewAuth(db, cache, "", "it_report_plan", false)
	api := &platform.API{DB: db, ES: es, Redis: cache, Auth: auth, Vault: vault, Outbound: policy}
	var preparations atomic.Int32
	snapshot := func(ctx context.Context, user model.Principal, window analytics.Window) (analytics.Snapshot, error) {
		if preparations.Add(1) == 1 {
			return analytics.Snapshot{}, errors.New("受控统计准备连接中断")
		}
		return api.Overview(ctx, user, window)
	}
	queue, err := jobs.NewAnalysis(db, vault, policy, snapshot)
	require(t, err)
	api.Jobs = queue
	server := httptest.NewServer(httpapi.Middleware(api.Handler()))
	defer server.Close()
	auth.Origin = server.URL
	login := func(name string) (*liveHTTP, model.Principal) {
		jar, err := cookiejar.New(nil)
		require(t, err)
		client := &liveHTTP{t: t, ctx: ctx, client: &http.Client{Jar: jar, Timeout: 15 * time.Second}, origin: server.URL, prefix: "/api/v1"}
		client.login(name, password)
		var user model.Principal
		client.request("GET", "/auth/me", "", nil, &user, 200)
		return client, user
	}
	a, user := login(tenant)
	b, _ := login(foreign)
	other, _ := login(tenant + "_other")
	viewer, _ := login(tenant + "_viewer")
	blank := assistant.PlanSpec{Name: "日度统计计划", Kind: "daily", Timezone: "Asia/Shanghai", At: "00:00", Enabled: true}
	latest, err := blank.Latest(time.Now())
	require(t, err)
	request, err := blank.RequestAt(latest)
	require(t, err)
	index := "sb-alerts-" + tenant + "-" + request.Window.Start.Format("2006.01.02")
	require(t, es.EnsurePolicy(ctx))
	require(t, es.EnsureIndex(ctx, index, request.Window.Start.Format("2006-01-02")))
	t.Cleanup(func() {
		clean, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		response, err := es.API.Indices.Delete([]string{index}, es.API.Indices.Delete.WithContext(clean))
		require(t, err)
		defer response.Body.Close()
		if response.IsError() {
			t.Errorf("自身统计索引清理失败：%d", response.StatusCode)
		}
	})
	alert := model.Alert{SchemaVersion: "alert.v1", EventID: "owned_plan_event", TenantID: tenant, SensorID: "probe_owned", Timestamp: request.Window.Start.Add(time.Hour), ObservedAt: request.Window.Start.Add(time.Hour), ReceivedAt: request.Window.Start.Add(time.Hour), RawSHA256: control.Digest([]byte("report-plan")), Severity: "high"}
	alert.Event.Kind, alert.Event.Dataset, alert.Network.Protocol, alert.Rule.ID = "alert", "suricata.alert", "http", "1000001"
	for _, err := range es.Bulk(ctx, index, []model.Alert{alert}) {
		require(t, err)
	}
	response, err := es.API.Indices.Refresh(es.API.Indices.Refresh.WithIndex(index), es.API.Indices.Refresh.WithContext(ctx))
	require(t, err)
	require(t, response.Body.Close())
	change := assistant.PlanChange{ID: "plan_daily", Spec: blank}
	var plan assistant.Plan
	a.request("POST", "/analysis/plans", "", change, &plan, 200)
	if plan.Revision != 1 || plan.NextAt == nil || !plan.NextAt.After(time.Now()) {
		t.Fatal("计划没有持久化将来槽位", plan)
	}
	a.request("POST", "/analysis/plans", "", change, &plan, 200)
	var scheduled, audits int
	require(t, owner.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM starbeacon_jobs.river_job WHERE args->>'tenant_id'=$1 AND args->>'plan_id'=$2`, tenant, plan.ID).Scan(&scheduled); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT count(*) FROM operation_audits WHERE tenant_id=$1 AND action='reports.plan.save' AND object_id=$2`, tenant, plan.ID).Scan(&audits)
	}))
	if scheduled != 1 || audits != 1 {
		t.Fatal("同一 CAS 重试重复创建计划作业或审计", scheduled, audits)
	}
	changed := change
	changed.Spec.At = "01:00"
	a.request("POST", "/analysis/plans", "", changed, nil, 409)
	for _, client := range []*liveHTTP{b, other} {
		client.request("GET", "/analysis/plans/"+plan.ID+"/runs", "", nil, nil, 404)
		if client == other {
			client.request("POST", "/analysis/plans", "", change, nil, 404)
		}
	}
	viewer.request("GET", "/analysis/plans", "", nil, nil, 403)
	viewer.request("POST", "/analysis/plans", "", change, nil, 403)
	var foreignPlans struct {
		Items []assistant.Plan `json:"items"`
	}
	b.request("GET", "/analysis/plans", "", nil, &foreignPlans, 200)
	if len(foreignPlans.Items) != 0 {
		t.Fatal("报告计划跨租户可见")
	}
	ownPlans, err := db.ReportPlans(ctx, user)
	require(t, err)
	if len(ownPlans) != 1 || ownPlans[0].ID != plan.ID {
		t.Fatal("报告计划所有者查询不一致", ownPlans)
	}
	// 只改动当前测试计划和对应的 River 行，让真实执行器处理已持久化的到期作业。
	advance := func(item assistant.Plan, due time.Time) (assistant.PlanArgs, int64) {
		t.Helper()
		args := assistant.PlanArgs{TenantID: tenant, PlanID: item.ID, Revision: item.Revision, DueAt: due}
		raw, err := json.Marshal(args)
		require(t, err)
		var jobID int64
		require(t, owner.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
			if err := tx.QueryRow(ctx, `UPDATE report_plans SET next_at=$3 WHERE tenant_id=$1 AND id=$2 RETURNING river_job_id`, tenant, item.ID, due).Scan(&jobID); err != nil {
				return err
			}
			tag, err := tx.Exec(ctx, `UPDATE starbeacon_jobs.river_job SET args=$2,scheduled_at=now()-interval '1 second' WHERE id=$1 AND kind='starbeacon.report_plan' AND state='scheduled'`, jobID, raw)
			if err == nil && tag.RowsAffected() != 1 {
				return errors.New("测试计划作业身份不匹配")
			}
			return err
		}))
		return args, jobID
	}
	args, riverID := advance(plan, latest.AddDate(0, 0, -3))
	var runs store.PlanRunPage
	a.request("GET", "/analysis/plans/"+plan.ID+"/runs", "", nil, &runs, 200)
	if len(runs.Items) != 0 {
		t.Fatal("尚未运行却出现虚构报告")
	}
	// 丢弃仅负责入队的客户端，用新执行器恢复同一数据库中的计划。
	restarted, err := jobs.NewAnalysis(db, vault, policy, snapshot)
	require(t, err)
	api.Jobs = restarted
	require(t, restarted.Start(ctx))
	t.Cleanup(func() {
		stopCtx, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		require(t, restarted.StopAndCancel(stopCtx))
	})
	waitRun := func(id, expected string) assistant.PlanRun {
		t.Helper()
		var found assistant.PlanRun
		eventually(t, ctx, "报告计划提交并得到处理结果", func() bool {
			a.request("GET", "/analysis/plans/"+id+"/runs", "", nil, &runs, 200)
			if len(runs.Items) == 1 {
				found = runs.Items[0]
				return found.AnalysisState == expected || found.State == expected
			}
			return false
		})
		return found
	}
	run := waitRun(plan.ID, "succeeded")
	if run.SkippedFrom == nil || run.SkippedUntil == nil || !run.SkippedFrom.Equal(args.DueAt) || !run.SkippedUntil.Equal(latest) || !run.EffectiveAt.Equal(latest) || run.Request.Period != request.Period || calls.Load() != 0 || preparations.Load() < 2 {
		t.Fatal("停机恢复没有保留错过范围或重复调用了模型", run, calls.Load(), preparations.Load())
	}
	var report assistant.Job
	a.request("GET", "/analysis/jobs/"+run.AnalysisID, "", nil, &report, 200)
	if report.Result.Code != "statistics_only" || report.Evidence.Facts()[len(report.Evidence.Facts())-1].ID != "observed_at" || report.ExpiresAt.Sub(report.CreatedAt) < 179*24*time.Hour {
		t.Fatal("统计来源或默认留存不一致", report.Result, report.ExpiresAt)
	}
	facts := report.Evidence.Facts()
	foundCount := false
	for _, fact := range facts {
		foundCount = foundCount || (fact.ID == "alerts.total" && fact.Value == "1")
	}
	if !foundCount {
		t.Fatal("定时报告不是当前租户真实 ES 统计", facts)
	}
	lease, err := db.StartReportPlan(ctx, args, riverID, restarted)
	require(t, err)
	if lease.Execute {
		t.Fatal("已提交的计划周期重复取得执行资格")
	}
	for _, kind := range []string{"weekly", "monthly"} {
		spec := blank
		spec.Kind, spec.Name = kind, "自然周期统计"
		var periodPlan assistant.Plan
		a.request("POST", "/analysis/plans", "", assistant.PlanChange{ID: "plan_" + kind, Spec: spec}, &periodPlan, 200)
		due, err := spec.Latest(time.Now())
		require(t, err)
		advance(periodPlan, due)
		periodRun := waitRun(periodPlan.ID, "succeeded")
		expected, err := spec.RequestAt(due)
		require(t, err)
		if periodRun.Request != expected || periodRun.SkippedFrom != nil {
			t.Fatal("计划周期范围不一致", periodRun.Request, expected)
		}
	}
	config := llm.Config{Name: "计划协议提供方", Kind: "openai_responses", BaseURL: provider.URL + "/v1", Model: "owned-plan-model", APIKey: "owned-plan-key", Enabled: true, MaxOutputTokens: 512, TimeoutSeconds: 5, DailyRequests: 1}
	var saved llm.Provider
	a.request("POST", "/models/providers", "", store.ModelChange{ID: "provider_plan", Config: config, ReplaceKey: true}, &saved, 200)
	modelSpec := blank
	modelSpec.Name, modelSpec.ProviderID, modelSpec.ProviderRevision, modelSpec.AllowContext = "模型周期报告", saved.ID, saved.Revision, true
	noConsent := modelSpec
	noConsent.AllowContext = false
	a.request("POST", "/analysis/plans", "", assistant.PlanChange{ID: "plan_no_consent", Spec: noConsent}, nil, 400)
	var modelPlan assistant.Plan
	a.request("POST", "/analysis/plans", "", assistant.PlanChange{ID: "plan_model", Spec: modelSpec}, &modelPlan, 200)
	modelArgs, modelRiverID := advance(modelPlan, latest)
	modelRun := waitRun(modelPlan.ID, "succeeded")
	if calls.Load() != 1 || modelRun.AnalysisID == "" {
		t.Fatal("定时模型报告没有实际执行一次", calls.Load(), modelRun)
	}
	lease, err = db.StartReportPlan(ctx, modelArgs, modelRiverID, restarted)
	require(t, err)
	if lease.Execute || calls.Load() != 1 {
		t.Fatal("模型计划重复取得执行资格")
	}
	var quotaPlan assistant.Plan
	a.request("POST", "/analysis/plans", "", assistant.PlanChange{ID: "plan_model_quota", Spec: modelSpec}, &quotaPlan, 200)
	advance(quotaPlan, latest)
	quotaRun := waitRun(quotaPlan.ID, "failed")
	if quotaRun.Code != "model_quota_exceeded" || quotaRun.AnalysisID != "" || calls.Load() != 1 {
		t.Fatal("计划绕过共享模型预算", quotaRun, calls.Load())
	}
	disable := assistant.PlanChange{ID: modelPlan.ID, ExpectedRevision: modelPlan.Revision, Spec: modelSpec}
	disable.Spec.Enabled = false
	a.request("POST", "/analysis/plans", "", disable, &modelPlan, 200)
	if modelPlan.NextAt != nil || modelPlan.Spec.Enabled {
		t.Fatal("停用后仍安排未来槽位", modelPlan)
	}
	if _, err := db.StartReportPlan(ctx, modelArgs, modelRiverID, restarted); !errors.Is(err, store.ErrConflict) {
		t.Fatal("停用修订仍取得执行资格", err)
	}
	a.request("GET", "/analysis/jobs/"+modelRun.AnalysisID, "", nil, &report, 200)
	if report.State != "succeeded" || calls.Load() != 1 {
		t.Fatal("停用计划破坏已完成报告")
	}
	var before store.PlanRunPage
	a.request("GET", "/analysis/plans/plan_daily/runs?before="+run.ID, "", nil, &before, 200)
	if len(before.Items) != 0 {
		t.Fatal("游标重复当前运行")
	}
	a.request("GET", "/analysis/plans/plan_daily/runs?before="+modelRun.ID, "", nil, nil, 404)
	a.request("GET", "/analysis/plans/invalid%2Fplan/runs", "", nil, nil, 400)
	t.Log("真实持久计划跨执行器恢复，日/周/月报告经 PG/Redis/ES 与受控 TLS 模型协议生成；重复周期、租户/所有者、错过范围、预算与停用边界通过")
}
