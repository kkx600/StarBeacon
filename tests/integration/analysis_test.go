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

// 本测试验证持久队列、真实依赖与受控生成协议；不冒充外部模型的领域效果验收。
func TestAnalysisPersistentJobsReportsOwnershipBudgetsAndCancellation(t *testing.T) {
	if os.Getenv("SB_MODE") != "development" || os.Getenv("SB_MIGRATION_DATABASE_URL") == "" {
		t.Skip("需要独立开发依赖")
	}
	ctx, stop := context.WithTimeout(context.Background(), 120*time.Second)
	defer stop()
	owner, err := store.Open(ctx, os.Getenv("SB_MIGRATION_DATABASE_URL"))
	require(t, err)
	defer owner.Close()
	db, err := store.Open(ctx, os.Getenv("SB_DATABASE_URL"))
	require(t, err)
	defer db.Close()
	require(t, db.VerifyRuntimeRole(ctx))
	es, err := store.OpenES(os.Getenv("SB_ES_URL"), os.Getenv("SB_ES_API_KEY"))
	require(t, err)
	options, err := redis.ParseURL(os.Getenv("SB_REDIS_URL"))
	require(t, err)
	options.DB = 13
	cache := redis.NewClient(options)
	defer cache.Close()
	password := store.Token()
	tenant := store.RandomID("it_analysis_")
	foreign := store.RandomID("it_analysis_b_")
	for _, id := range []string{tenant, foreign} {
		require(t, admin.Bootstrap(ctx, owner, id, "智能分析验收", id, password, "admin"))
		defer func() {
			clean, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			require(t, owner.TenantTx(clean, id, func(tx pgx.Tx) error {
				if _, err := tx.Exec(clean, `DELETE FROM starbeacon_jobs.river_job WHERE args->>'tenant_id'=$1`, id); err != nil {
					return err
				}
				for _, table := range []string{"analysis_jobs", "analysis_threads", "model_capability_checks", "model_provider_versions", "model_providers", "operation_audits", "login_audits", "retention_policies"} {
					if _, err := tx.Exec(clean, "DELETE FROM "+table+" WHERE tenant_id=$1", id); err != nil {
						return err
					}
				}
				for _, query := range []string{"DELETE FROM sessions WHERE user_id IN(SELECT id FROM users WHERE tenant_id=$1)", "DELETE FROM users WHERE tenant_id=$1", "DELETE FROM tenants WHERE id=$1"} {
					if _, err := tx.Exec(clean, query, id); err != nil {
						return err
					}
				}
				return nil
			}))
		}()
	}
	require(t, admin.Bootstrap(ctx, owner, tenant, "智能分析验收", tenant+"_other", password, "admin"))
	require(t, admin.Bootstrap(ctx, owner, tenant, "智能分析验收", tenant+"_viewer", password, "viewer"))
	window := analytics.Window{Start: time.Now().UTC().Add(-time.Hour), End: time.Now().UTC().Truncate(time.Minute)}
	index := "sb-alerts-" + tenant + "-" + window.Start.Format("2006.01.02")
	require(t, es.EnsurePolicy(ctx))
	require(t, es.EnsureIndex(ctx, index, window.Start.Format("2006-01-02")))
	defer func() {
		clean, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		response, err := es.API.Indices.Delete([]string{index}, es.API.Indices.Delete.WithContext(clean))
		require(t, err)
		defer response.Body.Close()
		if response.IsError() {
			t.Errorf("自身索引清理失败：%d", response.StatusCode)
		}
	}()
	item := model.Alert{SchemaVersion: "alert.v1", EventID: "owned_event", TenantID: tenant, SensorID: "probe_owned", Timestamp: window.Start.Add(time.Minute), ObservedAt: window.Start.Add(time.Minute), ReceivedAt: window.Start.Add(time.Minute), RawSHA256: control.Digest([]byte("owned")), Severity: "high"}
	item.Event.Kind = "alert"
	item.Event.Dataset = "suricata.alert"
	item.Rule.ID = "1000001"
	item.Network.Protocol = "http"
	for _, err := range es.Bulk(ctx, index, []model.Alert{item}) {
		require(t, err)
	}
	response, err := es.API.Indices.Refresh(es.API.Indices.Refresh.WithIndex(index), es.API.Indices.Refresh.WithContext(ctx))
	require(t, err)
	require(t, response.Body.Close())
	vault, err := secrets.New(store.Token())
	require(t, err)
	var calls atomic.Int32
	started := make(chan struct{}, 1)
	provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var payload struct {
			Input string `json:"input"`
			Model string `json:"model"`
			Store bool   `json:"store"`
			Max   int64  `json:"max_output_tokens"`
		}
		if r.URL.Path != "/v1/responses" || r.Header.Get("Authorization") != "Bearer owned-analysis-key" || json.NewDecoder(io.LimitReader(r.Body, 32769)).Decode(&payload) != nil || payload.Store || payload.Model != "owned-model" {
			w.WriteHeader(400)
			return
		}
		if strings.Contains(payload.Input, "接口结果未知") {
			w.WriteHeader(503)
			return
		}
		if strings.Contains(payload.Input, "请求取消") {
			select {
			case started <- struct{}{}:
			default:
			}
			<-r.Context().Done()
			return
		}
		text := `{"summary":"检测事件需要人工核实。","observations":[{"text":"规则命中不证明攻击成功。","sources":["alerts.total"]}],"recommendations":[{"text":"核对监测范围与原始证据。","sources":["window"]}]}`
		if payload.Max == 64 {
			text = "连接成功。"
		} else if strings.Contains(payload.Input, "无效引用") {
			text = `{"summary":"需要核对","observations":[{"text":"调查","sources":["foreign.source"]}],"recommendations":[]}`
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "response_owned", "object": "response", "status": "completed", "model": "owned-model", "output": []any{map[string]any{"type": "message", "role": "assistant", "id": "message_owned", "status": "completed", "content": []any{map[string]any{"type": "output_text", "text": text, "annotations": []any{}}}}}, "usage": map[string]int{"input_tokens": 30, "output_tokens": 40, "total_tokens": 70}})
	}))
	defer provider.Close()
	networks, err := outbound.ParseNetworks("127.0.0.0/8")
	require(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(provider.Certificate())
	policy := outbound.Policy{PrivateNetworks: networks, Roots: roots}
	queue, err := jobs.NewAnalysis(db, vault, policy)
	require(t, err)
	auth := httpapi.NewAuth(db, cache, "", "it_analysis", false)
	api := &platform.API{DB: db, ES: es, Redis: cache, Auth: auth, Vault: vault, Outbound: policy, Jobs: queue}
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
	config := llm.Config{Name: "协议验收提供方", Kind: "openai_responses", BaseURL: provider.URL + "/v1", Model: "owned-model", APIKey: "owned-analysis-key", Enabled: true, MaxOutputTokens: 512, TimeoutSeconds: 5, DailyRequests: 5}
	var saved llm.Provider
	a.request("POST", "/models/providers", "", store.ModelChange{ID: "provider_owned", Config: config, ReplaceKey: true}, &saved, 200)
	input := assistant.Request{Kind: "chat", ProviderID: saved.ID, ProviderRevision: 1, Window: window, Question: "有哪些统计需要调查？", AllowContext: true}
	var cancelled assistant.Job
	a.request("POST", "/analysis/jobs", "cancel_before_run", input, &cancelled, 202)
	a.request("POST", "/analysis/jobs/"+cancelled.ID+"/cancel", "", struct{}{}, &cancelled, 200)
	if cancelled.State != "cancelled" || calls.Load() != 0 {
		t.Fatal("未执行取消发生了模型调用", cancelled, calls.Load())
	}
	var preleased assistant.Job
	a.request("POST", "/analysis/jobs", "lease_lost_owned", input, &preleased, 202)
	var riverID int64
	require(t, owner.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT river_job_id FROM analysis_jobs WHERE tenant_id=$1 AND id=$2`, tenant, preleased.ID).Scan(&riverID)
	}))
	lease, err := db.StartAnalysis(ctx, assistant.Args{TenantID: tenant, JobID: preleased.ID}, riverID, vault)
	require(t, err)
	if !lease.Execute {
		t.Fatal("未取得执行资格")
	}
	require(t, owner.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE analysis_jobs SET deadline=now()-interval '1 second' WHERE tenant_id=$1 AND id=$2`, tenant, preleased.ID)
		return err
	}))
	a.request("GET", "/analysis/jobs/"+preleased.ID, "", nil, &preleased, 200)
	if preleased.State != "uncertain" || preleased.Result.DurationMS != nil || preleased.Result.Usage != nil {
		t.Fatal("失联请求被伪造为明确结果", preleased)
	}
	if err := db.FinishAnalysis(ctx, tenant, lease, llm.Result{State: "succeeded", Code: "completed"}, nil); !errors.Is(err, store.ErrConflict) {
		t.Fatal("迟到结果覆盖未知状态", err)
	}
	var unavailable assistant.Job
	a.request("POST", "/analysis/jobs", "credentials_unavailable_owned", input, &unavailable, 202)
	require(t, owner.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT river_job_id FROM analysis_jobs WHERE tenant_id=$1 AND id=$2`, tenant, unavailable.ID).Scan(&riverID)
	}))
	wrongVault, err := secrets.New(strings.Repeat("9", 64))
	require(t, err)
	lease, err = db.StartAnalysis(ctx, assistant.Args{TenantID: tenant, JobID: unavailable.ID}, riverID, wrongVault)
	require(t, err)
	a.request("GET", "/analysis/jobs/"+unavailable.ID, "", nil, &unavailable, 200)
	if lease.Execute || unavailable.State != "failed" || unavailable.Result.Code != "provider_config_unavailable" || calls.Load() != 0 {
		t.Fatal("凭据不可用时未保存未调用模型的明确失败状态", unavailable)
	}
	// 换修订后再运行队列，旧配置作业必须在出站调用前终止。
	var stale assistant.Job
	a.request("POST", "/analysis/jobs", "revision_stale_owned", input, &stale, 202)
	config.DailyRequests = 12
	config.APIKey = ""
	a.request("POST", "/models/providers", "", store.ModelChange{ID: saved.ID, ExpectedRevision: 1, Config: config}, &saved, 200)
	input.ProviderRevision = 2
	work, workStop := context.WithCancel(context.WithoutCancel(ctx))
	defer workStop()
	require(t, queue.Start(work))
	defer func() {
		clean, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		require(t, queue.StopAndCancel(clean))
	}()
	wait := func(id string) assistant.Job {
		for {
			var job assistant.Job
			a.request("GET", "/analysis/jobs/"+id, "", nil, &job, 200)
			if job.State != "queued" && job.State != "running" {
				return job
			}
			select {
			case <-ctx.Done():
				t.Fatal("作业未进入终态")
			case <-time.After(40 * time.Millisecond):
			}
		}
	}
	stale = wait(stale.ID)
	if stale.Result.Code != "provider_revision_changed" || calls.Load() != 0 {
		t.Fatal("旧配置作业调用了提供方", stale, calls.Load())
	}
	var job assistant.Job
	a.request("POST", "/analysis/jobs", "first_chat_owned", input, &job, 202)
	job = wait(job.ID)
	if job.State != "succeeded" || job.Answer == nil || job.Evidence.Segments[0].Events.Total != "1" || job.Request.ThreadID == "" || job.Result.Usage.TotalTokens != 70 || job.ExpiresAt.Sub(job.CreatedAt) < 179*24*time.Hour {
		t.Fatal("对话生成或统计、留存错误", job)
	}
	var duplicate assistant.Job
	a.request("POST", "/analysis/jobs", "first_chat_owned", input, &duplicate, 200)
	if duplicate.ID != job.ID || duplicate.Evidence.SHA256 != job.Evidence.SHA256 || calls.Load() != 1 {
		t.Fatal("幂等重试重复生成", duplicate, calls.Load())
	}
	changed := input
	changed.Question = "改变问题"
	a.request("POST", "/analysis/jobs", "first_chat_owned", changed, nil, 409)
	for _, client := range []*liveHTTP{b, other} {
		client.request("GET", "/analysis/jobs/"+job.ID, "", nil, nil, 404)
		client.request("GET", "/analysis/threads/"+job.Request.ThreadID, "", nil, nil, 404)
		client.request("POST", "/analysis/jobs/"+job.ID+"/cancel", "", struct{}{}, nil, 404)
	}
	viewer.request("GET", "/analysis/jobs/"+job.ID, "", nil, nil, 403)
	var conversation store.AnalysisConversation
	a.request("GET", "/analysis/threads/"+job.Request.ThreadID, "", nil, &conversation, 200)
	if len(conversation.Jobs) != 1 || conversation.Jobs[0].ID != job.ID {
		t.Fatal("对话记录未保存", conversation)
	}
	var threads store.AnalysisThreadsPage
	a.request("GET", "/analysis/threads", "", nil, &threads, 200)
	if len(threads.Items) == 0 {
		t.Fatal("对话目录为空")
	}
	history, err := db.AnalysisHistory(ctx, user, job.Request.ThreadID)
	require(t, err)
	if len(history) != 1 || history[0].Summary != job.Answer.Summary {
		t.Fatal("历史上下文不一致", history)
	}
	input.ThreadID, input.ParentID, input.Question = job.Request.ThreadID, job.ID, "请继续给出调查建议。"
	var second assistant.Job
	a.request("POST", "/analysis/jobs", "second_chat_owned", input, &second, 202)
	second = wait(second.ID)
	if second.State != "succeeded" {
		t.Fatal(second)
	}
	a.request("POST", "/analysis/jobs", "stale_parent_owned", input, nil, 409)
	input.ThreadID, input.ParentID, input.Question = "", "", "无效引用"
	a.request("POST", "/analysis/jobs", "bad_citation_owned", input, &job, 202)
	job = wait(job.ID)
	if job.Result.Code != "invalid_analysis_output" || job.Answer != nil {
		t.Fatal("伪造引用被接受", job)
	}
	input.Question = "接口结果未知"
	a.request("POST", "/analysis/jobs", "uncertain_owned", input, &job, 202)
	job = wait(job.ID)
	if job.State != "uncertain" || job.Answer != nil || job.Result.Usage != nil {
		t.Fatal("接口故障被伪造为成功", job)
	}
	input.Question = "请求取消"
	a.request("POST", "/analysis/jobs", "running_cancel_owned", input, &job, 202)
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("提供方未收到调用")
	}
	a.request("POST", "/analysis/jobs/"+job.ID+"/cancel", "", struct{}{}, nil, 200)
	job = wait(job.ID)
	if !job.CancelRequested || job.State != "uncertain" {
		t.Fatal("已发请求取消被误报为未执行", job)
	}
	reportInput := assistant.Request{Kind: "daily", Period: time.Now().In(time.FixedZone("CST", 8*3600)).AddDate(0, 0, -1).Format("2006-01-02"), Timezone: "Asia/Shanghai"}
	var report assistant.Job
	a.request("POST", "/analysis/jobs", "stats_report_owned", reportInput, &report, 202)
	if report.Answer != nil || report.State != "succeeded" || report.Result.Code != "statistics_only" {
		t.Fatal("统计报告行为错误", report)
	}
	request, err := http.NewRequestWithContext(ctx, "GET", server.URL+"/api/v1/analysis/jobs/"+report.ID+"/report", nil)
	require(t, err)
	exported, err := a.client.Do(request)
	require(t, err)
	raw, err := io.ReadAll(exported.Body)
	require(t, err)
	require(t, exported.Body.Close())
	if exported.StatusCode != 200 || !strings.Contains(string(raw), "统计来源") || !strings.Contains(exported.Header.Get("Content-Disposition"), "attachment") {
		t.Fatal("统计报告未导出", exported.StatusCode)
	}
	a.request("POST", "/analysis/jobs", "stats_report_revision_owned", reportInput, &duplicate, 202)
	if duplicate.Revision != report.Revision+1 || duplicate.ID == report.ID {
		t.Fatal("报告修订覆盖旧记录", duplicate)
	}
	var page store.AnalysisPage
	a.request("GET", "/analysis/jobs?group=reports&limit=1", "", nil, &page, 200)
	if len(page.Items) != 1 || page.Next == "" {
		t.Fatal("报告分页错误", page)
	}
	a.request("GET", "/analysis/jobs?group=reports&limit=1&before="+page.Next, "", nil, &page, 200)
	if len(page.Items) != 1 || page.Next != "" {
		t.Fatal("报告分页重复或遗漏", page)
	}
	b.request("GET", "/analysis/jobs?group=reports", "", nil, &page, 200)
	if len(page.Items) != 0 {
		t.Fatal("跨租户读取报告", page)
	}
	for _, query := range []string{"?limit=invalid", "?limit=0", "?limit=51", "?group=invalid", "?before=bad/id"} {
		a.request("GET", "/analysis/jobs"+query, "", nil, nil, 400)
	}
	bad := input
	bad.AllowContext = false
	a.request("POST", "/analysis/jobs", "no_context_owned", bad, nil, 400)
	// 最后降低额度，业务调用和连接验证必须同时受已有提交量约束。
	config.DailyRequests = 1
	a.request("POST", "/models/providers", "", store.ModelChange{ID: saved.ID, ExpectedRevision: 2, Config: config}, &saved, 200)
	input.ProviderRevision = 3
	input.Question = "额度检查"
	a.request("POST", "/analysis/jobs", "budget_owned", input, nil, 429)
	a.request("POST", "/models/providers/"+saved.ID+"/test", "budget_test_owned", map[string]int{"expected_revision": 3}, nil, 429)
	var denied bool
	require(t, db.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT has_table_privilege(current_user,'starbeacon_jobs.river_migration','INSERT') OR has_schema_privilege(current_user,'starbeacon_jobs','CREATE')`).Scan(&denied)
	}))
	if denied {
		t.Fatal("运行角色持有队列迁移权限")
	}
}
