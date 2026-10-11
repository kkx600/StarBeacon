//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/admin"
	"github.com/kkx600/StarBeacon/internal/analytics"
	"github.com/kkx600/StarBeacon/internal/assistant"
	"github.com/kkx600/StarBeacon/internal/jobs"
	"github.com/kkx600/StarBeacon/internal/llm"
	"github.com/kkx600/StarBeacon/internal/outbound"
	"github.com/kkx600/StarBeacon/internal/secrets"
	"github.com/kkx600/StarBeacon/internal/store"
)

func TestAnalysisTransactionsPaginationAndExecutionGuards(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	f := newIsolatedDatabase(t, ctx)
	tenant := store.RandomID("it_analysis_bounds_")
	require(t, admin.Bootstrap(ctx, f.Owner, tenant, "智能分析边界验收", tenant, store.Token(), "admin"))
	u, _, err := f.Runtime.Password(ctx, tenant)
	require(t, err)
	vault, err := secrets.New(store.Token())
	require(t, err)
	config := llm.Config{Name: "分析协议配置", Kind: "openai_responses", BaseURL: "https://models.example.com/v1", Model: "owned", APIKey: "owned-analysis-key", Enabled: true, MaxOutputTokens: 256, TimeoutSeconds: 5, DailyRequests: 1000}
	_, err = f.Runtime.SaveModelProvider(ctx, u, store.ModelChange{ID: "provider_owned", Config: config, ReplaceKey: true}, vault, outbound.Policy{}, "seed_provider")
	require(t, err)
	queue, err := jobs.NewAnalysis(f.Runtime, vault, outbound.Policy{})
	require(t, err)
	input := assistant.Request{Kind: "chat", ProviderID: "provider_owned", ProviderRevision: 1, Question: strings.Repeat("核对捕获质量", 16), AllowContext: true, Window: analytics.Window{Start: time.Now().UTC().Add(-time.Hour), End: time.Now().UTC().Truncate(time.Minute)}}
	seed, err := f.Runtime.CreateAnalysis(ctx, u, input, "seed_analysis", assistant.Evidence{}, "限定证据范围", queue, vault, "seed_analysis")
	require(t, err)
	// 已完成对话仅用于列表与数据库故障测试，不代表外部模型生成效果。
	require(t, f.Owner.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE analysis_jobs SET state='succeeded',answer='{"summary":"需要核实"}' WHERE tenant_id=$1 AND id=$2`, tenant, seed.ID)
		return e
	}))
	confirmed, err := f.Runtime.CreateAnalysis(ctx, u, input, "seed_analysis", assistant.Evidence{}, "限定证据范围", queue, vault, "seed_analysis")
	require(t, err)
	if confirmed.ID != seed.ID || confirmed.Request.ThreadID != seed.Request.ThreadID {
		t.Fatal("重复提交分析创建了其他计费作业或对话")
	}
	changedInput := input
	changedInput.Question += "不同请求"
	if _, err := f.Runtime.CreateAnalysis(ctx, u, changedInput, "seed_analysis", assistant.Evidence{}, "限定证据范围", queue, vault, "seed_analysis"); !errors.Is(err, store.ErrConflict) {
		t.Fatal("分析幂等请求改变了原问题", err)
	}
	var title string
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT title FROM analysis_threads WHERE tenant_id=$1 AND id=$2`, tenant, seed.Request.ThreadID).Scan(&title))
	if len([]rune(title)) != 80 || title != string([]rune(input.Question)[:80]) {
		t.Fatal("长问题的对话标题未按字符截断")
	}
	follow := input
	follow.ThreadID, follow.ParentID = seed.Request.ThreadID, seed.ID
	type operation struct {
		name     string
		prefixes []string
		run      func(*store.Postgres) error
	}
	ops := []operation{
		{"existing", []string{"UPDATE analysis_jobs SET state='uncertain'", "SELECT request_hash", "SELECT jsonb_build_object"}, func(db *store.Postgres) error {
			_, e := db.ExistingAnalysis(ctx, u, "seed_analysis", store.AnalysisInputHash(input))
			return e
		}},
		{"history", []string{"SELECT id FROM analysis_threads", "SELECT request->>'question'"}, func(db *store.Postgres) error { _, e := db.AnalysisHistory(ctx, u, seed.Request.ThreadID); return e }},
		{"report_cursor", []string{"UPDATE analysis_jobs SET state='uncertain'", "SELECT created_at FROM analysis_jobs", "SELECT id,kind,COALESCE"}, func(db *store.Postgres) error { _, e := db.AnalysisJobs(ctx, u, "chat", seed.ID, 2); return e }},
		{"thread_cursor", []string{"UPDATE analysis_jobs SET state='uncertain'", "SELECT updated_at FROM analysis_threads", "SELECT t.id,t.title"}, func(db *store.Postgres) error { _, e := db.AnalysisThreads(ctx, u, seed.Request.ThreadID); return e }},
		{"conversation_cursor", []string{"UPDATE analysis_jobs SET state='uncertain'", "SELECT title FROM analysis_threads", "SELECT created_at FROM analysis_jobs", "SELECT jsonb_build_object"}, func(db *store.Postgres) error {
			_, e := db.AnalysisConversation(ctx, u, seed.Request.ThreadID, seed.ID)
			return e
		}},
		{"followup", []string{"SELECT revision FROM model_providers", "SELECT ciphertext", "UPDATE rule_generation_jobs SET state='uncertain'", "UPDATE alert_triage_jobs SET state='uncertain'", "SELECT count(*) FILTER", "SELECT count(*) FROM analysis_jobs", "SELECT id FROM analysis_threads", "SELECT id,state FROM analysis_jobs", "UPDATE analysis_threads", "INSERT INTO analysis_jobs", "UPDATE analysis_jobs SET river_job_id", "INSERT INTO operation_audits"}, func(db *store.Postgres) error {
			_, e := db.CreateAnalysis(ctx, u, follow, "followup_fault", assistant.Evidence{}, "限定证据范围", queue, vault, "followup_fault")
			return e
		}},
	}
	for _, op := range ops {
		for i, prefix := range op.prefixes {
			t.Run(fmt.Sprintf("%s/%02d", op.name, i), func(t *testing.T) {
				before := ownedBusinessSnapshot(t, ctx, f.Owner, tenant)
				db, tracer := disconnectedStore(t, ctx, f.RuntimeDSN, prefix)
				if e := op.run(db); e == nil || !tracer.fired.Load() {
					t.Fatalf("目标数据库故障未执行或被当作成功：%v", e)
				}
				if ownedBusinessSnapshot(t, ctx, f.Owner, tenant) != before {
					t.Fatal("失败事务留下分析记录或审计变更")
				}
			})
		}
	}
	if _, err = f.Runtime.ExistingAnalysis(ctx, u, "seed_analysis", strings.Repeat("0", 64)); !errors.Is(err, store.ErrConflict) {
		t.Fatal("同幂等键不同内容未拒绝", err)
	}
	if _, err = f.Runtime.ExistingAnalysis(ctx, u, "id.invalid", "short"); !errors.Is(err, assistant.ErrInput) {
		t.Fatal("无效幂等请求未拒绝", err)
	}
	if history, e := f.Runtime.AnalysisHistory(ctx, u, ""); e != nil || len(history) != 0 {
		t.Fatal("无历史输入无效", e)
	}
	if _, e := f.Runtime.AnalysisHistory(ctx, u, "id.invalid"); !errors.Is(e, assistant.ErrInput) {
		t.Fatal("无效对话历史 ID 未拒绝", e)
	}
	for _, tc := range []struct {
		group, cursor string
		limit         int
	}{{"unknown", "", 20}, {"reports", "", 0}, {"reports", "", 51}, {"reports", "id.invalid", 20}} {
		if _, e := f.Runtime.AnalysisJobs(ctx, u, tc.group, tc.cursor, tc.limit); !errors.Is(e, assistant.ErrInput) {
			t.Fatal("无效列表参数未拒绝", e)
		}
	}
	if _, e := f.Runtime.AnalysisThreads(ctx, u, "id.invalid"); !errors.Is(e, assistant.ErrInput) {
		t.Fatal("无效对话游标未拒绝", e)
	}
	if _, e := f.Runtime.AnalysisConversation(ctx, u, seed.Request.ThreadID, "id.invalid"); !errors.Is(e, assistant.ErrInput) {
		t.Fatal("无效内容游标未拒绝", e)
	}
	if _, e := f.Runtime.AnalysisJob(ctx, u, "id.invalid"); !errors.Is(e, pgx.ErrNoRows) {
		t.Fatal("无效作业 ID 未拒绝", e)
	}
	if _, e := f.Runtime.CancelAnalysis(ctx, u, "id.invalid", queue, "invalid"); !errors.Is(e, pgx.ErrNoRows) {
		t.Fatal("无效取消 ID 未拒绝", e)
	}
	if _, e := f.Runtime.CreateAnalysis(ctx, u, input, "valid_key", assistant.Evidence{}, strings.Repeat("x", 24577), queue, vault, "invalid"); !errors.Is(e, assistant.ErrInput) {
		t.Fatal("超长提示未拒绝", e)
	}
	if _, e := f.Runtime.CreateAnalysis(ctx, u, input, "queue_missing", assistant.Evidence{}, "提示", nil, vault, "invalid"); !errors.Is(e, assistant.ErrInput) {
		t.Fatal("缺少持久队列仍允许模型作业", e)
	}

	queued, err := f.Runtime.CreateAnalysis(ctx, u, input, "execution_guard", assistant.Evidence{}, "限定证据范围", queue, vault, "execution_guard")
	require(t, err)
	var riverID int64
	require(t, f.Owner.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT river_job_id FROM analysis_jobs WHERE tenant_id=$1 AND id=$2`, tenant, queued.ID).Scan(&riverID)
	}))
	args := assistant.Args{TenantID: tenant, JobID: queued.ID}
	for _, prefix := range []string{"UPDATE analysis_jobs SET state='uncertain'", "SELECT jsonb_build_object", "SELECT EXISTS(SELECT 1 FROM users", "SELECT revision FROM model_providers", "SELECT ciphertext", "UPDATE analysis_jobs SET state='running'"} {
		t.Run("lease_fault/"+prefix, func(t *testing.T) {
			before := ownedBusinessSnapshot(t, ctx, f.Owner, tenant)
			db, tracer := disconnectedStore(t, ctx, f.RuntimeDSN, prefix)
			if lease, e := db.StartAnalysis(ctx, args, riverID, vault); e == nil || !tracer.fired.Load() {
				t.Fatalf("未阻止故障租约：%+v %v", lease, e)
			}
			if ownedBusinessSnapshot(t, ctx, f.Owner, tenant) != before {
				t.Fatal("失败租约改变作业状态")
			}
		})
	}
	if lease, e := f.Runtime.StartAnalysis(ctx, args, riverID+1, vault); !errors.Is(e, store.ErrConflict) || lease.Execute {
		t.Fatal("错误队列 ID 取得调用资格", e)
	}
	if _, e := f.Runtime.StartAnalysis(ctx, assistant.Args{TenantID: "id.invalid", JobID: queued.ID}, riverID, vault); !errors.Is(e, assistant.ErrInput) {
		t.Fatal("非法租户取得调用资格", e)
	}
	lease, err := f.Runtime.StartAnalysis(ctx, args, riverID, vault)
	require(t, err)
	if !lease.Execute || lease.Token == "" {
		t.Fatal("健康作业未取得执行租约")
	}
	for _, invalid := range []llm.Result{{State: "queued"}, {State: "unknown"}, {State: "running"}} {
		if e := f.Runtime.FinishAnalysis(ctx, tenant, lease, invalid, nil); !errors.Is(e, store.ErrConflict) {
			t.Fatal("非法终态被保存", e)
		}
	}
	fault, tracer := disconnectedStore(t, ctx, f.RuntimeDSN, "UPDATE analysis_jobs SET state=$4")
	before := ownedBusinessSnapshot(t, ctx, f.Owner, tenant)
	if e := fault.FinishAnalysis(ctx, tenant, lease, llm.Result{State: "failed", Code: "controlled_failure"}, nil); e == nil || !tracer.fired.Load() {
		t.Fatal("结束事务故障被隐藏", e)
	}
	if ownedBusinessSnapshot(t, ctx, f.Owner, tenant) != before {
		t.Fatal("失败结束事务改变状态")
	}
	require(t, f.Runtime.FinishAnalysis(ctx, tenant, lease, llm.Result{State: "failed", Code: "controlled_failure", Text: "不得保存的原始响应"}, &assistant.Answer{Summary: "失败时不得保存"}))
	finished, err := f.Runtime.AnalysisJob(ctx, u, queued.ID)
	require(t, err)
	if finished.State != "failed" || finished.Answer != nil || finished.Result.Text != "" {
		t.Fatal("失败作业留下未验证答案", finished)
	}

	// 用真实表中的独立分页夹具检查顺序与归属，不调用或冒充任何模型。
	require(t, f.Owner.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		for i := 1; i <= 22; i++ {
			thread := fmt.Sprintf("thread_page_%02d", i)
			if _, e := tx.Exec(ctx, `INSERT INTO analysis_threads(tenant_id,id,created_by,title,updated_at) VALUES($1,$2,$3,$2,now()-make_interval(secs=>$4))`, tenant, thread, u.ID, i); e != nil {
				return e
			}
			if _, e := tx.Exec(ctx, `INSERT INTO analysis_jobs(tenant_id,id,created_by,kind,thread_id,revision,period_start,period_end,request,request_hash,idempotency_key_hash,template,evidence,prompt_hash,state,answer,created_at) SELECT tenant_id,$3,created_by,kind,$4,revision,period_start,period_end,request||jsonb_build_object('thread_id',$4::text,'question',$3::text),request_hash,$3,template,evidence,prompt_hash,'succeeded','{"summary":"分页夹具"}',now()-make_interval(secs=>$5) FROM analysis_jobs WHERE tenant_id=$1 AND id=$2`, tenant, seed.ID, fmt.Sprintf("page_job_%02d", i), thread, i); e != nil {
				return e
			}
		}
		for i := 1; i <= 12; i++ {
			if _, e := tx.Exec(ctx, `INSERT INTO analysis_jobs(tenant_id,id,created_by,kind,thread_id,revision,period_start,period_end,request,request_hash,idempotency_key_hash,template,evidence,prompt_hash,state,answer,created_at) SELECT tenant_id,$3,created_by,kind,thread_id,revision,period_start,period_end,request||jsonb_build_object('question',$3::text),request_hash,$3,template,evidence,prompt_hash,'succeeded','{"summary":"历史夹具"}',now()-make_interval(secs=>$4) FROM analysis_jobs WHERE tenant_id=$1 AND id=$2`, tenant, seed.ID, fmt.Sprintf("turn_job_%02d", i), i+30); e != nil {
				return e
			}
		}
		return nil
	}))
	threads, err := f.Runtime.AnalysisThreads(ctx, u, "")
	require(t, err)
	if len(threads.Items) != 20 || threads.Next == "" {
		t.Fatal("对话分页边界缺失", threads)
	}
	older, err := f.Runtime.AnalysisThreads(ctx, u, threads.Next)
	require(t, err)
	if len(older.Items) != 4 || older.Next != "" {
		t.Fatal("对话分页出现重复或遗漏", older)
	}
	seen := map[string]bool{}
	for _, item := range append(threads.Items, older.Items...) {
		if seen[item.ID] {
			t.Fatal("对话跨页重复", item.ID)
		}
		seen[item.ID] = true
	}
	conversation, err := f.Runtime.AnalysisConversation(ctx, u, seed.Request.ThreadID, "")
	require(t, err)
	if len(conversation.Jobs) != 10 || conversation.Next == "" {
		t.Fatal("内容分页边界缺失", conversation)
	}
	previous, err := f.Runtime.AnalysisConversation(ctx, u, seed.Request.ThreadID, conversation.Next)
	require(t, err)
	if len(previous.Jobs) != 3 || previous.Next != "" {
		t.Fatal("内容跨页遗漏或重复", previous)
	}
	for i := 1; i < len(conversation.Jobs); i++ {
		if conversation.Jobs[i].CreatedAt.Before(conversation.Jobs[i-1].CreatedAt) {
			t.Fatal("对话显示顺序不是从早到晚")
		}
	}
	history, err := f.Runtime.AnalysisHistory(ctx, u, seed.Request.ThreadID)
	require(t, err)
	if len(history) != 8 || history[len(history)-1].Question != input.Question {
		t.Fatal("历史上下文数量或顺序错误", history)
	}
	chatPage, err := f.Runtime.AnalysisJobs(ctx, u, "chat", "", 2)
	require(t, err)
	if len(chatPage.Items) != 2 || chatPage.Next == "" {
		t.Fatal("作业分页边界缺失", chatPage)
	}
	second, err := f.Runtime.AnalysisJobs(ctx, u, "chat", chatPage.Next, 2)
	require(t, err)
	for _, a := range chatPage.Items {
		for _, b := range second.Items {
			if a.ID == b.ID {
				t.Fatal("作业跨页重复")
			}
		}
	}
	var principalCount int
	require(t, f.Owner.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM analysis_jobs WHERE tenant_id=$1`, tenant).Scan(&principalCount)
	}))
	if principalCount != 36 {
		t.Fatalf("分页夹具泄露或缺少记录：%d", principalCount)
	}
	if _, e := json.Marshal(conversation); e != nil {
		t.Fatal("内容不能编码为接口响应", e)
	}
	for _, reason := range []string{"missing_window", "reversed_window", "oversized_window", "unknown_kind", "analysis_input_invalid", "authorization_revoked"} {
		guarded, e := f.Runtime.CreateAnalysis(ctx, u, input, "guard_"+reason, assistant.Evidence{}, "限定证据范围", queue, vault, "guard_"+reason)
		require(t, e)
		var guardedRiverID int64
		require(t, f.Owner.Pool.QueryRow(ctx, `SELECT river_job_id FROM analysis_jobs WHERE tenant_id=$1 AND id=$2`, tenant, guarded.ID).Scan(&guardedRiverID))
		wantCode := "analysis_input_invalid"
		switch reason {
		case "missing_window":
			_, e = f.Owner.Pool.Exec(ctx, `UPDATE analysis_jobs SET request=jsonb_set(request,'{window}','{}') WHERE tenant_id=$1 AND id=$2`, tenant, guarded.ID)
		case "reversed_window", "oversized_window":
			window := input.Window
			if reason == "reversed_window" {
				window.End = window.Start.Add(-time.Second)
			} else {
				window.End = window.Start.Add(31*24*time.Hour + time.Second)
			}
			raw, marshalErr := json.Marshal(window)
			require(t, marshalErr)
			_, e = f.Owner.Pool.Exec(ctx, `UPDATE analysis_jobs SET request=jsonb_set(request,'{window}',$3::jsonb) WHERE tenant_id=$1 AND id=$2`, tenant, guarded.ID, raw)
		case "unknown_kind":
			_, e = f.Owner.Pool.Exec(ctx, `UPDATE analysis_jobs SET request=jsonb_set(request,'{kind}','"unknown"') WHERE tenant_id=$1 AND id=$2`, tenant, guarded.ID)
		case "analysis_input_invalid":
			_, e = f.Owner.Pool.Exec(ctx, `UPDATE analysis_jobs SET prompt='被改变的提示材料' WHERE tenant_id=$1 AND id=$2`, tenant, guarded.ID)
		case "authorization_revoked":
			wantCode = reason
			_, e = f.Owner.Pool.Exec(ctx, `UPDATE users SET role='viewer' WHERE tenant_id=$1 AND id=$2`, tenant, u.ID)
		}
		require(t, e)
		blocked, e := f.Runtime.StartAnalysis(ctx, assistant.Args{TenantID: tenant, JobID: guarded.ID}, guardedRiverID, vault)
		require(t, e)
		if blocked.Execute {
			t.Fatal("失效授权或损坏提示仍取得外部调用资格")
		}
		var code string
		require(t, f.Owner.Pool.QueryRow(ctx, `SELECT result->>'code' FROM analysis_jobs WHERE tenant_id=$1 AND id=$2`, tenant, guarded.ID).Scan(&code))
		if code != wantCode {
			t.Fatal("拒绝调用的业务原因不一致", code, wantCode)
		}
	}
	_, err = f.Owner.Pool.Exec(ctx, `UPDATE users SET role='admin' WHERE tenant_id=$1 AND id=$2`, tenant, u.ID)
	require(t, err)
	config.Enabled = false
	_, err = f.Runtime.SaveModelProvider(ctx, u, store.ModelChange{ID: "provider_owned", ExpectedRevision: 1, Config: config, ReplaceKey: true}, vault, outbound.Policy{}, "disable_provider")
	require(t, err)
	for _, revision := range []int64{1, 2} {
		stale := input
		stale.ProviderRevision = revision
		if _, err := f.Runtime.CreateAnalysis(ctx, u, stale, fmt.Sprintf("disabled_revision_%d", revision), assistant.Evidence{}, "限定证据范围", queue, vault, "disabled"); !errors.Is(err, store.ErrConflict) {
			t.Fatal("过期修订或停用模型仍可提交业务作业", revision, err)
		}
	}
	_, err = f.Owner.Pool.Exec(ctx, `UPDATE analysis_jobs SET request=jsonb_set(request,'{window}','"invalid_window"') WHERE tenant_id=$1 AND id=$2`, tenant, seed.ID)
	require(t, err)
	if _, err := f.Runtime.AnalysisJobs(ctx, u, "chat", "", 20); err == nil {
		t.Fatal("损坏统计窗口被呈现为有效作业")
	}
	if _, err := f.Runtime.AnalysisConversation(ctx, u, seed.Request.ThreadID, ""); err == nil {
		t.Fatal("损坏作业被呈现为有效对话")
	}
}
