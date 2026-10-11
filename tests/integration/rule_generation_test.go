//go:build integration

package integration

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/admin"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/jobs"
	"github.com/kkx600/StarBeacon/internal/llm"
	"github.com/kkx600/StarBeacon/internal/outbound"
	"github.com/kkx600/StarBeacon/internal/platform"
	"github.com/kkx600/StarBeacon/internal/replay"
	"github.com/kkx600/StarBeacon/internal/rulegen"
	"github.com/kkx600/StarBeacon/internal/secrets"
	"github.com/kkx600/StarBeacon/internal/store"
)

// 真实数据库验证预留、资格、取消与失败恢复；不把人工完成租约当成模型效果验收。
func TestRuleGenerationPersistentOwnershipSIDBudgetAndRecovery(t *testing.T) {
	ctx, stop := context.WithTimeout(context.Background(), 120*time.Second)
	defer stop()
	f := newIsolatedDatabase(t, ctx)
	tenant, foreign, password := store.RandomID("it_generation_"), store.RandomID("it_generation_other_"), store.Token()
	for _, v := range []struct{ tenant, user, role string }{{tenant, tenant, "admin"}, {tenant, tenant + "_other", "admin"}, {tenant, tenant + "_viewer", "viewer"}, {foreign, foreign, "admin"}} {
		require(t, admin.Bootstrap(ctx, f.Owner, v.tenant, "规则生成验收", v.user, password, v.role))
	}
	u, _, err := f.Runtime.Password(ctx, tenant)
	require(t, err)
	vault, err := secrets.New(store.Token())
	require(t, err)
	provider, calls := newGenerationProvider(t)
	defer provider.Close()
	networks, err := outbound.ParseNetworks("127.0.0.0/8")
	require(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(provider.Certificate())
	policy := outbound.Policy{PrivateNetworks: networks, Roots: roots}
	config := llm.Config{Name: "生成资格模型", Kind: "openai_responses", BaseURL: provider.URL + "/v1", Model: "owned-rule-model", Enabled: true, APIKey: "owned-rule-generation-key", MaxOutputTokens: 1024, TimeoutSeconds: 5, DailyRequests: 1000}
	_, err = f.Runtime.SaveModelProvider(ctx, u, store.ModelChange{ID: "provider_owned", ReplaceKey: true, Config: config}, vault, policy, "provider_seed")
	require(t, err)
	queue, err := jobs.NewAnalysis(f.Runtime, vault, policy)
	require(t, err)
	objects, err := replay.NewLocal(filepath.Join(t.TempDir(), "samples"), 128<<20)
	require(t, err)
	api := &platform.API{DB: f.Runtime, Vault: vault, Outbound: policy, Jobs: queue, Samples: objects, SampleQuota: 128 << 20}
	a := authenticatedFaultHTTP(t, ctx, f.Runtime, api, tenant, password)
	other := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime, Vault: vault, Jobs: queue}, tenant+"_other", password)
	b := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime, Vault: vault, Jobs: queue}, foreign, password)
	viewer := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime}, tenant+"_viewer", password)
	input := rulegen.Request{Description: "定义请求路径检测", Source: "natural_language", ProviderID: "provider_owned", ProviderRevision: 1, CandidateCount: 1, AllowContext: true}
	var job rulegen.Job
	a.request("POST", "/rule-generation/jobs", "generation_owned", input, &job, 202)
	if job.State != "queued" || len(job.SIDs) != 1 || job.SIDs[0] != rulegen.MinSID || len(job.Candidates) != 0 || job.Template != rulegen.TemplateVersion {
		t.Fatal("持久预留与 SID 分配不准确")
	}
	first := job
	a.request("POST", "/rule-generation/jobs", "generation_owned", input, &job, 200)
	if job.ID != first.ID {
		t.Fatal("幂等键改变了作业")
	}
	changed := input
	changed.Description += "另一目标"
	a.request("POST", "/rule-generation/jobs", "generation_owned", changed, nil, 409)
	a.request("POST", "/models/providers/provider_owned/test", "shared_generation_budget", map[string]any{"expected_revision": 1}, nil, 429)
	for _, client := range []*liveHTTP{other, b} {
		client.request("GET", "/rule-generation/jobs/"+job.ID, "", nil, nil, 404)
		client.request("POST", "/rule-generation/jobs/"+job.ID+"/cancel", "", struct{}{}, nil, 404)
	}
	for _, request := range []struct {
		method, path string
		body         any
	}{{"GET", "/rule-generation/jobs", nil}, {"GET", "/rule-generation/jobs/" + job.ID, nil}, {"POST", "/rule-generation/jobs", input}, {"POST", "/rule-generation/jobs/" + job.ID + "/cancel", struct{}{}}, {"POST", "/rule-generation/jobs/" + job.ID + "/adopt", map[string]any{"sid": job.SIDs[0]}}} {
		viewer.request(request.method, request.path, "viewer_owned", request.body, nil, 403)
	}
	a.request("POST", "/rule-generation/jobs/"+job.ID+"/adopt", "", map[string]any{"sid": job.SIDs[0]}, nil, 409)
	a.request("POST", "/rule-generation/jobs/"+job.ID+"/cancel", "", map[string]any{"unknown": true}, nil, 400)
	a.request("POST", "/rule-generation/jobs/"+job.ID+"/cancel", "", struct{}{}, &job, 200)
	a.request("POST", "/rule-generation/jobs/"+job.ID+"/cancel", "", struct{}{}, &job, 200)
	if job.State != "cancelled" || !job.CancelRequested || calls.Load() != 0 {
		t.Fatal("排队取消错误调用模型")
	}
	riverID := func(job rulegen.Job) int64 {
		var id int64
		require(t, f.Owner.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT river_job_id FROM rule_generation_jobs WHERE tenant_id=$1 AND id=$2`, tenant, job.ID).Scan(&id)
		}))
		return id
	}
	lease, err := f.Runtime.StartRuleGeneration(ctx, rulegen.Args{TenantID: tenant, JobID: job.ID}, riverID(job), vault)
	require(t, err)
	if lease.Execute {
		t.Fatal("取消作业被重新执行")
	}
	if _, err := f.Runtime.ExistingRuleGeneration(ctx, u, "bad key", rulegen.InputHash(input)); !errors.Is(err, rulegen.ErrInput) {
		t.Fatal(err)
	}
	if _, err := f.Runtime.ExistingRuleGeneration(ctx, u, "owned_missing", rulegen.InputHash(input)); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal(err)
	}
	newJob := func(name string) rulegen.Job {
		var v rulegen.Job
		a.request("POST", "/rule-generation/jobs", name, input, &v, 202)
		return v
	}
	failed := newJob("provider_changed")
	revised := config
	revised.APIKey = ""
	_, err = f.Runtime.SaveModelProvider(ctx, u, store.ModelChange{ID: "provider_owned", ExpectedRevision: 1, Config: revised}, vault, policy, "provider_revision")
	require(t, err)
	lease, err = f.Runtime.StartRuleGeneration(ctx, rulegen.Args{TenantID: tenant, JobID: failed.ID}, riverID(failed), vault)
	require(t, err)
	if lease.Execute {
		t.Fatal("旧模型修订仍执行")
	}
	a.request("GET", "/rule-generation/jobs/"+failed.ID, "", nil, &failed, 200)
	if failed.Result.Code != "provider_revision_changed" {
		t.Fatal(failed.Result.Code)
	}
	input.ProviderRevision = 2
	for _, kind := range []string{"owner", "vault", "prompt", "queue_deadline"} {
		v := newJob("guard_" + kind)
		switch kind {
		case "owner":
			require(t, f.Owner.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
				_, e := tx.Exec(ctx, `UPDATE users SET active=false WHERE tenant_id=$1 AND id=$2`, tenant, u.ID)
				return e
			}))
		case "prompt":
			require(t, f.Owner.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
				_, e := tx.Exec(ctx, `UPDATE rule_generation_jobs SET prompt=prompt||'changed' WHERE tenant_id=$1 AND id=$2`, tenant, v.ID)
				return e
			}))
		case "queue_deadline":
			require(t, f.Owner.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
				_, e := tx.Exec(ctx, `UPDATE rule_generation_jobs SET deadline=now()-interval '1 second' WHERE tenant_id=$1 AND id=$2`, tenant, v.ID)
				return e
			}))
		}
		usedVault := vault
		if kind == "vault" {
			usedVault, err = secrets.New(store.Token())
			require(t, err)
		}
		lease, err = f.Runtime.StartRuleGeneration(ctx, rulegen.Args{TenantID: tenant, JobID: v.ID}, riverID(v), usedVault)
		require(t, err)
		if lease.Execute {
			t.Fatal("失效执行资格仍调用模型", kind)
		}
		if kind == "owner" {
			require(t, f.Owner.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
				_, e := tx.Exec(ctx, `UPDATE users SET active=true WHERE tenant_id=$1 AND id=$2`, tenant, u.ID)
				return e
			}))
		}
		v, err = f.Runtime.RuleGeneration(ctx, u, v.ID)
		require(t, err)
		want := map[string]string{"owner": "authorization_revoked", "vault": "provider_config_unavailable", "prompt": "generation_input_invalid", "queue_deadline": "queue_wait_expired"}[kind]
		if v.State != "failed" || v.Result.Code != want {
			t.Fatal("失败资格没有准确落库", kind, v.State, v.Result.Code)
		}
	}
	running := newJob("running_owned")
	if _, err := f.Runtime.StartRuleGeneration(ctx, rulegen.Args{TenantID: tenant, JobID: running.ID}, riverID(running)+10000, vault); !errors.Is(err, store.ErrConflict) {
		t.Fatal(err)
	}
	lease, err = f.Runtime.StartRuleGeneration(ctx, rulegen.Args{TenantID: tenant, JobID: running.ID}, riverID(running), vault)
	require(t, err)
	if !lease.Execute {
		t.Fatal("有效租约未取得")
	}
	if again, err := f.Runtime.StartRuleGeneration(ctx, rulegen.Args{TenantID: tenant, JobID: running.ID}, riverID(running), vault); err != nil || again.Execute {
		t.Fatal("运行租约被重复取得", err)
	}
	candidate := rulegen.Candidate{SID: running.SIDs[0], EngineVersion: "8.0.7", Title: "受控路径检测", Rule: fmt.Sprintf(`alert http any any -> any any (msg:"受控路径"; http.uri; content:"/starbeacon/ai-validation"; sid:%d; rev:1;)`, running.SIDs[0]), Explanation: "人工结果用于验证存储契约；原生验证由独立链路承担。", Risks: []string{}, References: []int64{}}
	candidate.SHA256 = control.Digest([]byte(candidate.Rule))
	candidate.PackageID = rulegen.PackageID(running.ID, candidate.SID)
	result := llm.Result{State: "succeeded", Code: "completed", ReturnedModel: "owned-rule-model", Usage: &llm.Usage{InputTokens: 3, OutputTokens: 4, TotalTokens: 7}}
	wrong := lease
	wrong.Token = "wrong"
	if err := f.Runtime.FinishRuleGeneration(ctx, tenant, wrong, result, []rulegen.Candidate{candidate}); !errors.Is(err, store.ErrConflict) {
		t.Fatal("错误租约写入结果", err)
	}
	if err := f.Runtime.FinishRuleGeneration(ctx, foreign, lease, result, []rulegen.Candidate{candidate}); !errors.Is(err, store.ErrConflict) {
		t.Fatal("跨租户结果被接受", err)
	}
	bad := candidate
	bad.SHA256 = store.Token()
	if err := f.Runtime.FinishRuleGeneration(ctx, tenant, lease, result, []rulegen.Candidate{bad}); !errors.Is(err, rulegen.ErrOutput) {
		t.Fatal("错误摘要被保存", err)
	}
	require(t, f.Runtime.FinishRuleGeneration(ctx, tenant, lease, result, []rulegen.Candidate{candidate}))
	if err := f.Runtime.FinishRuleGeneration(ctx, tenant, lease, result, []rulegen.Candidate{candidate}); !errors.Is(err, store.ErrConflict) {
		t.Fatal("终态被覆写", err)
	}
	a.request("POST", "/rule-packages", "", map[string]any{"id": candidate.PackageID, "name": candidate.Title, "text": candidate.Rule + " ", "expected_revision": 0}, nil, 409)
	var pkg store.RulePackage
	a.request("POST", "/rule-generation/jobs/"+running.ID+"/adopt", "", map[string]any{"sid": candidate.SID}, &pkg, 200)
	a.request("POST", "/rule-generation/jobs/"+running.ID+"/adopt", "", map[string]any{"sid": candidate.SID}, &pkg, 200)
	if pkg.GenerationID == nil || *pkg.GenerationID != running.ID || pkg.GenerationSID == nil || *pkg.GenerationSID != candidate.SID {
		t.Fatal("候选出处缺失")
	}
	a.request("POST", "/rule-packages", "", map[string]any{"id": "pkg_collision", "name": "冲突规则", "text": candidate.Rule, "expected_revision": 0}, nil, 409)
	a.request("POST", "/rule-packages", "", map[string]any{"id": pkg.ID, "name": "人工修订规则", "text": candidate.Rule, "expected_revision": 1}, &pkg, 201)
	if pkg.Revision != 2 || pkg.GenerationID == nil {
		t.Fatal("人工修订丢失创建出处")
	}
	a.request("POST", "/rule-generation/jobs/"+running.ID+"/adopt", "", map[string]any{"sid": candidate.SID}, &pkg, 200)
	if pkg.Revision != 1 {
		t.Fatal("重复采用覆盖了人工修订")
	}
	unknown := newJob("uncertain_owned")
	lease, err = f.Runtime.StartRuleGeneration(ctx, rulegen.Args{TenantID: tenant, JobID: unknown.ID}, riverID(unknown), vault)
	require(t, err)
	require(t, f.Owner.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE rule_generation_jobs SET deadline=now()-interval '1 second' WHERE tenant_id=$1 AND id=$2`, tenant, unknown.ID)
		return e
	}))
	if err := f.Runtime.FinishRuleGeneration(ctx, tenant, lease, llm.Result{State: "failed", Code: "provider_unavailable"}, nil); !errors.Is(err, store.ErrConflict) {
		t.Fatal("迟到结果覆写未知状态", err)
	}
	a.request("GET", "/rule-generation/jobs/"+unknown.ID, "", nil, &unknown, 200)
	if unknown.State != "uncertain" || unknown.Result.Code != "provider_result_unknown" {
		t.Fatal("不确定结果被重试或认定为零费用")
	}
	var page store.GenerationPage
	a.request("GET", "/rule-generation/jobs", "", nil, &page, 200)
	if len(page.Items) == 0 {
		t.Fatal("生成历史缺失")
	}
	a.request("GET", "/rule-generation/jobs?before="+page.Items[0].ID, "", nil, &page, 200)
	a.request("GET", "/rule-generation/jobs?before=owned_missing", "", nil, nil, 404)
	a.request("GET", "/rule-generation/jobs?before=bad%20cursor", "", nil, nil, 400)
	a.request("POST", "/rule-generation/jobs/"+running.ID+"/adopt", "", map[string]any{"sid": 1}, nil, 400)
	a.request("POST", "/rule-generation/jobs/"+running.ID+"/adopt", "", map[string]any{"sid": rulegen.MaxSID}, nil, 404)
	if calls.Load() != 0 {
		t.Fatal("数据库资格测试不应发送模型请求")
	}
	t.Log("真实 PostgreSQL 验证幂等、角色与归属、不可复用 SID、共享并发额度、候选出处、模型修订、撤权、密钥、迟到响应和恢复；无模型效果声明。")
}
