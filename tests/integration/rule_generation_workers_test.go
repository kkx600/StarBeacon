//go:build integration

package integration

import (
	"context"
	"crypto/x509"
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
	"github.com/kkx600/StarBeacon/internal/testpcap"
)

func TestRuleGenerationWorkersVerifySourcesRejectOutputAndRetainUnknownCalls(t *testing.T) {
	ctx, stop := context.WithTimeout(context.Background(), 120*time.Second)
	defer stop()
	f := newIsolatedDatabase(t, ctx)
	tenant, password := store.RandomID("it_generation_work_"), store.Token()
	require(t, admin.Bootstrap(ctx, f.Owner, tenant, "生成队列验收", tenant, password, "admin"))
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
	config := llm.Config{Name: "队列输出模型", Kind: "openai_responses", BaseURL: provider.URL + "/v1", Model: "owned-rule-model", Enabled: true, APIKey: "owned-rule-generation-key", MaxOutputTokens: 1024, TimeoutSeconds: 10, DailyRequests: 1000}
	_, err = f.Runtime.SaveModelProvider(ctx, u, store.ModelChange{ID: "provider_owned", ReplaceKey: true, Config: config}, vault, policy, "provider_seed")
	require(t, err)
	queue, err := jobs.NewAnalysis(f.Runtime, vault, policy)
	require(t, err)
	objects, err := replay.NewLocal(filepath.Join(t.TempDir(), "samples"), 128<<20)
	require(t, err)
	a := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime, Vault: vault, Jobs: queue, Samples: objects, SampleQuota: 128 << 20}, tenant, password)
	work, cancelWork := context.WithCancel(context.WithoutCancel(ctx))
	defer cancelWork()
	require(t, queue.Start(work))
	defer func() {
		clean, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		require(t, queue.StopAndCancel(clean))
	}()
	input := rulegen.Request{Description: "定义请求路径候选", Source: "natural_language", ProviderID: "provider_owned", ProviderRevision: 1, CandidateCount: 3, AllowContext: true}
	create := func(key string, input rulegen.Request) rulegen.Job {
		var job rulegen.Job
		a.request("POST", "/rule-generation/jobs", key, input, &job, 202)
		if job.State != "queued" || job.Result.State != "queued" || job.Result.Code != "awaiting_execution" || job.Result.DurationMS != nil {
			t.Fatal("受理状态与尚未调用的耗时不准确")
		}
		return job
	}
	wait := func(id string) rulegen.Job {
		var job rulegen.Job
		eventually(t, ctx, "实际生成作业进入终态", func() bool {
			a.request("GET", "/rule-generation/jobs/"+id, "", nil, &job, 200)
			return job.State != "queued" && job.State != "running"
		})
		return job
	}
	natural := create("natural_owned", input)
	natural = wait(natural.ID)
	if natural.State != "succeeded" || len(natural.Candidates) != 3 || natural.Evidence.Sample != nil || len(natural.Evidence.Packets) != 0 || calls.Load() != 1 {
		t.Fatal("自然语言三候选或模型调用计数不准确")
	}
	for i, candidate := range natural.Candidates {
		if candidate.SID != rulegen.MinSID+uint32(i) || len(candidate.References) != 0 {
			t.Fatal("独立 SID 或无样本来源被补造")
		}
	}
	pcap, err := testpcap.HTTP(false)
	require(t, err)
	var sample replay.Sample
	a.request("POST", "/replay/samples", "", pcap, &sample, 201)
	input.Source, input.SampleID, input.SampleSHA256, input.CandidateCount = "pcap", sample.ID, sample.SHA256, 1
	wrong := input
	wrong.Source = "http_raw"
	a.request("POST", "/rule-generation/jobs", "source_mismatch", wrong, nil, 400)
	wrong = input
	wrong.SampleSHA256 = control.Digest([]byte("wrong"))
	a.request("POST", "/rule-generation/jobs", "digest_mismatch", wrong, nil, 409)
	pcapJob := create("pcap_owned", input)
	pcapJob = wait(pcapJob.ID)
	if pcapJob.State != "succeeded" || pcapJob.Evidence.Sample == nil || pcapJob.Evidence.Sample.Origin != nil || pcapJob.Evidence.Sample.SHA256 != sample.SHA256 || len(pcapJob.Candidates) != 1 || len(pcapJob.Candidates[0].References) == 0 || calls.Load() != 2 {
		t.Fatal("原始 PCAP 来源、帧引用或调用计数不准确")
	}
	var empty replay.Sample
	a.request("POST", "/replay/samples", "", pcap[:24], &empty, 201)
	invalidMaterial := input
	invalidMaterial.SampleID, invalidMaterial.SampleSHA256 = empty.ID, empty.SHA256
	a.request("POST", "/rule-generation/jobs", "empty_container", invalidMaterial, nil, 422)
	if calls.Load() != 2 {
		t.Fatal("无可解析包的材料错误调用模型")
	}
	input.Source, input.SampleID, input.SampleSHA256 = "natural_language", "", ""
	input.Description = "[invalid_output] 拒绝执行动作候选"
	bad := create("invalid_output_owned", input)
	bad = wait(bad.ID)
	if bad.State != "failed" || bad.Result.Code != "invalid_generation_output" || len(bad.Candidates) != 0 || bad.Result.Text != "" || calls.Load() != 3 {
		t.Fatal("违规模型输出未在保存候选前拒绝")
	}
	a.request("POST", "/rule-generation/jobs/"+bad.ID+"/adopt", "", map[string]any{"sid": bad.SIDs[0]}, nil, 409)
	input.Description = "[uncertain] 提供方调用结果未知"
	unknown := create("uncertain_owned", input)
	unknown = wait(unknown.ID)
	if unknown.State != "uncertain" || unknown.Result.Code != "provider_result_unknown" || len(unknown.Candidates) != 0 || calls.Load() != 4 {
		t.Fatal("未知结果被当成失败可重复调用或成功")
	}
	var repeated rulegen.Job
	a.request("POST", "/rule-generation/jobs", "uncertain_owned", input, &repeated, 200)
	if repeated.ID != unknown.ID || repeated.State != "uncertain" || calls.Load() != 4 {
		t.Fatal("未知原请求再次调用模型")
	}
	input.Description = "[cancel_after_send] 取消已到达提供方的生成"
	running := create("running_cancel_owned", input)
	eventually(t, ctx, "提供方确已收到取消目标请求", func() bool {
		a.request("GET", "/rule-generation/jobs/"+running.ID, "", nil, &running, 200)
		return running.State == "running" && calls.Load() == 5
	})
	started := time.Now()
	a.request("POST", "/rule-generation/jobs/"+running.ID+"/cancel", "", struct{}{}, nil, 200)
	running = wait(running.ID)
	if !running.CancelRequested || running.State != "uncertain" || running.Result.Code != "provider_result_unknown" || time.Since(started) >= 8*time.Second || calls.Load() != 5 {
		t.Fatal("已发送请求取消后没有保留未知结果，或未在提供方超时前停止本地请求")
	}
	// 过期样本的冻结摘要仍然存在，但不能获得新的出站调用资格。
	require(t, queue.StopAndCancel(ctx))
	input.Description, input.Source, input.SampleID, input.SampleSHA256 = "排队后样本到期", "pcap", sample.ID, sample.SHA256
	expiring := create("sample_expired_owned", input)
	var riverID int64
	require(t, f.Owner.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE replay_samples SET expires_at=now()-interval '1 second' WHERE tenant_id=$1 AND id=$2`, tenant, sample.ID); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT river_job_id FROM rule_generation_jobs WHERE tenant_id=$1 AND id=$2`, tenant, expiring.ID).Scan(&riverID)
	}))
	lease, err := f.Runtime.StartRuleGeneration(ctx, rulegen.Args{TenantID: tenant, JobID: expiring.ID}, riverID, vault)
	require(t, err)
	if lease.Execute {
		t.Fatal("已到期样本仍获调用租约")
	}
	expiring = wait(expiring.ID)
	if expiring.Result.Code != "sample_unavailable" || calls.Load() != 5 {
		t.Fatal("样本到期错误调用模型")
	}
	t.Log("真实 River、HTTPS SDK 与样本来源检查通过；受控模型只验证协议，不代表领域生成效果。")
}
