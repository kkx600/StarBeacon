//go:build integration

package integration

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/admin"
	"github.com/kkx600/StarBeacon/internal/jobs"
	"github.com/kkx600/StarBeacon/internal/llm"
	"github.com/kkx600/StarBeacon/internal/outbound"
	"github.com/kkx600/StarBeacon/internal/replay"
	"github.com/kkx600/StarBeacon/internal/rulegen"
	"github.com/kkx600/StarBeacon/internal/secrets"
	"github.com/kkx600/StarBeacon/internal/store"
)

func TestRuleGenerationBoundedHistorySIDExhaustionAndDisabledProvider(t *testing.T) {
	ctx, stop := context.WithTimeout(context.Background(), 90*time.Second)
	defer stop()
	f := newIsolatedDatabase(t, ctx)
	tenant := store.RandomID("it_generation_capacity_")
	require(t, admin.Bootstrap(ctx, f.Owner, tenant, "规则生成容量验收", tenant, store.Token(), "admin"))
	u, _, err := f.Runtime.Password(ctx, tenant)
	require(t, err)
	vault, err := secrets.New(store.Token())
	require(t, err)
	config := llm.Config{Name: "容量资格模型", Kind: "openai_responses", BaseURL: "https://models.example.com/v1", Model: "owned", Enabled: true, APIKey: "owned-key", MaxOutputTokens: 256, TimeoutSeconds: 5, DailyRequests: 10000}
	_, err = f.Runtime.SaveModelProvider(ctx, u, store.ModelChange{ID: "provider_owned", ReplaceKey: true, Config: config}, vault, outbound.Policy{}, "seed")
	require(t, err)
	queue, err := jobs.NewAnalysis(f.Runtime, vault, outbound.Policy{})
	require(t, err)
	evidence, err := rulegen.Seal(rulegen.Evidence{Packets: []replay.PacketSnippet{}})
	require(t, err)
	input := rulegen.Request{Description: "定义受控请求路径检测", Source: "natural_language", ProviderID: "provider_owned", ProviderRevision: 1, CandidateCount: 1, AllowContext: true}
	create := func(key string) rulegen.Job {
		v, e := f.Runtime.CreateRuleGeneration(ctx, u, input, key, evidence, queue, vault, key)
		require(t, e)
		return v
	}
	// 只登记七个专属夹具 SID，核对连续占用区跳过；不模拟百万条吞吐。
	_, err = f.Owner.Pool.Exec(ctx, `INSERT INTO rule_sid_registry(tenant_id,sid,package_id) SELECT $1,n,'pkg_owned' FROM generate_series($2::bigint,$3::bigint) n`, tenant, rulegen.MinSID, rulegen.MinSID+6)
	require(t, err)
	first := create("history_00")
	if len(first.SIDs) != 1 || first.SIDs[0] != rulegen.MinSID+7 {
		t.Fatal("重复分配既有 SID，或没有跳过连续占用区", first.SIDs)
	}
	repeated := create("history_00")
	if repeated.ID != first.ID || repeated.SIDs[0] != first.SIDs[0] {
		t.Fatal("幂等重试重新分配 SID")
	}
	if _, err := f.Runtime.CancelRuleGeneration(ctx, u, first.ID, nil, "no_queue"); !errors.Is(err, store.ErrConflict) {
		t.Fatal("无队列的撤销被声明成功", err)
	}
	_, err = f.Runtime.CancelRuleGeneration(ctx, u, first.ID, queue, "cancel")
	require(t, err)
	for i := 1; i < 22; i++ {
		v := create(fmt.Sprintf("history_%02d", i))
		if v.SIDs[0] != rulegen.MinSID+7+uint32(i) {
			t.Fatal("SID 游标存在重复或无解释缺口")
		}
		_, err = f.Runtime.CancelRuleGeneration(ctx, u, v.ID, queue, "cancel")
		require(t, err)
	}
	page, err := f.Runtime.RuleGenerations(ctx, u, "")
	require(t, err)
	if len(page.Items) != 20 || page.Next == "" {
		t.Fatal("规则生成历史没有二十条分页", len(page.Items))
	}
	next, err := f.Runtime.RuleGenerations(ctx, u, page.Next)
	require(t, err)
	if len(next.Items) != 2 || next.Next != "" {
		t.Fatal("规则生成历史翻页丢失或重复", len(next.Items))
	}
	seen := map[string]bool{}
	for _, item := range append(page.Items, next.Items...) {
		if seen[item.ID] || item.State != "cancelled" || !item.CancelRequested {
			t.Fatal("规则历史状态或分页不正确")
		}
		seen[item.ID] = true
	}
	blocked := create("disabled_guard")
	raw, err := llm.Encode(func() llm.Config { v := config; v.Enabled = false; return v }())
	require(t, err)
	cipher, err := vault.Seal(tenant, "model", "provider_owned", 1, raw)
	require(t, err)
	_, err = f.Owner.Pool.Exec(ctx, `UPDATE model_provider_versions SET ciphertext=$2 WHERE tenant_id=$1 AND provider_id='provider_owned' AND revision=1`, tenant, cipher)
	require(t, err)
	var riverID int64
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT river_job_id FROM rule_generation_jobs WHERE tenant_id=$1 AND id=$2`, tenant, blocked.ID).Scan(&riverID))
	lease, err := f.Runtime.StartRuleGeneration(ctx, rulegen.Args{TenantID: tenant, JobID: blocked.ID}, riverID, vault)
	require(t, err)
	if lease.Execute {
		t.Fatal("已停用模型仍取得生成租约")
	}
	blocked, err = f.Runtime.RuleGeneration(ctx, u, blocked.ID)
	require(t, err)
	if blocked.State != "failed" || blocked.Result.Code != "provider_disabled" || len(blocked.Candidates) != 0 {
		t.Fatal("停用模型没有准确终止生成")
	}
	if _, err := f.Runtime.CreateRuleGeneration(ctx, u, input, "disabled_create", evidence, queue, vault, "disabled"); !errors.Is(err, store.ErrConflict) {
		t.Fatal("创建绕过模型停用状态", err)
	}
	raw, err = llm.Encode(config)
	require(t, err)
	cipher, err = vault.Seal(tenant, "model", "provider_owned", 1, raw)
	require(t, err)
	_, err = f.Owner.Pool.Exec(ctx, `UPDATE model_provider_versions SET ciphertext=$2 WHERE tenant_id=$1 AND provider_id='provider_owned' AND revision=1`, tenant, cipher)
	require(t, err)
	snapshot := func() string {
		var raw []byte
		require(t, f.Owner.Pool.QueryRow(ctx, `SELECT jsonb_build_object('jobs',(SELECT count(*) FROM rule_generation_jobs WHERE tenant_id=$1),'sids',(SELECT count(*) FROM rule_sid_registry WHERE tenant_id=$1),'queue',(SELECT count(*) FROM starbeacon_jobs.river_job WHERE args->>'tenant_id'=$1),'audit',(SELECT count(*) FROM operation_audits WHERE tenant_id=$1),'cursor',(SELECT next_sid FROM rule_sid_state WHERE tenant_id=$1))`, tenant).Scan(&raw))
		return string(raw)
	}
	for _, cursor := range []uint32{rulegen.MaxSID + 1, rulegen.MaxSID} {
		_, err = f.Owner.Pool.Exec(ctx, `UPDATE rule_sid_state SET next_sid=$2 WHERE tenant_id=$1`, tenant, cursor)
		require(t, err)
		if cursor == rulegen.MaxSID {
			_, err = f.Owner.Pool.Exec(ctx, `INSERT INTO rule_sid_registry(tenant_id,sid,package_id) VALUES($1,$2,'pkg_last')`, tenant, cursor)
			require(t, err)
		}
		before := snapshot()
		if _, err := f.Runtime.CreateRuleGeneration(ctx, u, input, fmt.Sprintf("exhausted_%d", cursor), evidence, queue, vault, "capacity"); !errors.Is(err, rulegen.ErrSID) {
			t.Fatal("SID 空间用尽后继续受理生成", err)
		}
		if snapshot() != before {
			t.Fatal("SID 预留失败留下队列、审计或游标变更")
		}
	}
	_, err = f.Owner.Pool.Exec(ctx, `INSERT INTO rule_generation_jobs(tenant_id,id,created_by,provider_id,provider_revision,request,request_hash,idempotency_key_hash,template,evidence,assigned_sids,prompt,prompt_hash,state,result,deadline) SELECT $1,'quota_'||n,$2,'provider_owned',1,$3,$4,'quota_'||n,$5,$6,'[]','owned',$4,'cancelled','{"state":"cancelled","code":"cancelled_before_execution"}',now() FROM generate_series(1,1000) n`, tenant, u.ID, mustTriageJSON(t, input), rulegen.InputHash(input), rulegen.TemplateVersion, mustTriageJSON(t, evidence))
	require(t, err)
	if _, err := f.Runtime.CreateRuleGeneration(ctx, u, input, "daily_limit", evidence, queue, vault, "daily"); !errors.Is(err, store.ErrModelQuota) {
		t.Fatal("租户生成日额度被绕过", err)
	}
	t.Log("实际 PostgreSQL SID 排他预留、未知配置资格和有界历史核对通过；不启用模型出站调用。")
}
