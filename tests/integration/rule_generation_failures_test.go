//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/admin"
	"github.com/kkx600/StarBeacon/internal/jobs"
	"github.com/kkx600/StarBeacon/internal/llm"
	"github.com/kkx600/StarBeacon/internal/outbound"
	"github.com/kkx600/StarBeacon/internal/replay"
	"github.com/kkx600/StarBeacon/internal/rulegen"
	"github.com/kkx600/StarBeacon/internal/secrets"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/riverqueue/river"
)

// 断开专属测试数据库连接，证明 SID、模型额度、队列与审计事务不会留下部分成功。
func TestRuleGenerationDatabaseInterruptionPreservesSIDQueueAndCandidates(t *testing.T) {
	ctx, stop := context.WithTimeout(context.Background(), 90*time.Second)
	defer stop()
	f := newIsolatedDatabase(t, ctx)
	tenant := store.RandomID("it_generation_fault_")
	require(t, admin.Bootstrap(ctx, f.Owner, tenant, "规则生成故障验收", tenant, store.Token(), "admin"))
	u, _, err := f.Runtime.Password(ctx, tenant)
	require(t, err)
	vault, err := secrets.New(store.Token())
	require(t, err)
	policy := outbound.Policy{}
	_, err = f.Runtime.SaveModelProvider(ctx, u, store.ModelChange{ID: "provider_owned", ReplaceKey: true, Config: llm.Config{Name: "生成边界模型", Kind: "openai_responses", BaseURL: "https://models.example.com/v1", Model: "owned", Enabled: true, APIKey: "owned-generation-key", MaxOutputTokens: 256, TimeoutSeconds: 5, DailyRequests: 1000}}, vault, policy, "seed_provider")
	require(t, err)
	queue, err := jobs.NewAnalysis(f.Runtime, vault, policy)
	require(t, err)
	evidence, err := rulegen.Seal(rulegen.Evidence{Packets: []replay.PacketSnippet{}})
	require(t, err)
	input := rulegen.Request{Description: "验证规则生成事务边界", Source: "natural_language", ProviderID: "provider_owned", ProviderRevision: 1, CandidateCount: 1, AllowContext: true}
	snapshot := func() string {
		parts := []string{}
		require(t, f.Owner.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
			for _, table := range []string{"rule_generation_jobs", "rule_sid_registry", "rule_sid_state", "rule_packages", "operation_audits"} {
				var raw []byte
				if err := tx.QueryRow(ctx, `SELECT COALESCE(jsonb_agg(to_jsonb(v) ORDER BY to_jsonb(v)::text),'[]'::jsonb) FROM (SELECT * FROM `+pgx.Identifier{table}.Sanitize()+` WHERE tenant_id=$1) v`, tenant).Scan(&raw); err != nil {
					return err
				}
				parts = append(parts, string(raw))
			}
			var raw []byte
			if err := tx.QueryRow(ctx, `SELECT COALESCE(jsonb_agg(to_jsonb(v) ORDER BY id),'[]'::jsonb) FROM (SELECT * FROM starbeacon_jobs.river_job WHERE args->>'tenant_id'=$1) v`, tenant).Scan(&raw); err != nil {
				return err
			}
			parts = append(parts, string(raw))
			return nil
		}))
		raw, _ := json.Marshal(parts)
		return store.Hash(string(raw))
	}
	type operation struct {
		name     string
		prefixes []string
		run      func(*store.Postgres, *river.Client[pgx.Tx]) error
	}
	check := func(ops []operation) {
		for _, op := range ops {
			for i, prefix := range op.prefixes {
				t.Run(fmt.Sprintf("%s/%02d", op.name, i), func(t *testing.T) {
					before := snapshot()
					db, tracer := disconnectedStore(t, ctx, f.RuntimeDSN, prefix)
					q, err := jobs.NewAnalysis(db, vault, policy)
					require(t, err)
					if err := op.run(db, q); err == nil || !tracer.fired.Load() {
						t.Fatalf("目标断连未发生或被当作成功：%v", err)
					}
					if before != snapshot() {
						t.Fatal("失败事务留下 SID、作业、候选、队列或审计变更")
					}
				})
			}
		}
	}
	check([]operation{{"create", []string{"SELECT pg_advisory_xact_lock", "UPDATE rule_generation_jobs SET state='uncertain'", "UPDATE rule_generation_jobs SET state='failed'", "SELECT request_hash FROM rule_generation_jobs", "SELECT public.lock_report_plan_owner", "SELECT revision FROM model_providers", "SELECT ciphertext", "SELECT count(*) FILTER", "SELECT count(*) FROM rule_generation_jobs", "INSERT INTO rule_sid_state", "SELECT next_sid FROM rule_sid_state", "INSERT INTO rule_sid_registry", "UPDATE rule_sid_state", "INSERT INTO rule_generation_jobs", "UPDATE rule_generation_jobs SET river_job_id", "INSERT INTO operation_audits"}, func(db *store.Postgres, q *river.Client[pgx.Tx]) error {
		_, e := db.CreateRuleGeneration(ctx, u, input, "create_fault", evidence, q, vault, "create_fault")
		return e
	}}})
	job, err := f.Runtime.CreateRuleGeneration(ctx, u, input, "seed_generation", evidence, queue, vault, "seed_generation")
	require(t, err)
	var riverID int64
	require(t, f.Owner.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT river_job_id FROM rule_generation_jobs WHERE tenant_id=$1 AND id=$2`, tenant, job.ID).Scan(&riverID)
	}))
	args := rulegen.Args{TenantID: tenant, JobID: job.ID}
	check([]operation{
		{"lookup", []string{"SELECT request_hash FROM rule_generation_jobs", "SELECT jsonb_build_object"}, func(db *store.Postgres, _ *river.Client[pgx.Tx]) error {
			_, e := db.ExistingRuleGeneration(ctx, u, "seed_generation", rulegen.InputHash(input))
			return e
		}},
		{"detail", []string{"SELECT jsonb_build_object"}, func(db *store.Postgres, _ *river.Client[pgx.Tx]) error {
			_, e := db.RuleGeneration(ctx, u, job.ID)
			return e
		}},
		{"history", []string{"SELECT id,left"}, func(db *store.Postgres, _ *river.Client[pgx.Tx]) error {
			_, e := db.RuleGenerations(ctx, u, "")
			return e
		}},
		{"cursor", []string{"SELECT created_at FROM rule_generation_jobs"}, func(db *store.Postgres, _ *river.Client[pgx.Tx]) error {
			_, e := db.RuleGenerations(ctx, u, job.ID)
			return e
		}},
		{"start", []string{"SELECT jsonb_build_object", "SELECT public.lock_report_plan_owner", "SELECT revision FROM model_providers", "SELECT ciphertext", "UPDATE rule_generation_jobs SET state='running'"}, func(db *store.Postgres, _ *river.Client[pgx.Tx]) error {
			_, e := db.StartRuleGeneration(ctx, args, riverID, vault)
			return e
		}},
		{"cancel", []string{"SELECT state,river_job_id FROM rule_generation_jobs", "UPDATE rule_generation_jobs SET state='cancelled'", "INSERT INTO operation_audits"}, func(db *store.Postgres, q *river.Client[pgx.Tx]) error {
			_, e := db.CancelRuleGeneration(ctx, u, job.ID, q, "cancel_fault")
			return e
		}},
	})
	lease, err := f.Runtime.StartRuleGeneration(ctx, args, riverID, vault)
	require(t, err)
	if !lease.Execute {
		t.Fatal("有效作业未获得执行租约")
	}
	check([]operation{{"finish", []string{"UPDATE rule_generation_jobs SET state=$4"}, func(db *store.Postgres, _ *river.Client[pgx.Tx]) error {
		return db.FinishRuleGeneration(ctx, tenant, lease, llm.Result{State: "failed", Code: "invalid_generation_output"}, nil)
	}}})
	require(t, f.Runtime.FinishRuleGeneration(ctx, tenant, lease, llm.Result{State: "failed", Code: "invalid_generation_output"}, nil))
	t.Log("模型调用未启用；本用例只验证真实 PostgreSQL 断连和持久事务完整性。")
}
