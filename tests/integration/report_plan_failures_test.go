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
	"github.com/kkx600/StarBeacon/internal/assistant"
	"github.com/kkx600/StarBeacon/internal/jobs"
	"github.com/kkx600/StarBeacon/internal/llm"
	"github.com/kkx600/StarBeacon/internal/outbound"
	"github.com/kkx600/StarBeacon/internal/secrets"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/riverqueue/river"
)

func TestReportPlanDatabaseInterruptionPreservesScheduleAndHistory(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f := newIsolatedDatabase(t, ctx)
	tenant := store.RandomID("it_plan_failure_")
	require(t, admin.Bootstrap(ctx, f.Owner, tenant, "计划故障验收", tenant, store.Token(), "admin"))
	u, _, err := f.Runtime.Password(ctx, tenant)
	require(t, err)
	vault, err := secrets.New(store.Token())
	require(t, err)
	policy := outbound.Policy{}
	provider := llm.Config{Name: "计划模型", Kind: "openai_responses", BaseURL: "https://models.example.com/v1", Model: "owned", Enabled: true, APIKey: "owned-test-key", MaxOutputTokens: 256, TimeoutSeconds: 5, DailyRequests: 1000}
	_, err = f.Runtime.SaveModelProvider(ctx, u, store.ModelChange{ID: "provider_owned", ReplaceKey: true, Config: provider}, vault, policy, "provider_seed")
	require(t, err)
	queue, err := jobs.NewAnalysis(f.Runtime, vault, policy)
	require(t, err)
	spec := assistant.PlanSpec{Name: "故障边界统计", Kind: "daily", Timezone: "UTC", At: "00:00", Enabled: true}
	plan, err := f.Runtime.SaveReportPlan(ctx, u, assistant.PlanChange{ID: "plan_owned", Spec: spec}, queue, vault, "plan_seed")
	require(t, err)
	due, err := spec.Latest(time.Now())
	require(t, err)
	args := assistant.PlanArgs{TenantID: tenant, PlanID: plan.ID, Revision: 1, DueAt: due}
	raw, _ := json.Marshal(args)
	var riverID int64
	require(t, f.Owner.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `UPDATE report_plans SET next_at=$3 WHERE tenant_id=$1 AND id=$2 RETURNING river_job_id`, tenant, plan.ID, due).Scan(&riverID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE starbeacon_jobs.river_job SET args=$2,scheduled_at=$3 WHERE id=$1`, riverID, raw, due)
		return err
	}))
	snapshot := func() string {
		parts := []string{}
		require(t, f.Owner.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
			for _, table := range []string{"report_plans", "report_plan_runs", "analysis_jobs", "operation_audits"} {
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
		encoded, _ := json.Marshal(parts)
		return store.Hash(string(encoded))
	}
	type operation struct {
		name     string
		prefixes []string
		run      func(*store.Postgres, *river.Client[pgx.Tx]) error
	}
	modelSpec := spec
	modelSpec.ProviderID, modelSpec.ProviderRevision, modelSpec.AllowContext = "provider_owned", 1, true
	savePrefixes := []string{"SELECT pg_advisory_xact_lock", "SELECT public.lock_report_plan_owner", "SELECT revision,created_by,spec", "SELECT count(*) FROM operation_audits", "SELECT count(*) FROM report_plans", "SELECT clock_timestamp()", "INSERT INTO report_plans", "SELECT jsonb_build_object('id',id,'revision'", "INSERT INTO operation_audits"}
	ops := []operation{
		{"create", savePrefixes, func(db *store.Postgres, q *river.Client[pgx.Tx]) error {
			_, e := db.SaveReportPlan(ctx, u, assistant.PlanChange{ID: "plan_create_failure", Spec: spec}, q, vault, "plan_failure")
			return e
		}},
		{"model_binding", []string{"SELECT EXISTS(SELECT 1 FROM model_provider_versions", "SELECT revision FROM model_providers", "SELECT ciphertext FROM model_provider_versions"}, func(db *store.Postgres, q *river.Client[pgx.Tx]) error {
			_, e := db.SaveReportPlan(ctx, u, assistant.PlanChange{ID: "plan_model_failure", Spec: modelSpec}, q, vault, "plan_model_failure")
			return e
		}},
		{"start", []string{"SELECT created_by,revision,spec", "SELECT id,state,request,deadline", "SELECT clock_timestamp()", "INSERT INTO report_plan_runs", "SELECT public.lock_report_plan_owner", "UPDATE report_plans SET next_at"}, func(db *store.Postgres, q *river.Client[pgx.Tx]) error {
			_, e := db.StartReportPlan(ctx, args, riverID, q)
			return e
		}},
		{"list", []string{"SELECT jsonb_build_object('id',id,'revision'"}, func(db *store.Postgres, _ *river.Client[pgx.Tx]) error { _, e := db.ReportPlans(ctx, u); return e }},
	}
	check := func(ops []operation) {
		for _, op := range ops {
			for i, prefix := range op.prefixes {
				t.Run(fmt.Sprintf("%s/%02d", op.name, i), func(t *testing.T) {
					before := snapshot()
					db, tracer := disconnectedStore(t, ctx, f.RuntimeDSN, prefix)
					q, err := jobs.NewAnalysis(db, vault, policy)
					require(t, err)
					if err := op.run(db, q); err == nil {
						t.Fatal("计划连接中断仍返回成功")
					}
					if !tracer.fired.Load() {
						t.Fatal("没有到达计划故障边界", prefix)
					}
					if before != snapshot() {
						t.Fatal("失败计划改变了调度槽位、运行、报告或审计")
					}
				})
			}
		}
	}
	check(ops)
	lease, err := f.Runtime.StartReportPlan(ctx, args, riverID, queue)
	require(t, err)
	if !lease.Execute {
		t.Fatal("中断恢复后未取得实际准备资格")
	}
	ops = []operation{
		{"qualification_read", []string{"SELECT revision,spec FROM report_plans", "SELECT public.lock_report_plan_owner", "SELECT request FROM report_plan_runs"}, func(db *store.Postgres, _ *river.Client[pgx.Tx]) error { return db.CheckReportPlanLease(ctx, lease) }},
		{"qualification_failure", []string{"SELECT spec,river_job_id FROM report_plans", "SELECT public.lock_report_plan_owner", "UPDATE report_plan_runs SET state='failed'"}, func(db *store.Postgres, q *river.Client[pgx.Tx]) error {
			return db.FailReportPlanRun(ctx, lease, "plan_qualification_changed", q)
		}},
		{"history", []string{"SELECT id FROM report_plans", "UPDATE report_plan_runs h", "UPDATE analysis_jobs SET state='failed'", "SELECT jsonb_build_object('id',h.id"}, func(db *store.Postgres, _ *river.Client[pgx.Tx]) error {
			_, e := db.ReportPlanRuns(ctx, u, plan.ID, "")
			return e
		}},
		{"history_cursor", []string{"SELECT created_at FROM report_plan_runs"}, func(db *store.Postgres, _ *river.Client[pgx.Tx]) error {
			_, e := db.ReportPlanRuns(ctx, u, plan.ID, lease.RunID)
			return e
		}},
	}
	check(ops)
	require(t, f.Runtime.CheckReportPlanLease(ctx, lease))
	require(t, f.Runtime.FailReportPlanRun(ctx, lease, "plan_qualification_changed", queue))
	runs, err := f.Runtime.ReportPlanRuns(ctx, u, plan.ID, "")
	require(t, err)
	if len(runs.Items) != 1 || runs.Items[0].State != "failed" || runs.Items[0].Code != "plan_qualification_changed" {
		t.Fatal("恢复后失败状态未准确持久化")
	}
	// 当前资格仍有效时，失败单次准备不会擅自关闭后继计划。
	plans, err := f.Runtime.ReportPlans(ctx, u)
	require(t, err)
	if len(plans) != 1 || !plans[0].Spec.Enabled || plans[0].NextAt == nil {
		t.Fatal("单次失败错误停用了整个计划")
	}
}
