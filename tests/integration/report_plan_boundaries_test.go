//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/kkx600/StarBeacon/internal/admin"
	"github.com/kkx600/StarBeacon/internal/analytics"
	"github.com/kkx600/StarBeacon/internal/assistant"
	"github.com/kkx600/StarBeacon/internal/jobs"
	"github.com/kkx600/StarBeacon/internal/outbound"
	"github.com/kkx600/StarBeacon/internal/store"
)

func TestReportPlanLeaseQualificationAtomicSubmissionAndQuotas(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f := newIsolatedDatabase(t, ctx)
	tenant := store.RandomID("it_plan_guards_")
	require(t, admin.Bootstrap(ctx, f.Owner, tenant, "计划事务验收", tenant, store.Token(), "admin"))
	u, _, err := f.Runtime.Password(ctx, tenant)
	require(t, err)
	var writeIdentity, publicExecute bool
	require(t, f.Runtime.Pool.QueryRow(ctx, `SELECT has_table_privilege(current_user,'public.users','UPDATE') OR has_table_privilege(current_user,'public.tenants','UPDATE')`).Scan(&writeIdentity))
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_proc p CROSS JOIN LATERAL aclexplode(p.proacl) a WHERE p.oid='public.lock_report_plan_owner(text)'::regprocedure AND a.grantee=0 AND a.privilege_type='EXECUTE')`).Scan(&publicExecute))
	if writeIdentity || publicExecute {
		t.Fatal("资格核验扩大了身份写权限或开放给 PUBLIC")
	}
	// 临时表不能遮蔽受限函数的身份来源；没有租户作用域或跨租户调用不得返回账号。
	require(t, f.Runtime.TenantTx(ctx, "it_other_plan_scope", func(tx pgx.Tx) error {
		var locked string
		if err := tx.QueryRow(ctx, `SELECT public.lock_report_plan_owner($1)`, u.ID).Scan(&locked); !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("跨租户取得管理员资格：%w", err)
		}
		return nil
	}))
	require(t, f.Runtime.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `CREATE TEMP TABLE users(id text,tenant_id text,active boolean,role text); CREATE TEMP TABLE tenants(id text,active boolean)`); err != nil {
			return err
		}
		var locked string
		if err := tx.QueryRow(ctx, `SELECT public.lock_report_plan_owner($1)`, u.ID).Scan(&locked); err != nil || locked != u.ID {
			return fmt.Errorf("管理员资格来源被临时表遮蔽：%w", err)
		}
		for _, query := range []string{`UPDATE public.users SET role='viewer' WHERE tenant_id=$1`, `UPDATE public.tenants SET active=false WHERE id=$1`} {
			blocked := f.Owner.TenantTx(ctx, tenant, func(other pgx.Tx) error {
				if _, err := other.Exec(ctx, `SET LOCAL lock_timeout='100ms'`); err != nil {
					return err
				}
				_, err := other.Exec(ctx, query, tenant)
				return err
			})
			var pgError *pgconn.PgError
			if !errors.As(blocked, &pgError) || pgError.Code != "55P03" {
				return fmt.Errorf("提交事务未锁定管理员或租户资格：%w", blocked)
			}
		}
		_, err := tx.Exec(ctx, `DROP TABLE pg_temp.users,pg_temp.tenants`)
		return err
	}))
	queue, err := jobs.NewAnalysis(f.Runtime, nil, outbound.Policy{})
	require(t, err)
	spec := assistant.PlanSpec{Name: "事务统计计划", Kind: "daily", Timezone: "Asia/Shanghai", At: "00:00", Enabled: true}
	change := assistant.PlanChange{ID: "plan_guard", Spec: spec}
	plan, err := f.Runtime.SaveReportPlan(ctx, u, change, queue, nil, "plan_seed")
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
		_, err := tx.Exec(ctx, `UPDATE starbeacon_jobs.river_job SET args=$2,scheduled_at=now()-interval '1 second' WHERE id=$1`, riverID, raw)
		return err
	}))
	if _, err := f.Runtime.StartReportPlan(ctx, args, riverID+1, queue); !errors.Is(err, store.ErrConflict) {
		t.Fatal("错误队列身份取得资格", err)
	}
	lease, err := f.Runtime.StartReportPlan(ctx, args, riverID, queue)
	require(t, err)
	retried, err := f.Runtime.StartReportPlan(ctx, args, riverID, queue)
	require(t, err)
	if !lease.Execute || lease != retried {
		t.Fatal("准备恢复没有复用同一周期", lease, retried)
	}
	require(t, f.Runtime.CheckReportPlanLease(ctx, lease))
	var jobsCount, runsCount int
	require(t, f.Owner.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM starbeacon_jobs.river_job WHERE args->>'tenant_id'=$1 AND args->>'plan_id'=$2`, tenant, plan.ID).Scan(&jobsCount); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT count(*) FROM report_plan_runs WHERE tenant_id=$1 AND plan_id=$2`, tenant, plan.ID).Scan(&runsCount)
	}))
	if jobsCount != 2 || runsCount != 1 {
		t.Fatal("统计准备重试重复推进日历", jobsCount, runsCount)
	}
	distribution := analytics.Distribution{Buckets: []analytics.Bucket{}, Other: "0", ErrorUpperBound: "0"}
	snapshot := analytics.Snapshot{Window: lease.Request.Window, ObservedAt: time.Now().UTC(), Events: analytics.Events{Total: "0", Interval: "hour", Trend: []analytics.Bucket{}, Severity: distribution, Protocols: distribution, Rules: distribution, Sensors: distribution}, Inventory: analytics.Inventory{Assets: "0", Groups: "0", Networks: "0", Sensors: "0", Online: "0", Offline: "0", Disabled: "0"}, Limitations: []string{"仅用于计划事务校验，不代表真实检测效果"}}
	evidence, err := assistant.Freeze(lease.Request.Window, []analytics.Snapshot{snapshot})
	require(t, err)
	if _, err := f.Runtime.CreateScheduledAnalysis(ctx, lease, assistant.Evidence{}, "", queue, nil); !errors.Is(err, assistant.ErrInput) {
		t.Fatal("没有冻结证据也提交统计报告", err)
	}
	for _, mutate := range []func(*assistant.PlanLease){func(l *assistant.PlanLease) { l.OwnerID = "other_owner" }, func(l *assistant.PlanLease) { l.RunID = "other_run" }, func(l *assistant.PlanLease) { l.Args.Revision++ }, func(l *assistant.PlanLease) { l.Request.Period = "2026-01-01" }, func(l *assistant.PlanLease) { l.Execute = false }} {
		invalid := lease
		mutate(&invalid)
		if _, err := f.Runtime.CreateScheduledAnalysis(ctx, invalid, evidence, "", queue, nil); err == nil {
			t.Fatal("被修改的计划租约取得提交资格")
		}
	}
	// 结果关联写入失败必须同时撤销统计报告与审计，随后可安全重试。
	fault, tracer := disconnectedStore(t, ctx, f.RuntimeDSN, "UPDATE report_plan_runs SET state='submitted'")
	if _, err := fault.CreateScheduledAnalysis(ctx, lease, evidence, "", queue, nil); err == nil || !tracer.fired.Load() {
		t.Fatal("计划结果关联故障被当作成功", err)
	}
	var analyses int
	require(t, f.Owner.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM analysis_jobs WHERE tenant_id=$1`, tenant).Scan(&analyses)
	}))
	if analyses != 0 {
		t.Fatal("失败关联留下孤立报告")
	}
	require(t, f.Owner.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE users SET role='viewer' WHERE tenant_id=$1 AND id=$2`, tenant, u.ID)
		return err
	}))
	if _, err := f.Runtime.CreateScheduledAnalysis(ctx, lease, evidence, "", queue, nil); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("所有者权限撤销后仍提交报告", err)
	}
	if err := f.Runtime.CheckReportPlanLease(ctx, lease); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("统计准备未检查已经撤销的执行资格", err)
	}
	require(t, f.Owner.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE users SET role='admin' WHERE tenant_id=$1 AND id=$2`, tenant, u.ID)
		return err
	}))
	job, err := f.Runtime.CreateScheduledAnalysis(ctx, lease, evidence, "", queue, nil)
	require(t, err)
	if job.State != "succeeded" || job.Result.Code != "statistics_only" {
		t.Fatal("统计计划提交状态错误", job.State, job.Result)
	}
	if _, err := f.Runtime.CreateScheduledAnalysis(ctx, lease, evidence, "", queue, nil); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("已经提交的运行再次生成报告", err)
	}
	require(t, f.Runtime.FailReportPlanRun(ctx, lease, "preparation_unavailable"))
	runs, err := f.Runtime.ReportPlanRuns(ctx, u, plan.ID, "")
	require(t, err)
	if len(runs.Items) != 1 || runs.Items[0].State != "submitted" || runs.Items[0].AnalysisID != job.ID {
		t.Fatal("失败回写覆盖已经提交的报告", runs)
	}
	change.ExpectedRevision, change.Spec.Enabled = 1, false
	plan, err = f.Runtime.SaveReportPlan(ctx, u, change, queue, nil, "disable_plan")
	require(t, err)
	if plan.NextAt != nil || plan.Revision != 2 {
		t.Fatal("停用修订没有撤销未来槽位", plan)
	}
	var scheduledCount int
	require(t, f.Owner.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM starbeacon_jobs.river_job WHERE args->>'tenant_id'=$1 AND args->>'plan_id'=$2 AND state='scheduled'`, tenant, plan.ID).Scan(&scheduledCount)
	}))
	if scheduledCount != 1 {
		// 原已取走的测试行没有启动执行器，只有后继槽位应由停用事务取消。
		t.Fatal("停用没有原子取消后继槽位", scheduledCount)
	}
	for i := 1; i < 32; i++ {
		_, err := f.Runtime.SaveReportPlan(ctx, u, assistant.PlanChange{ID: fmt.Sprintf("plan_limit_%02d", i), Spec: change.Spec}, queue, nil, "quota_seed")
		require(t, err)
	}
	if _, err := f.Runtime.SaveReportPlan(ctx, u, assistant.PlanChange{ID: "plan_limit_overflow", Spec: change.Spec}, queue, nil, "quota"); !errors.Is(err, store.ErrPlanQuota) {
		t.Fatal("计划数量超过租户硬上限", err)
	}
	if _, err := f.Runtime.ReportPlanRuns(ctx, u, "bad/id", ""); !errors.Is(err, assistant.ErrInput) {
		t.Fatal("无效计划标识未拒绝", err)
	}
	if _, err := f.Runtime.StartReportPlan(ctx, assistant.PlanArgs{}, 0, nil); !errors.Is(err, assistant.ErrInput) {
		t.Fatal("无效调度参数未拒绝", err)
	}
	if err := f.Runtime.FailReportPlanRun(ctx, lease, "untrusted_message"); !errors.Is(err, assistant.ErrInput) {
		t.Fatal("任意失败正文写入运行记录", err)
	}
	// 分类清理先回收过期运行引用，再允许报告删除；存续计划配置继续保留。
	require(t, f.Owner.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE starbeacon_jobs.river_job SET state='completed',finalized_at=now() WHERE id=$1`, riverID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE report_plan_runs SET expires_at=now()-interval '1 day' WHERE tenant_id=$1`, tenant); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE analysis_jobs SET expires_at=now()-interval '1 day' WHERE tenant_id=$1`, tenant)
		return err
	}))
	_, err = f.Runtime.SweepHistory(ctx)
	require(t, err)
	require(t, f.Owner.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM report_plan_runs WHERE tenant_id=$1)+(SELECT count(*) FROM analysis_jobs WHERE tenant_id=$1)`, tenant).Scan(&analyses)
	}))
	if analyses != 0 {
		t.Fatal("到期报告引用阻塞分类清理")
	}
}
