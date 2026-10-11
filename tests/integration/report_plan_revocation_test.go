//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/admin"
	"github.com/kkx600/StarBeacon/internal/analytics"
	"github.com/kkx600/StarBeacon/internal/assistant"
	"github.com/kkx600/StarBeacon/internal/jobs"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/outbound"
	"github.com/kkx600/StarBeacon/internal/store"
)

// 只移动独立测试数据库中的队列槽位；权限变化与队列执行使用真实 PostgreSQL/River。
func TestReportPlanOwnerRevocationStopsInitialAndRecoveredRuns(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 70*time.Second)
	defer cancel()
	f := newIsolatedDatabase(t, ctx)
	var snapshots atomic.Int32
	queue, err := jobs.NewAnalysis(f.Runtime, nil, outbound.Policy{}, func(context.Context, model.Principal, analytics.Window) (analytics.Snapshot, error) {
		snapshots.Add(1)
		return analytics.Snapshot{}, assistant.ErrInput
	})
	require(t, err)
	type scenario struct {
		name, revoke string
		resume       bool
	}
	cases := []scenario{{"account", `UPDATE public.users SET active=false WHERE tenant_id=$1`, false}, {"role", `UPDATE public.users SET role='viewer' WHERE tenant_id=$1`, false}, {"tenant", `UPDATE public.tenants SET active=false WHERE id=$1`, false}, {"recovered", `UPDATE public.users SET active=false WHERE tenant_id=$1`, true}}
	principals := []model.Principal{}
	for _, test := range cases {
		tenant := store.RandomID("it_plan_revoke_")
		require(t, admin.Bootstrap(ctx, f.Owner, tenant, "报告资格验收", tenant, store.Token(), "admin"))
		user, _, err := f.Runtime.Password(ctx, tenant)
		require(t, err)
		principals = append(principals, user)
		spec := assistant.PlanSpec{Name: "执行资格计划", Kind: "daily", Timezone: "Asia/Shanghai", At: "00:00", Enabled: true}
		plan, err := f.Runtime.SaveReportPlan(ctx, user, assistant.PlanChange{ID: "plan_revocation", Spec: spec}, queue, nil, "revocation_seed")
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
		if test.resume {
			lease, err := f.Runtime.StartReportPlan(ctx, args, riverID, queue)
			require(t, err)
			if !lease.Execute {
				t.Fatal("未进入准备阶段")
			}
		}
		require(t, f.Owner.TenantTx(ctx, tenant, func(tx pgx.Tx) error { _, err := tx.Exec(ctx, test.revoke, tenant); return err }))
		if _, err := f.Runtime.StartReportPlan(ctx, args, riverID+999, queue); err == nil {
			t.Fatal("错误作业身份可以停止计划", test.name)
		}
	}
	require(t, queue.Start(ctx))
	defer func() {
		stop, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		require(t, queue.Stop(stop))
	}()
	for {
		var terminal int
		require(t, f.Owner.Pool.QueryRow(ctx, `SELECT count(*) FROM starbeacon_jobs.river_job WHERE kind='starbeacon.report_plan' AND args->>'plan_id'='plan_revocation' AND state='completed'`).Scan(&terminal))
		if terminal == len(cases) {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("撤销资格作业未完成")
		case <-time.After(25 * time.Millisecond):
		}
	}
	if snapshots.Load() != 0 {
		t.Fatal("无资格计划仍读取了统计内容", snapshots.Load())
	}
	for i, user := range principals {
		t.Run(cases[i].name, func(t *testing.T) {
			plans, err := f.Runtime.ReportPlans(ctx, user)
			require(t, err)
			if len(plans) != 1 || plans[0].Revision != 2 || plans[0].Spec.Enabled || plans[0].NextAt != nil {
				t.Fatal("权限撤销没有持久停止计划", plans)
			}
			runs, err := f.Runtime.ReportPlanRuns(ctx, user, plans[0].ID, "")
			require(t, err)
			if len(runs.Items) != 1 || runs.Items[0].State != "failed" || runs.Items[0].Code != "plan_qualification_changed" || runs.Items[0].AnalysisID != "" || runs.Items[0].FinishedAt == nil || runs.Items[0].PlanRevision != 1 {
				t.Fatal("资格变化缺少完整失败记录", runs)
			}
			var outstanding, generated, audit int
			require(t, f.Owner.TenantTx(ctx, user.TenantID, func(tx pgx.Tx) error {
				return tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM starbeacon_jobs.river_job WHERE args->>'tenant_id'=$1 AND state IN ('available','pending','retryable','running','scheduled')),(SELECT count(*) FROM analysis_jobs WHERE tenant_id=$1),(SELECT count(*) FROM operation_audits WHERE tenant_id=$1 AND action='reports.plan.suspend')`, user.TenantID).Scan(&outstanding, &generated, &audit)
			}))
			if outstanding != 0 || generated != 0 || audit != 1 {
				t.Fatal("仍有未来任务、模型分析或缺少停止审计", outstanding, generated, audit)
			}
			require(t, f.Owner.TenantTx(ctx, user.TenantID, func(tx pgx.Tx) error {
				if _, err := tx.Exec(ctx, `UPDATE public.users SET active=true,role='admin' WHERE tenant_id=$1`, user.TenantID); err != nil {
					return err
				}
				_, err := tx.Exec(ctx, `UPDATE public.tenants SET active=true WHERE id=$1`, user.TenantID)
				return err
			}))
			restored, err := f.Runtime.ReportPlans(ctx, user)
			require(t, err)
			if restored[0].Spec.Enabled || restored[0].Revision != 2 || restored[0].NextAt != nil {
				t.Fatal("恢复账号重新激活了旧持续授权")
			}
		})
	}
}
