//go:build integration

package integration

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/rulesync"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/transport"
)

// 复用真实引擎及 mTLS 设备：四个阶段各走平台事务、签名投递、设备执行和回执。
func exerciseNativeRuleSync(t *testing.T, ctx context.Context, f *isolatedDatabase, h *liveHTTP, u model.Principal, id transport.SensorIdentity, signer ed25519.PrivateKey, samples [2]string, target store.RulePackage, health func(string), execute func(string) control.Receipt) {
	t.Helper()
	c := rulesync.Change{ID: "sync_native", Spec: rulesync.Spec{Name: "办公探针规则同步", Enabled: true, SensorID: id.SensorID, RegistrationID: id.RegistrationID, PackageID: target.ID, PackageRevision: target.Revision, PositiveSampleID: samples[0], NegativeSampleID: samples[1], IntervalSeconds: 30}}
	var plan rulesync.Plan
	h.request("POST", "/rule-sync-plans", "sync_save", c, &plan, 200)
	if plan.Revision != 1 || plan.Spec != c.Spec {
		t.Fatal("授权计划回执未绑定原提交")
	}
	h.request("POST", "/rule-sync-plans", "sync_save_retry", c, &plan, 200)
	if plan.Revision != 1 {
		t.Fatal("精确重试重复创建计划")
	}
	conflict := c
	conflict.Spec.Name = "其他名称"
	h.request("POST", "/rule-sync-plans", "sync_conflict", conflict, nil, 409)
	page := func() rulesync.Plan {
		t.Helper()
		var out store.RuleSyncPage
		h.request("GET", "/rule-sync-plans", "", nil, &out, 200)
		if len(out.Items) != 1 || out.Items[0].ID != c.ID {
			t.Fatal("规则同步目录不完整")
		}
		return out.Items[0]
	}
	pulse := func() {
		t.Helper()
		_, err := f.Owner.Pool.Exec(ctx, `UPDATE rule_sync_plans SET next_at=now()-interval '1 second' WHERE tenant_id=$1 AND id=$2`, u.TenantID, c.ID)
		require(t, err)
		_, err = f.Runtime.SweepRuleSync(ctx, u.TenantID, signer)
		require(t, err)
	}
	for stage := 0; stage < 4; stage++ {
		pulse()
		plan = page()
		if plan.Run == nil || plan.Run.Stage != stage || plan.Run.State != rulesync.State(stage) || plan.Run.Tasks[stage] == "" {
			t.Fatal("阶段未准确持久化", stage, plan.Run)
		}
		first := plan.Run.Tasks[stage]
		// 两个调度器重查同一阶段，不产生重复签名任务。
		pulse()
		again := page()
		if again.Run.Tasks[stage] != first {
			t.Fatal("调度重试重复下发")
		}
		if stage == 0 {
			other := c
			other.ExpectedRevision = 1
			other.Spec.Name = "在途编辑"
			h.request("POST", "/rule-sync-plans", "sync_busy", other, nil, 409)
		}
		r := execute(first)
		if stage == 3 && !rulesync.Applied(r.Result, target.SHA256) {
			t.Fatal("同步任务没有实际规则回读")
		}
	}
	health(target.SHA256)
	pulse()
	plan = page()
	if plan.Run.State != "succeeded" || plan.Run.Code != "applied" || plan.ProcessedRevision != 1 {
		t.Fatal("没有按实际回执完成", plan)
	}
	if plan.Run.Spec != c.Spec || plan.Run.CreatedBy != u.ID || time.Until(plan.Run.ExpiresAt) < 179*24*time.Hour {
		t.Fatal("运行缺少完整批准快照或默认留存")
	}
	require(t, f.Runtime.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM sensor_tasks WHERE tenant_id=$1 AND id=$2`, u.TenantID, plan.Run.Tasks[0])
		if err == nil && tag.RowsAffected() != 0 {
			t.Fatal("仍受运行引用的任务被清理")
		}
		return err
	}))
	pulse()
	if page().Run.ID != plan.Run.ID {
		t.Fatal("终态计划被再次执行")
	}
	if _, err := f.Runtime.SweepRuleSync(ctx, u.TenantID, nil); !errors.Is(err, rulesync.ErrInput) {
		t.Fatal("缺少签名未拒绝")
	}
	if _, err := f.Runtime.RuleSyncPlans(ctx, u, "bad/id"); !errors.Is(err, rulesync.ErrInput) {
		t.Fatal("非法游标通过")
	}
	for _, cursor := range []string{"?bad=1", "?cursor=a&cursor=b"} {
		h.request("GET", "/rule-sync-plans"+cursor, "", nil, nil, 400)
	}
	c.ExpectedRevision = 1
	c.Spec.Enabled = false
	h.request("POST", "/rule-sync-plans", "sync_disable", c, &plan, 200)
	if plan.Revision != 2 || plan.Spec.Enabled {
		t.Fatal("停用没有生效")
	}
	if _, err := f.Runtime.SaveRuleSyncPlan(ctx, model.Principal{ID: u.ID, TenantID: u.TenantID, Role: "viewer"}, c, "viewer"); err == nil {
		t.Fatal("只读角色修改规则同步")
	}
	// 重新启用生成独立授权修订；停用在途计划不猜测已投递任务取消。
	c.ExpectedRevision = 2
	c.Spec.Enabled = true
	h.request("POST", "/rule-sync-plans", "sync_reenable", c, &plan, 200)
	pulse()
	running := page()
	first := running.Run.Tasks[0]
	c.ExpectedRevision = 3
	c.Spec.Enabled = false
	h.request("POST", "/rule-sync-plans", "sync_pause_running", c, &plan, 200)
	pulse()
	if page().Run.State != "validating" {
		t.Fatal("停用错误地宣称已签名任务终止")
	}
	_ = execute(first)
	pulse()
	if page().Run.State != "paused" || page().Run.Code != "plan_disabled" {
		t.Fatal("停用后继续创建后续步骤")
	}
	// 注册代次不匹配不下发；当前身份不会被计划自行改写。
	c.ExpectedRevision = 4
	c.Spec.Enabled = true
	c.Spec.RegistrationID = "registration_foreign"
	h.request("POST", "/rule-sync-plans", "sync_wrong_identity", c, nil, 409)
	c.Spec.RegistrationID = id.RegistrationID
	c.Spec.NegativeSampleID = c.Spec.PositiveSampleID
	h.request("POST", "/rule-sync-plans", "sync_same_sample", c, nil, 400)
	// 同一租户只有批准者可改授权；运行记录读取不受其它租户作用域影响。
	if err := f.Runtime.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		var n int
		err := tx.QueryRow(ctx, `SELECT count(*) FROM rule_sync_runs WHERE tenant_id<>$1`, u.TenantID).Scan(&n)
		if err == nil && n != 0 {
			t.Fatal("跨租户运行可见")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}
