//go:build integration

package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/admin"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/enginehealth"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/replay"
	"github.com/kkx600/StarBeacon/internal/rulerollout"
	"github.com/kkx600/StarBeacon/internal/rulesync"
	"github.com/kkx600/StarBeacon/internal/store"
)

type rolloutFixture struct {
	f      *isolatedDatabase
	u      model.Principal
	signer ed25519.PrivateKey
	rule   store.RulePackage
}

func newRolloutFixture(t *testing.T, ctx context.Context) *rolloutFixture {
	t.Helper()
	f := newIsolatedDatabase(t, ctx)
	tenant := store.RandomID("it_rollout_")
	require(t, admin.Bootstrap(ctx, f.Owner, tenant, "分批发布持久化", tenant, store.Token(), "admin"))
	u, _, err := f.Runtime.Password(ctx, tenant)
	require(t, err)
	_, signer, err := ed25519.GenerateKey(rand.Reader)
	require(t, err)
	rule, err := f.Runtime.SaveRulePackage(ctx, u, "rules_rollout", "发布规则", `alert tcp any any -> any any (msg:"rollout"; content:"validation"; sid:1008125; rev:1;)`, 0, "save")
	require(t, err)
	for i := 0; i < 2; i++ {
		id := fmt.Sprintf("rollout_sample_%d", i)
		require(t, f.Runtime.ReserveSample(ctx, u, replay.Sample{ID: id, Name: "协议状态样本", Size: 24}, 100<<20))
		require(t, f.Runtime.CompleteSample(ctx, u, id, control.Digest([]byte(id)), "pcap", "sample"))
	}
	return &rolloutFixture{f, u, signer, rule}
}
func (f *rolloutFixture) create(t *testing.T, ctx context.Context, prefix string, count int) rulerollout.Create {
	t.Helper()
	c := rulerollout.Create{ID: "rollout_" + prefix, Spec: rulerollout.Spec{Name: "办公探针规则分批发布", CanaryCount: 1, BatchSize: 2, ObservationSeconds: 30, TimeoutSeconds: 600}}
	for i := 0; i < count; i++ {
		name := fmt.Sprintf("%s_%d", prefix, i)
		s := rulesync.Spec{Name: "探针同步 " + name, SensorID: "sensor_" + name, RegistrationID: "registration_" + name, PackageID: f.rule.ID, PackageRevision: f.rule.Revision, PositiveSampleID: "rollout_sample_0", NegativeSampleID: "rollout_sample_1", IntervalSeconds: 30}
		h, _ := json.Marshal(model.HostHealth{ObservedAt: time.Now().UTC(), TaskCapabilities: []string{"rules.validate", "rules.replay", "rules.apply"}, CommandSignerSHA256: control.Digest(f.signer.Public().(ed25519.PublicKey)), RegisteredRulesAvailable: true, RegisteredRulesSHA256: control.Digest([]byte("previous"))})
		_, err := f.f.Owner.Pool.Exec(ctx, `INSERT INTO sensors(tenant_id,id,name,registration_id,last_seen,health) VALUES($1,$2,$2,$3,now(),$4)`, f.u.TenantID, s.SensorID, s.RegistrationID, h)
		require(t, err)
		p, err := f.f.Runtime.SaveRuleSyncPlan(ctx, f.u, rulesync.Change{ID: "sync_" + name, Spec: s}, "plan")
		require(t, err)
		c.Spec.Plans = append(c.Spec.Plans, rulerollout.Selection{PlanID: p.ID, Revision: p.Revision})
	}
	return c
}
func (f *rolloutFixture) pulse(t *testing.T, ctx context.Context, id string) rulerollout.Rollout {
	t.Helper()
	_, err := f.f.Owner.Pool.Exec(ctx, `UPDATE rule_rollouts SET next_at=now()-interval '1 second' WHERE tenant_id=$1 AND id=$2`, f.u.TenantID, id)
	require(t, err)
	_, err = f.f.Runtime.SweepRuleRollouts(ctx, f.u.TenantID)
	require(t, err)
	r, err := f.f.Runtime.RuleRollout(ctx, f.u, id)
	require(t, err)
	return r
}

// 此帮助函数仅建立 PG 状态夹具，验证批次门禁；实际签名与原生装载由独立双探针用例执行。
func (f *rolloutFixture) complete(t *testing.T, ctx context.Context, r rulerollout.Rollout, index int) {
	t.Helper()
	target := r.Targets[index]
	s := target.Spec
	s.Enabled = true
	raw, _ := json.Marshal(s)
	_, err := f.f.Owner.Pool.Exec(ctx, `INSERT INTO rule_sync_runs(tenant_id,id,plan_id,plan_revision,spec,created_by,state,stage,expected_sha256,finished_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,'succeeded',3,$7,clock_timestamp(),now()+interval '180 days')`, f.u.TenantID, store.RandomID("sync_run_"), target.PlanID, target.ExecutionRevision, raw, f.u.ID, f.rule.SHA256)
	require(t, err)
	_, err = f.f.Owner.Pool.Exec(ctx, `UPDATE rule_sync_plans SET processed_revision=$3 WHERE tenant_id=$1 AND id=$2`, f.u.TenantID, target.PlanID, target.ExecutionRevision)
	require(t, err)
	now := time.Now().UTC()
	observation := &enginehealth.Report{SchemaVersion: enginehealth.Schema, State: "observed", Source: "managed_process", ObservedAt: now, PID: 100, StartedAt: now.Add(-time.Hour), ConfigSHA256: control.Digest([]byte("fixture_configuration")), RulesSHA256: f.rule.SHA256, FileRuleCount: 1, RulesLoaded: 1}
	h, _ := json.Marshal(model.HostHealth{ObservedAt: now, RegisteredRulesAvailable: true, RegisteredRulesSHA256: f.rule.SHA256, EngineHealth: observation})
	_, err = f.f.Owner.Pool.Exec(ctx, `UPDATE sensors SET last_seen=clock_timestamp(),health=$3 WHERE tenant_id=$1 AND id=$2`, f.u.TenantID, target.Spec.SensorID, h)
	require(t, err)
}

func TestRuleRolloutPersistenceAuthorizationAndTransactions(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	f := newRolloutFixture(t, ctx)
	c := f.create(t, ctx, "atomic", 3)
	for _, prefix := range []string{"SELECT pg_advisory_xact_lock", "SELECT jsonb_build_object('id',r.id", "SELECT count(*),count(*) FILTER", "SELECT count(*) FROM operation_audits", "SELECT jsonb_build_object('id',p.id", "SELECT EXISTS(SELECT 1 FROM rule_rollout_targets", "SELECT registration_id FROM sensors", "SELECT sha256 FROM rule_packages", "SELECT a.sha256,b.sha256", "INSERT INTO rule_rollouts", "INSERT INTO rule_rollout_targets", "INSERT INTO operation_audits"} {
		t.Run("创建事务中断 "+prefix, func(t *testing.T) {
			broken, tracer := disconnectedStore(t, ctx, f.f.RuntimeDSN, prefix)
			before := ownedBusinessSnapshot(t, ctx, f.f.Owner, f.u.TenantID)
			_, err := broken.CreateRuleRollout(ctx, f.u, c, "fault")
			if err == nil || !tracer.fired.Load() {
				t.Fatal("未触发真实数据库故障", err)
			}
			if ownedBusinessSnapshot(t, ctx, f.f.Owner, f.u.TenantID) != before {
				t.Fatal("失败创建留下部分授权或预留")
			}
		})
	}
	r, err := f.f.Runtime.CreateRuleRollout(ctx, f.u, c, "create")
	require(t, err)
	if len(r.Targets) != 3 || r.State != "pending" || time.Until(r.ExpiresAt) < 179*24*time.Hour {
		t.Fatal("创建回执缺少快照或默认期限")
	}
	_, err = f.f.Runtime.CreateRuleRollout(ctx, f.u, c, "retry")
	require(t, err)
	bad := c
	bad.Spec.Name = "其他发布"
	if _, err = f.f.Runtime.CreateRuleRollout(ctx, f.u, bad, "different"); !errors.Is(err, store.ErrConflict) {
		t.Fatal("原标识接受不同输入", err)
	}
	bad = c
	bad.ID = "rollout_duplicate"
	if _, err = f.f.Runtime.CreateRuleRollout(ctx, f.u, bad, "reserved"); !errors.Is(err, store.ErrConflict) {
		t.Fatal("目标被重复预留", err)
	}
	viewer := f.u
	viewer.Role = "viewer"
	if _, err = f.f.Runtime.RuleRollouts(ctx, viewer, ""); err == nil {
		t.Fatal("只读角色读取发布目录")
	}
	if _, err = f.f.Runtime.CreateRuleRollout(ctx, viewer, c, "viewer"); err == nil {
		t.Fatal("只读角色创建发布")
	}
	if _, err = f.f.Runtime.RuleRollouts(ctx, f.u, "bad/id"); !errors.Is(err, rulerollout.ErrInput) {
		t.Fatal(err)
	}
	if _, err = f.f.Runtime.RuleRollout(ctx, f.u, "bad/id"); !errors.Is(err, rulerollout.ErrInput) {
		t.Fatal(err)
	}
	if _, err = f.f.Runtime.CreateRuleRollout(ctx, f.u, rulerollout.Create{}, "invalid"); !errors.Is(err, rulerollout.ErrInput) {
		t.Fatal(err)
	}
	if _, err = f.f.Runtime.StopRuleRollout(ctx, f.u, "bad/id", rulerollout.Stop{Reason: "维护"}, "stop"); !errors.Is(err, rulerollout.ErrInput) {
		t.Fatal(err)
	}
	for _, method := range []string{"list", "detail"} {
		for _, prefix := range []string{"SELECT pg_advisory_xact_lock", "SELECT jsonb_build_object('id',r.id"} {
			t.Run(method+prefix, func(t *testing.T) {
				broken, tracer := disconnectedStore(t, ctx, f.f.RuntimeDSN, prefix)
				if method == "list" {
					_, err = broken.RuleRollouts(ctx, f.u, "")
				} else {
					_, err = broken.RuleRollout(ctx, f.u, c.ID)
				}
				if err == nil || !tracer.fired.Load() {
					t.Fatal("读取故障未返回", err)
				}
			})
		}
	}
	other := f.u
	other.ID = store.RandomID("user_missing_")
	if _, err = f.f.Runtime.RuleRollout(ctx, other, c.ID); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("失效账号读取详情", err)
	}
	for _, target := range r.Targets {
		change := rulesync.Change{ID: target.PlanID, ExpectedRevision: target.AuthorizedRevision, Spec: target.Spec}
		change.Spec.Name = "被其他操作替换"
		if _, err = f.f.Runtime.SaveRuleSyncPlan(ctx, f.u, change, "reserved_plan"); !errors.Is(err, store.ErrConflict) {
			t.Fatal("预留计划可被替换", err)
		}
	}
	for _, prefix := range []string{"SELECT id FROM rule_rollouts", "SET LOCAL lock_timeout", "SELECT clock_timestamp()", "SELECT t.ordinal,t.batch,t.plan_id", "UPDATE rule_rollouts SET next_at", "UPDATE rule_sync_plans SET revision=revision+1", "UPDATE rule_rollout_targets SET execution_revision", "UPDATE rule_rollouts SET state='running'"} {
		t.Run("首批推进中断 "+prefix, func(t *testing.T) {
			broken, tracer := disconnectedStore(t, ctx, f.f.RuntimeDSN, prefix)
			before := ownedBusinessSnapshot(t, ctx, f.f.Owner, f.u.TenantID)
			_, err := broken.SweepRuleRollouts(ctx, f.u.TenantID)
			if err == nil || !tracer.fired.Load() {
				t.Fatal("调度故障未触发", err)
			}
			if ownedBusinessSnapshot(t, ctx, f.f.Owner, f.u.TenantID) != before {
				t.Fatal("失败调度留下部分目标启用")
			}
		})
	}
	r = f.pulse(t, ctx, c.ID)
	if r.State != "running" || r.Targets[0].ExecutionRevision != 2 || r.Targets[1].ExecutionRevision != 0 {
		t.Fatal("首批范围错误", r)
	}
	for _, prefix := range []string{"UPDATE rule_rollouts SET state='stopping'", "UPDATE rule_sync_plans p SET revision", "UPDATE rule_rollouts SET stopped_by", "INSERT INTO operation_audits"} {
		t.Run("停止中断 "+prefix, func(t *testing.T) {
			broken, tracer := disconnectedStore(t, ctx, f.f.RuntimeDSN, prefix)
			before := ownedBusinessSnapshot(t, ctx, f.f.Owner, f.u.TenantID)
			_, err := broken.StopRuleRollout(ctx, f.u, c.ID, rulerollout.Stop{Reason: "现场维护"}, "stop_fault")
			if err == nil || !tracer.fired.Load() {
				t.Fatal("停止故障未触发", err)
			}
			if ownedBusinessSnapshot(t, ctx, f.f.Owner, f.u.TenantID) != before {
				t.Fatal("停止失败仍改变授权")
			}
		})
	}
	stopped, err := f.f.Runtime.StopRuleRollout(ctx, f.u, c.ID, rulerollout.Stop{Reason: "现场维护"}, "stop")
	require(t, err)
	if stopped.State != "stopping" || stopped.StopReason != "现场维护" {
		t.Fatal("停止误报已终止")
	}
	_, err = f.f.Runtime.StopRuleRollout(ctx, f.u, c.ID, rulerollout.Stop{Reason: "现场维护"}, "stop_retry")
	require(t, err)
	if _, err = f.f.Runtime.StopRuleRollout(ctx, f.u, c.ID, rulerollout.Stop{Reason: "其他原因"}, "stop_other"); !errors.Is(err, store.ErrConflict) {
		t.Fatal("停止原提交被改写")
	}
	r = f.pulse(t, ctx, c.ID)
	if r.State != "stopped" || r.FinishedAt == nil {
		t.Fatal("无任务的停止未闭环", r)
	}
	for _, target := range r.Targets {
		if target.State != "stopped" {
			t.Fatal("未下发目标状态错误")
		}
	}
	page, err := f.f.Runtime.RuleRollouts(ctx, f.u, "")
	require(t, err)
	if len(page.Items) != 1 || page.Items[0].Targets != nil {
		t.Fatal("目录返回错误")
	}
	// 留存到期之前不能清除发布档案；到期后仅回收终态档案，活动计划保留。
	require(t, f.f.Runtime.TenantTx(ctx, f.u.TenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM rule_rollouts WHERE tenant_id=$1 AND id=$2`, f.u.TenantID, c.ID)
		if err == nil && tag.RowsAffected() != 0 {
			t.Fatal("未到期档案被删除")
		}
		return err
	}))
	_, err = f.f.Owner.Pool.Exec(ctx, `UPDATE rule_rollouts SET created_at=now()-interval '2 days',expires_at=now()-interval '1 day' WHERE tenant_id=$1 AND id=$2`, f.u.TenantID, c.ID)
	require(t, err)
	if _, err = f.f.Runtime.RuleRollout(ctx, f.u, c.ID); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("到期档案仍可读取", err)
	}
	require(t, f.f.Runtime.TenantTx(ctx, f.u.TenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM rule_rollouts WHERE tenant_id=$1 AND id=$2`, f.u.TenantID, c.ID)
		if err == nil && tag.RowsAffected() != 1 {
			t.Fatal("终态到期档案未回收")
		}
		return err
	}))
}

func TestRuleRolloutSchedulerRequiresEvidenceAndFreshWatermarks(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	f := newRolloutFixture(t, ctx)
	for _, scenario := range []string{"success", "offline", "digest", "identity", "owner", "deadline", "task_failed", "task_unknown", "stop_pending", "stop_signed", "plan_changed", "engine_missing", "engine_stale", "engine_before_release", "engine_busy", "engine_failed", "engine_count_changed", "engine_digest_changed"} {
		t.Run(scenario, func(t *testing.T) {
			c := f.create(t, ctx, scenario, 3)
			_, err := f.f.Runtime.CreateRuleRollout(ctx, f.u, c, "create")
			require(t, err)
			modify := func(q string, args ...any) {
				t.Helper()
				_, err := f.f.Owner.Pool.Exec(ctx, q, args...)
				require(t, err)
			}
			if scenario == "plan_changed" {
				modify(`UPDATE rule_sync_plans SET revision=revision+1 WHERE tenant_id=$1 AND id=$2`, f.u.TenantID, c.Spec.Plans[0].PlanID)
			}
			if scenario == "deadline" {
				modify(`UPDATE rule_rollouts SET deadline=now()-interval '1 second' WHERE tenant_id=$1 AND id=$2`, f.u.TenantID, c.ID)
			}
			if scenario == "owner" {
				modify(`UPDATE users SET active=false WHERE tenant_id=$1 AND id=$2`, f.u.TenantID, f.u.ID)
				_, err = f.f.Runtime.SweepRuleRollouts(ctx, f.u.TenantID)
				require(t, err)
				modify(`UPDATE users SET active=true WHERE tenant_id=$1 AND id=$2`, f.u.TenantID, f.u.ID)
			}
			r := f.pulse(t, ctx, c.ID)
			if scenario == "deadline" || scenario == "owner" || scenario == "plan_changed" {
				r = f.pulse(t, ctx, c.ID)
				if r.State != "blocked" {
					t.Fatal("资格失效仍继续", r.State, r.Code)
				}
				return
			}
			if scenario == "stop_pending" || scenario == "stop_signed" {
				if scenario == "stop_signed" {
					_, err = f.f.Runtime.SweepRuleSync(ctx, f.u.TenantID, f.signer)
					require(t, err)
				}
				_, err = f.f.Runtime.StopRuleRollout(ctx, f.u, c.ID, rulerollout.Stop{Reason: "维护"}, "stop")
				require(t, err)
				r = f.pulse(t, ctx, c.ID)
				if scenario == "stop_signed" {
					if r.State != "stopping" || r.Targets[0].Run == nil {
						t.Fatal("已签名任务被推定取消")
					}
					modify(`UPDATE sensor_tasks SET state='cancelled' WHERE tenant_id=$1 AND id=$2`, f.u.TenantID, r.Targets[0].Run.Tasks[0])
					modify(`UPDATE rule_sync_plans SET next_at=now()-interval '1 second' WHERE tenant_id=$1 AND id=$2`, f.u.TenantID, c.Spec.Plans[0].PlanID)
					_, err = f.f.Runtime.SweepRuleSync(ctx, f.u.TenantID, f.signer)
					require(t, err)
					r = f.pulse(t, ctx, c.ID)
				}
				if r.State != "stopped" {
					t.Fatal("停止未闭环", r.State)
				}
				return
			}
			f.complete(t, ctx, r, 0)
			if scenario == "task_failed" || scenario == "task_unknown" {
				state := strings.TrimPrefix(scenario, "task_")
				modify(`UPDATE rule_sync_runs SET state='blocked',code=$3 WHERE tenant_id=$1 AND plan_id=$2`, f.u.TenantID, c.Spec.Plans[0].PlanID, "task_"+state)
			}
			if scenario == "offline" {
				modify(`UPDATE sensors SET last_seen=now()-interval '5 minutes' WHERE tenant_id=$1 AND id=$2`, f.u.TenantID, r.Targets[0].Spec.SensorID)
			}
			if scenario == "digest" {
				modify(`UPDATE sensors SET health=jsonb_set(health,'{registered_rules_sha256}',to_jsonb($3::text)) WHERE tenant_id=$1 AND id=$2`, f.u.TenantID, r.Targets[0].Spec.SensorID, strings.Repeat("f", 64))
			}
			if scenario == "identity" {
				modify(`UPDATE sensors SET registration_id='changed_registration' WHERE tenant_id=$1 AND id=$2`, f.u.TenantID, r.Targets[0].Spec.SensorID)
			}
			switch scenario {
			case "engine_missing":
				modify(`UPDATE sensors SET health=health-'engine_health' WHERE tenant_id=$1 AND id=$2`, f.u.TenantID, r.Targets[0].Spec.SensorID)
			case "engine_stale":
				modify(`UPDATE sensors SET health=jsonb_set(health,'{engine_health,observed_at}',to_jsonb((clock_timestamp()-interval '5 minutes')::timestamptz)) WHERE tenant_id=$1 AND id=$2`, f.u.TenantID, r.Targets[0].Spec.SensorID)
			case "engine_before_release":
				modify(`UPDATE sensors s SET health=jsonb_set(health,'{engine_health,observed_at}',to_jsonb(r.finished_at-interval '1 millisecond')) FROM rule_sync_runs r WHERE s.tenant_id=$1 AND s.id=$2 AND r.tenant_id=s.tenant_id AND r.plan_id=$3 AND r.plan_revision=$4`, f.u.TenantID, r.Targets[0].Spec.SensorID, r.Targets[0].PlanID, r.Targets[0].ExecutionRevision)
			case "engine_busy":
				modify(`UPDATE sensors SET health=jsonb_set(health,'{engine_health,state}','"pending"') WHERE tenant_id=$1 AND id=$2`, f.u.TenantID, r.Targets[0].Spec.SensorID)
			case "engine_failed":
				modify(`UPDATE sensors SET health=jsonb_set(health,'{engine_health,state}','"unavailable"') WHERE tenant_id=$1 AND id=$2`, f.u.TenantID, r.Targets[0].Spec.SensorID)
			case "engine_count_changed":
				modify(`UPDATE sensors SET health=jsonb_set(health,'{engine_health,rules_loaded}','2') WHERE tenant_id=$1 AND id=$2`, f.u.TenantID, r.Targets[0].Spec.SensorID)
			case "engine_digest_changed":
				modify(`UPDATE sensors SET health=jsonb_set(health,'{engine_health,rules_sha256}',to_jsonb($3::text)) WHERE tenant_id=$1 AND id=$2`, f.u.TenantID, r.Targets[0].Spec.SensorID, strings.Repeat("f", 64))
			}
			r = f.pulse(t, ctx, c.ID)
			if scenario == "offline" || scenario == "engine_missing" || scenario == "engine_stale" || scenario == "engine_before_release" || scenario == "engine_busy" {
				want := "waiting_for_engine"
				if scenario == "offline" {
					want = "waiting_for_heartbeat"
				}
				if r.Code != want || r.Targets[1].ExecutionRevision != 0 || r.ObservationStartedAt != nil {
					t.Fatal("缺少心跳仍推进")
				}
				_, err = f.f.Runtime.StopRuleRollout(ctx, f.u, c.ID, rulerollout.Stop{Reason: "等待现场恢复"}, "stop")
				require(t, err)
				r = f.pulse(t, ctx, c.ID)
				if r.State != "stopped" {
					t.Fatal(r.State)
				}
				return
			}
			if scenario != "success" {
				r = f.pulse(t, ctx, c.ID)
				if r.State != "blocked" || r.Targets[1].ExecutionRevision != 0 {
					t.Fatal("失败仍扩大执行范围", r.State, r.Code)
				}
				return
			}
			if r.State != "observing" || r.ObservationStartedAt == nil {
				t.Fatal("未进入观察", r)
			}
			r = f.pulse(t, ctx, c.ID)
			if r.CurrentBatch != 0 {
				t.Fatal("实际观察时间不足仍推进")
			}
			modify(`UPDATE rule_rollouts SET observation_started_at=now()-interval '31 seconds' WHERE tenant_id=$1 AND id=$2`, f.u.TenantID, c.ID)
			r = f.pulse(t, ctx, c.ID)
			if r.CurrentBatch != 1 || r.Targets[1].ExecutionRevision != 0 {
				t.Fatal("观察完成未进入下一批待办")
			}
			r = f.pulse(t, ctx, c.ID)
			if r.Targets[1].ExecutionRevision != 2 || r.Targets[2].ExecutionRevision != 2 {
				t.Fatal("第二批范围错误")
			}
			f.complete(t, ctx, r, 1)
			f.complete(t, ctx, r, 2)
			r = f.pulse(t, ctx, c.ID)
			if r.State != "observing" {
				t.Fatal(r.State)
			}
			modify(`UPDATE rule_rollouts SET observation_started_at=now()-interval '31 seconds' WHERE tenant_id=$1 AND id=$2`, f.u.TenantID, c.ID)
			r = f.pulse(t, ctx, c.ID)
			if r.State != "succeeded" || r.Code != "observed" {
				t.Fatal("全部实际摘要核对后未完成", r.State, r.Code)
			}
			var storedCode string
			require(t, f.f.Owner.Pool.QueryRow(ctx, `SELECT code FROM rule_rollouts WHERE tenant_id=$1 AND id=$2`, f.u.TenantID, c.ID).Scan(&storedCode))
			if storedCode != "observed" {
				t.Fatal("持久终态仍保留等待原因")
			}
			modify(`UPDATE rule_rollouts SET code='observing' WHERE tenant_id=$1 AND id=$2`, f.u.TenantID, c.ID)
			historical, err := f.f.Runtime.RuleRollout(ctx, f.u, c.ID)
			require(t, err)
			if historical.Code != "observed" {
				t.Fatal("历史成功记录仍显示等待")
			}
			for _, target := range r.Targets {
				if target.State != "succeeded" || target.Run == nil {
					t.Fatal("目标档案丢失")
				}
			}
			if _, err = f.f.Runtime.StopRuleRollout(ctx, f.u, c.ID, rulerollout.Stop{Reason: "停止"}, "stop"); !errors.Is(err, store.ErrConflict) {
				t.Fatal("已完成事实被改写")
			}
		})
	}
}

// 人工时间夹具独立验证三条水位及前序批次门禁，不替代原生设备真实观察窗口。
func TestRuleRolloutEngineWatermarkAndEarlierBatchFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f := newRolloutFixture(t, ctx)
	c := f.create(t, ctx, "engine_window", 3)
	_, err := f.f.Runtime.CreateRuleRollout(ctx, f.u, c, "create")
	require(t, err)
	r := f.pulse(t, ctx, c.ID)
	f.complete(t, ctx, r, 0)
	r = f.pulse(t, ctx, c.ID)
	if r.ObservationStartedAt == nil {
		t.Fatal("没有开始原生观察窗口")
	}
	firstStart := *r.ObservationStartedAt
	sensor := r.Targets[0].Spec.SensorID
	modify := func(query string, args ...any) {
		t.Helper()
		_, err := f.f.Owner.Pool.Exec(ctx, query, args...)
		require(t, err)
	}
	modify(`UPDATE sensors SET health=jsonb_set(health,'{engine_health,state}','"pending"') WHERE tenant_id=$1 AND id=$2`, f.u.TenantID, sensor)
	r = f.pulse(t, ctx, c.ID)
	if r.Code != "waiting_for_engine" || r.ObservationStartedAt != nil || r.CurrentBatch != 0 {
		t.Fatal("原生事务忙仍累积观察时间")
	}
	modify(`UPDATE sensors SET health=jsonb_set(health,'{engine_health,state}','"observed"') WHERE tenant_id=$1 AND id=$2`, f.u.TenantID, sensor)
	r = f.pulse(t, ctx, c.ID)
	if r.ObservationStartedAt == nil || !r.ObservationStartedAt.After(firstStart) {
		t.Fatal("恢复后沿用了被中断的窗口")
	}
	modify(`UPDATE rule_sync_runs SET finished_at=clock_timestamp()-interval '1 minute' WHERE tenant_id=$1 AND plan_id=$2`, f.u.TenantID, r.Targets[0].PlanID)
	modify(`UPDATE rule_rollouts SET observation_started_at=clock_timestamp()-interval '31 seconds' WHERE tenant_id=$1 AND id=$2`, f.u.TenantID, c.ID)
	modify(`UPDATE sensors SET last_seen=clock_timestamp(),health=jsonb_set(jsonb_set(health,'{observed_at}',to_jsonb(clock_timestamp())),'{engine_health,observed_at}',to_jsonb(clock_timestamp()-interval '2 seconds')) WHERE tenant_id=$1 AND id=$2`, f.u.TenantID, sensor)
	r = f.pulse(t, ctx, c.ID)
	if r.Code != "observing" || r.CurrentBatch != 0 || r.ObservationStartedAt == nil {
		t.Fatal("只有心跳越过窗口末尾仍放行")
	}
	modify(`UPDATE sensors SET health=jsonb_set(health,'{engine_health,observed_at}',to_jsonb(clock_timestamp())) WHERE tenant_id=$1 AND id=$2`, f.u.TenantID, sensor)
	r = f.pulse(t, ctx, c.ID)
	if r.CurrentBatch != 1 {
		t.Fatal("三条水位均通过后没有推进")
	}
	r = f.pulse(t, ctx, c.ID)
	if r.Targets[1].ExecutionRevision != 2 {
		t.Fatal("后续批次未启用")
	}
	modify(`UPDATE sensors SET health=jsonb_set(health,'{engine_health,state}','"unavailable"') WHERE tenant_id=$1 AND id=$2`, f.u.TenantID, sensor)
	r = f.pulse(t, ctx, c.ID)
	r = f.pulse(t, ctx, c.ID)
	if r.State != "blocked" || r.Code != "engine_health_failed" {
		t.Fatal("前序批次引擎失效仍继续后续提交", r.State, r.Code)
	}
	var tasks, enabled int
	require(t, f.f.Owner.Pool.QueryRow(ctx, `SELECT count(*) FROM sensor_tasks WHERE tenant_id=$1`, f.u.TenantID).Scan(&tasks))
	require(t, f.f.Owner.Pool.QueryRow(ctx, `SELECT count(*) FROM rule_sync_plans WHERE tenant_id=$1 AND enabled`, f.u.TenantID).Scan(&enabled))
	if tasks != 0 || enabled != 0 {
		t.Fatal("失效后仍留下执行授权或任务")
	}
}
