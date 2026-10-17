//go:build integration

package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/admin"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/replay"
	"github.com/kkx600/StarBeacon/internal/rulesync"
	"github.com/kkx600/StarBeacon/internal/store"
)

// 此用例验证真实 PG 的权限、恢复和原子性；设备实际效果由原生 mTLS 用例独立验证。
func TestRuleSyncPersistenceAuthorizationRecoveryAndFaults(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
	defer cancel()
	f := newIsolatedDatabase(t, ctx)
	tenant := store.RandomID("it_sync_")
	require(t, admin.Bootstrap(ctx, f.Owner, tenant, "同步持久化", tenant, store.Token(), "admin"))
	u, _, err := f.Runtime.Password(ctx, tenant)
	require(t, err)
	pub, signer, err := ed25519.GenerateKey(rand.Reader)
	require(t, err)
	rules, err := f.Runtime.SaveRulePackage(ctx, u, "rules_sync", "同步规则", `alert tcp any any -> any any (msg:"sync"; content:"example"; sid:1008123; rev:1;)`, 0, "rules")
	require(t, err)
	for i := 0; i < 2; i++ {
		id := "sample_sync_" + strconv.Itoa(i)
		require(t, f.Runtime.ReserveSample(ctx, u, replay.Sample{ID: id, Name: "隔离样本", Size: 32}, 1<<20))
		require(t, f.Runtime.CompleteSample(ctx, u, id, control.Digest([]byte(id)), "pcap", "sample"))
	}
	base := rulesync.Change{ID: "sync_save", Spec: rulesync.Spec{Name: "同步计划", Enabled: true, SensorID: "sensor_save", RegistrationID: "registration_save", PackageID: rules.ID, PackageRevision: 1, PositiveSampleID: "sample_sync_0", NegativeSampleID: "sample_sync_1", IntervalSeconds: 30}}
	health := model.HostHealth{ObservedAt: time.Now().UTC(), TaskCapabilities: []string{"rules.validate", "rules.replay", "rules.apply"}, CommandSignerSHA256: control.Digest(pub), RegisteredRulesSHA256: control.Digest([]byte("previous")), RegisteredRulesAvailable: true}
	seed := func(c rulesync.Change, h model.HostHealth) {
		t.Helper()
		raw, _ := json.Marshal(h)
		_, err := f.Owner.Pool.Exec(ctx, `INSERT INTO sensors(tenant_id,id,name,registration_id,last_seen,health) VALUES($1,$2,'隔离探针',$3,now(),$4)`, tenant, c.Spec.SensorID, c.Spec.RegistrationID, raw)
		require(t, err)
	}
	seed(base, health)
	for _, prefix := range []string{"SELECT pg_advisory_xact_lock", "SELECT jsonb_build_object('id',p.id", "SELECT count(*) FROM operation_audits", "SELECT count(*) FROM rule_sync_plans", "SELECT jsonb_build_object('id',r.id", "SELECT registration_id FROM sensors", "SELECT EXISTS(SELECT 1 FROM rule_packages", "SELECT a.sha256,b.sha256", "INSERT INTO rule_sync_plans", "INSERT INTO operation_audits"} {
		t.Run("保存中断 "+prefix, func(t *testing.T) {
			broken, tracer := disconnectedStore(t, ctx, f.RuntimeDSN, prefix)
			before := ownedBusinessSnapshot(t, ctx, f.Owner, tenant)
			_, err := broken.SaveRuleSyncPlan(ctx, u, base, "save_fault")
			if err == nil || !tracer.fired.Load() {
				t.Fatal("没有触发真实数据库中断", err)
			}
			if ownedBusinessSnapshot(t, ctx, f.Owner, tenant) != before {
				t.Fatal("保存中断留下部分变更")
			}
			var n int
			require(t, f.Owner.Pool.QueryRow(ctx, `SELECT count(*) FROM rule_sync_plans WHERE tenant_id=$1`, tenant).Scan(&n))
			if n != 0 {
				t.Fatal("保存失败仍写入计划")
			}
		})
	}
	plan, err := f.Runtime.SaveRuleSyncPlan(ctx, u, base, "save")
	require(t, err)
	if plan.Revision != 1 {
		t.Fatal("初次修订错误")
	}
	bad := base
	bad.Spec.PackageID = "missing"
	bad.ExpectedRevision = 1
	if _, err := f.Runtime.SaveRuleSyncPlan(ctx, u, bad, "missing"); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("缺失规则未拒绝", err)
	}
	bad = base
	bad.ExpectedRevision = 1
	bad.Spec.PositiveSampleID = "missing"
	if _, err := f.Runtime.SaveRuleSyncPlan(ctx, u, bad, "sample"); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("缺失样本未拒绝", err)
	}
	bad = base
	bad.ID = "bad/id"
	if _, err := f.Runtime.SaveRuleSyncPlan(ctx, u, bad, "bad"); !errors.Is(err, rulesync.ErrInput) {
		t.Fatal("非法计划通过")
	}
	bad = base
	bad.ExpectedRevision = 1
	bad.Spec.SensorID = "other"
	if _, err := f.Runtime.SaveRuleSyncPlan(ctx, u, bad, "move"); !errors.Is(err, rulesync.ErrInput) {
		t.Fatal("目标被隐式移动")
	}
	for _, prefix := range []string{"SELECT id FROM rule_sync_plans", "SET LOCAL lock_timeout", "SELECT jsonb_build_object('id',p.id", "UPDATE rule_sync_plans SET next_at", "INSERT INTO rule_sync_runs", "SELECT u.active,u.role,t.active", "SELECT registration_id,active,last_seen,health", "SELECT rules_text,sha256,engine_version", "INSERT INTO sensor_tasks", "UPDATE rule_sync_runs SET stage"} {
		t.Run("调度中断 "+prefix, func(t *testing.T) {
			_, err := f.Owner.Pool.Exec(ctx, `UPDATE rule_sync_plans SET next_at=now()-interval '1 second' WHERE tenant_id=$1`, tenant)
			require(t, err)
			broken, tracer := disconnectedStore(t, ctx, f.RuntimeDSN, prefix)
			before := ownedBusinessSnapshot(t, ctx, f.Owner, tenant)
			_, err = broken.SweepRuleSync(ctx, tenant, signer)
			if err == nil || !tracer.fired.Load() {
				t.Fatal("调度没有触发真实中断", err)
			}
			if ownedBusinessSnapshot(t, ctx, f.Owner, tenant) != before {
				t.Fatal("调度中断留下任务或审计")
			}
			var n int
			require(t, f.Owner.Pool.QueryRow(ctx, `SELECT count(*) FROM rule_sync_runs WHERE tenant_id=$1`, tenant).Scan(&n))
			if n != 0 {
				t.Fatal("调度失败留下半个阶段")
			}
		})
	}
	for i, scenario := range []string{"offline", "trust", "capability", "digest", "disabled", "registration", "owner", "sample_expired", "task_failed", "task_unknown", "missing_task", "apply_unverified"} {
		t.Run(scenario, func(t *testing.T) {
			c := base
			c.ID = "sync_case_" + strconv.Itoa(i)
			c.Spec.SensorID = "sensor_case_" + strconv.Itoa(i)
			c.Spec.RegistrationID = "registration_case_" + strconv.Itoa(i)
			h := health
			switch scenario {
			case "trust":
				h.CommandSignerSHA256 = strings.Repeat("f", 64)
			case "capability":
				h.TaskCapabilities = nil
			case "digest":
				h.RegisteredRulesSHA256 = ""
			}
			seed(c, h)
			_, err := f.Runtime.SaveRuleSyncPlan(ctx, u, c, "case")
			require(t, err)
			modify := func(q string, args ...any) { t.Helper(); _, err := f.Owner.Pool.Exec(ctx, q, args...); require(t, err) }
			if scenario == "offline" {
				modify(`UPDATE sensors SET last_seen=now()-interval '5 minutes' WHERE tenant_id=$1 AND id=$2`, tenant, c.Spec.SensorID)
			}
			if scenario == "disabled" {
				modify(`UPDATE sensors SET active=false WHERE tenant_id=$1 AND id=$2`, tenant, c.Spec.SensorID)
			}
			if scenario == "registration" {
				modify(`UPDATE sensors SET registration_id='different_registration' WHERE tenant_id=$1 AND id=$2`, tenant, c.Spec.SensorID)
			}
			if scenario == "owner" {
				modify(`UPDATE users SET active=false WHERE tenant_id=$1 AND id=$2`, tenant, u.ID)
			}
			_, err = f.Runtime.SweepRuleSync(ctx, tenant, signer)
			require(t, err)
			if scenario == "owner" {
				modify(`UPDATE users SET active=true WHERE tenant_id=$1 AND id=$2`, tenant, u.ID)
			}
			var state, code string
			read := func() {
				t.Helper()
				require(t, f.Owner.Pool.QueryRow(ctx, `SELECT state,code FROM rule_sync_runs WHERE tenant_id=$1 AND plan_id=$2 ORDER BY plan_revision DESC LIMIT 1`, tenant, c.ID).Scan(&state, &code))
			}
			read()
			if scenario == "offline" {
				if state != "pending" || code != "sensor_offline" {
					t.Fatal("离线被误报为完成")
				}
				return
			}
			if scenario == "trust" || scenario == "capability" || scenario == "digest" || scenario == "disabled" || scenario == "registration" || scenario == "owner" {
				if state != "blocked" {
					t.Fatal("资格变化未停止", scenario, state, code)
				}
				return
			}
			var task string
			require(t, f.Owner.Pool.QueryRow(ctx, `SELECT tasks->>0 FROM rule_sync_runs WHERE tenant_id=$1 AND plan_id=$2`, tenant, c.ID).Scan(&task))
			switch scenario {
			case "sample_expired":
				modify(`UPDATE sensor_tasks SET state='succeeded',receipt='{}' WHERE tenant_id=$1 AND id=$2`, tenant, task)
				modify(`UPDATE replay_samples SET expires_at=now()+interval '1 minute' WHERE tenant_id=$1 AND id=$2`, tenant, c.Spec.PositiveSampleID)
			case "task_failed":
				modify(`UPDATE sensor_tasks SET state='failed' WHERE tenant_id=$1 AND id=$2`, tenant, task)
			case "task_unknown":
				modify(`UPDATE sensor_tasks SET state='unknown' WHERE tenant_id=$1 AND id=$2`, tenant, task)
			case "missing_task":
				modify(`UPDATE rule_sync_runs SET tasks='["task_missing","","",""]' WHERE tenant_id=$1 AND plan_id=$2`, tenant, c.ID)
			case "apply_unverified":
				modify(`UPDATE sensor_tasks SET state='succeeded',receipt='{}' WHERE tenant_id=$1 AND id=$2`, tenant, task)
				modify(`UPDATE rule_sync_runs SET stage=3,tasks=jsonb_build_array('','','',$3::text) WHERE tenant_id=$1 AND plan_id=$2`, tenant, c.ID, task)
			}
			modify(`UPDATE rule_sync_plans SET next_at=now()-interval '1 second' WHERE tenant_id=$1 AND id=$2`, tenant, c.ID)
			_, err = f.Runtime.SweepRuleSync(ctx, tenant, signer)
			require(t, err)
			read()
			if state != "blocked" {
				t.Fatal("异常继续推进", scenario, state, code)
			}
			if scenario == "sample_expired" {
				modify(`UPDATE replay_samples SET expires_at=now()+interval '180 days' WHERE tenant_id=$1 AND id=$2`, tenant, c.Spec.PositiveSampleID)
			}
		})
	}
}
