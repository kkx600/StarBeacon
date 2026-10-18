package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/config"
	"github.com/kkx600/StarBeacon/internal/enginehealth"
)

func TestObservedRulesetRejectsIncompleteAndAmbiguousNativeData(t *testing.T) {
	for _, raw := range []string{`null`, `{}`, `[]`, `[{}]`, `[{"rules_loaded":2}]`, `[{"rules_loaded":null,"rules_failed":0}]`, `[{"rules_loaded":2,"rules_failed":null}]`, `[{"rules_loaded":2,"rules_failed":1}]`, `[{"rules_loaded":1,"rules_failed":0}]`, `[{"rules_loaded":2.5,"rules_failed":0}]`, `[{"rules_loaded":2,"rules_failed":0},{"rules_loaded":2,"rules_failed":0}]`, `[{"rules_loaded":2,"rules_failed":0}] {}`} {
		if _, _, err := observedRuleset(json.RawMessage(raw), 2); err == nil {
			t.Fatal("未拒绝不完整装载回读", raw)
		}
	}
	raw := json.RawMessage(`[{"id":0,"rules_loaded":2,"rules_failed":0}]`)
	if loaded, failed, err := observedRuleset(raw, 2); err != nil || loaded != 2 || failed != 0 {
		t.Fatal("真实形状的装载计数未通过", err)
	}
	if _, _, err := observedRuleset(raw, 0); err == nil {
		t.Fatal("空文件被作为装载成功")
	}
}

func TestEngineMonitorSnapshotDoesNotBlockAndExpiresCachedObservation(t *testing.T) {
	m := &EngineMonitor{}
	ctx := context.Background()
	if m.Snapshot(ctx).State != "pending" {
		t.Fatal("未开始观测就报告健康")
	}
	r := &enginehealth.Report{State: "observed", ObservedAt: time.Now().UTC(), RulesLoaded: 3}
	m.record.Store(r)
	copy := m.Snapshot(ctx)
	copy.RulesLoaded = 900
	if m.Snapshot(ctx).RulesLoaded != 3 {
		t.Fatal("调用方修改了后续心跳")
	}
	for _, at := range []time.Time{time.Now().Add(-16 * time.Second), time.Now().Add(6 * time.Second)} {
		m.record.Store(&enginehealth.Report{State: "observed", ObservedAt: at})
		if m.Snapshot(ctx).State != "pending" {
			t.Fatal("缓存过期或未来时间仍标记为健康")
		}
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if m.Snapshot(cancelled).Code != "engine_observation_cancelled" {
		t.Fatal("取消未生效")
	}
	m.mu.Lock()
	if m.Observe(ctx).State != "pending" {
		t.Fatal("并发观察未立即返回")
	}
	m.mu.Unlock()
}

func TestEngineMonitorAvailabilityAndRuleTransactionGuards(t *testing.T) {
	ctx := context.Background()
	m := &EngineMonitor{}
	if m.Observe(ctx).State != "unconfigured" {
		t.Fatal("缺少配置被推定为运行")
	}
	e, _ := recoveryFixture(t)
	var err error
	e.WAL, err = OpenWAL(e.Config.StatePath, "tenant_monitor", "sensor_monitor", "reg_monitor", 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer e.WAL.Close()
	e.Config.SuricataBinary = "/unavailable/suricata"
	e.Config.SuricataConfig = filepath.Join(t.TempDir(), "suricata.yaml")
	m.Engine = e
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if m.Observe(cancelled).Code != "engine_observation_cancelled" {
		t.Fatal("取消后仍读取原生状态")
	}
	e.ruleApplyMu.Lock()
	if m.Observe(ctx).Code != "rule_operation_in_progress" {
		t.Fatal("执行互斥未作为待观测状态")
	}
	e.ruleApplyMu.Unlock()
	if err := os.WriteFile(e.ruleJournalPath(), []byte("evidence"), 0600); err != nil {
		t.Fatal(err)
	}
	if m.Observe(ctx).Code != "rule_recovery_required" {
		t.Fatal("未决恢复被推定为健康")
	}
	if raw, err := os.ReadFile(e.ruleJournalPath()); err != nil || string(raw) != "evidence" {
		t.Fatal("观测改写了恢复材料", err)
	}
	if err := os.Remove(e.ruleJournalPath()); err != nil {
		t.Fatal(err)
	}
	if m.Observe(ctx).Code != "engine_process_unverified" {
		t.Fatal("未验证进程被接受")
	}
	if m.Snapshot(ctx).State != "unavailable" {
		t.Fatal("读取旧健康状态")
	}
	e.WAL.engineSnapshot = m.Snapshot
	if e.WAL.Health(ctx, e.Config.StatePath).EngineHealth.State != "unavailable" {
		t.Fatal("宿主健康没有携带原生观测")
	}
	m.Engine = &Engine{Config: config.Config{}}
	work, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { m.Run(work); close(done) }()
	deadline := time.After(time.Second)
	for m.Snapshot(ctx).State != "unconfigured" {
		select {
		case <-deadline:
			stop()
			t.Fatal("后台观察未执行")
		case <-time.After(time.Millisecond):
		}
	}
	stop()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("后台观察未随取消退出")
	}
}

func TestNativeEngineMonitorReadsActualProcessWithoutReload(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	e, _ := nativeRuleControl(t, ctx, nativeRuleControlOptions{})
	m := &EngineMonitor{Engine: e}
	before, err := socketCommand(ctx, e.Config.SuricataSocket, "ruleset-reload-time", nil)
	if err != nil {
		t.Fatal(err)
	}
	r := m.Observe(ctx)
	if r.State != "observed" || r.PID < 1 || r.Source != "registered_process" || r.RulesLoaded != 1 || enginehealth.Gate(r, r.RulesSHA256, time.Now(), time.Now().Add(-time.Minute)) != "" {
		t.Fatal("原生进程没有得到独立回读", r)
	}
	after, err := socketCommand(ctx, e.Config.SuricataSocket, "ruleset-reload-time", nil)
	if err != nil || string(before) != string(after) {
		t.Fatal("只读观测触发了规则重载", err)
	}
	original, err := os.ReadFile(e.Config.SuricataRulesPath)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(e.Config.SuricataRulesPath); err != nil {
		t.Fatal(err)
	}
	if r := m.Observe(ctx); r.Code != "registered_rules_unavailable" {
		t.Fatal("文件丢失仍被作为原生观测通过", r)
	}
	if err = os.WriteFile(e.Config.SuricataRulesPath, append(original, []byte("\n"+recoveryPrevious)...), 0600); err != nil {
		t.Fatal(err)
	}
	if r := m.Observe(ctx); r.State != "unavailable" || r.Code != "engine_ruleset_mismatch" {
		t.Fatal("文件数量变化而引擎未重载仍被通过", r)
	}
	if err = os.WriteFile(e.Config.SuricataRulesPath, original, 0600); err != nil {
		t.Fatal(err)
	}
	socket := e.Config.SuricataSocket
	e.Config.SuricataSocket = filepath.Join(t.TempDir(), "missing.sock")
	if r := m.Observe(ctx); r.State != "unavailable" || !strings.HasPrefix(r.Code, "engine_") {
		t.Fatal("失去原生控制后仍被通过", r)
	}
	e.Config.SuricataSocket = socket
	if m.Observe(ctx).State != "observed" {
		t.Fatal("原生观测未恢复")
	}
	process, err := os.FindProcess(int(r.PID))
	if err != nil || process.Signal(os.Interrupt) != nil {
		t.Fatal("无法停止本用例独占引擎", err)
	}
	for deadline := time.Now().Add(5 * time.Second); ; {
		r := m.Observe(ctx)
		if r.State == "unavailable" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("实际引擎退出后仍被推定为健康")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
