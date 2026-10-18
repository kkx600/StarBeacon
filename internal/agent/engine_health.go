package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/enginehealth"
	"github.com/shirou/gopsutil/v4/process"
)

var errInvalidEngineObservation = errors.New("原生引擎观测不完整或与登记规则不一致")

// EngineMonitor 不重载、不启动或停止引擎；观测在后台进行，心跳只读取有时效的快照。
type EngineMonitor struct {
	Engine *Engine
	mu     sync.Mutex
	record atomic.Pointer[enginehealth.Report]
}

func engineReport(state, code string) *enginehealth.Report {
	return &enginehealth.Report{SchemaVersion: enginehealth.Schema, State: state, Source: "unavailable", ObservedAt: time.Now().UTC(), Code: code}
}

func (m *EngineMonitor) Snapshot(ctx context.Context) *enginehealth.Report {
	if ctx.Err() != nil {
		return engineReport("pending", "engine_observation_cancelled")
	}
	r := m.record.Load()
	if r == nil || time.Since(r.ObservedAt) > 15*time.Second || r.ObservedAt.After(time.Now().Add(5*time.Second)) {
		return engineReport("pending", "engine_observation_pending")
	}
	// 调用方只能读取值副本，不能改写后续心跳或其他请求的观测。
	copy := *r
	return &copy
}

func (m *EngineMonitor) Run(ctx context.Context) {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for ctx.Err() == nil {
		m.Observe(ctx)
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func (m *EngineMonitor) Observe(ctx context.Context) (result *enginehealth.Report) {
	if !m.mu.TryLock() {
		return engineReport("pending", "engine_observation_pending")
	}
	defer m.mu.Unlock()
	defer func() { m.record.Store(result) }()
	e := m.Engine
	if e == nil {
		return engineReport("unconfigured", "engine_observation_not_configured")
	}
	if ctx.Err() != nil {
		return engineReport("pending", "engine_observation_cancelled")
	}
	if !e.ruleApplyMu.TryLock() {
		return engineReport("pending", "rule_operation_in_progress")
	}
	defer e.ruleApplyMu.Unlock()
	if e.Config.SuricataBinary == "" || e.Config.SuricataConfig == "" || e.Config.SuricataSocket == "" || e.Config.SuricataPIDFile == "" || e.Config.SuricataRulesPath == "" {
		return engineReport("unconfigured", "engine_observation_not_configured")
	}
	if _, err := os.Lstat(e.ruleJournalPath()); !os.IsNotExist(err) {
		return engineReport("unavailable", "rule_recovery_required")
	}
	call, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	before, err := e.engineIdentity(call)
	if err != nil {
		return engineReport("unavailable", "engine_process_unverified")
	}
	rules, err := readRegularBounded(e.Config.SuricataRulesPath, 900*1024, false)
	if err != nil {
		return engineReport("unavailable", "registered_rules_unavailable")
	}
	stats, err := socketCommand(call, e.Config.SuricataSocket, "ruleset-stats", nil)
	if err != nil {
		return engineReport("unavailable", "engine_ruleset_unavailable")
	}
	loaded, failed, err := observedRuleset(stats, ruleCount(string(rules)))
	if err != nil {
		return engineReport("unavailable", "engine_ruleset_mismatch")
	}
	after, err := e.engineIdentity(call)
	actual, readErr := readRegularBounded(e.Config.SuricataRulesPath, 900*1024, false)
	if err != nil || readErr != nil || before != after || control.Digest(actual) != control.Digest(rules) || call.Err() != nil {
		return engineReport("unavailable", "engine_observation_changed")
	}
	source := "registered_process"
	if e.Capture != nil {
		source = "managed_process"
	}
	return &enginehealth.Report{SchemaVersion: enginehealth.Schema, State: "observed", Source: source, ObservedAt: time.Now().UTC(), PID: before.PID, StartedAt: time.UnixMilli(before.Started).UTC(), ConfigSHA256: before.ConfigSHA256, RulesSHA256: control.Digest(rules), FileRuleCount: ruleCount(string(rules)), RulesLoaded: loaded, RulesFailed: failed}
}

type engineIdentity struct {
	PID          int32
	Started      int64
	ConfigSHA256 string
}

func (e *Engine) engineIdentity(ctx context.Context) (engineIdentity, error) {
	var result engineIdentity
	if err := e.ensureManagedPath(ctx); err != nil {
		return result, err
	}
	raw, err := readRegularBounded(e.Config.SuricataPIDFile, 32, true)
	if err != nil {
		return result, err
	}
	pid, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 32)
	if err != nil {
		return result, err
	}
	p, err := process.NewProcessWithContext(ctx, int32(pid))
	if err != nil {
		return result, err
	}
	started, err := p.CreateTimeWithContext(ctx)
	if err != nil || started <= 0 {
		return result, errInvalidEngineObservation
	}
	digest, err := ruleFileDigest(e.Config.SuricataConfig, 2*1024*1024)
	if err != nil {
		return result, err
	}
	return engineIdentity{PID: int32(pid), Started: started, ConfigSHA256: digest}, nil
}

// 多规则租户、缺失计数和部分装载都不能解释为登记完整规则包已经装载。
func observedRuleset(raw json.RawMessage, expected int) (int, int, error) {
	var values []struct {
		Loaded *int `json:"rules_loaded"`
		Failed *int `json:"rules_failed"`
	}
	if json.Unmarshal(raw, &values) != nil || len(values) != 1 || values[0].Loaded == nil || values[0].Failed == nil || expected < 1 || *values[0].Loaded != expected || *values[0].Failed != 0 {
		return 0, 0, errInvalidEngineObservation
	}
	return *values[0].Loaded, *values[0].Failed, nil
}
