package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"

	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/store"
	bolt "go.etcd.io/bbolt"
)

func (e *Engine) reconcile(ctx context.Context, c control.Command) (json.RawMessage, string, error) {
	if e.WAL == nil || !e.Config.AllowRuleApply || e.Config.SuricataSocket == "" || e.Config.SuricataRulesPath == "" || e.Config.SuricataPIDFile == "" {
		return nil, "rule_apply_not_authorized", errors.New("设备未授权规则核实")
	}
	var p control.RuleReconcile
	d := json.NewDecoder(bytes.NewReader(c.Payload))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil || d.Decode(new(any)) != io.EOF || p.Validate() != nil || control.Validate(c) != nil || p.UnknownTaskID == c.ID {
		return nil, "invalid_task", errors.New("规则核实参数无效")
	}
	var original LocalTask
	if err := e.WAL.DB.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("sensor_tasks"))
		if bucket == nil || bucket.Get([]byte(p.UnknownTaskID)) == nil {
			return errors.New("原设备任务不存在")
		}
		return json.Unmarshal(bucket.Get([]byte(p.UnknownTaskID)), &original)
	}); err != nil {
		return nil, "reconciliation_unavailable", err
	}
	if original.Origin != "platform" || original.Receipt.State != "unknown" || original.Command.Kind != "rules.apply" || original.Command.ID != p.UnknownTaskID || original.SHA256 != p.UnknownCommandSHA256 || original.Command.TenantID != e.WAL.TenantID || original.Command.SensorID != e.WAL.SensorID || original.Command.RegistrationID != e.WAL.RegistrationID || control.Validate(original.Command) != nil {
		return nil, "reconciliation_unavailable", errors.New("原任务不属于当前设备待核实的规则事务")
	}
	var source control.RulePackage
	if json.Unmarshal(original.Command.Payload, &source) != nil || source.Authorization.Validate() != nil || source.SHA256 != p.TargetSHA256 || source.Authorization.ExpectedRulesSHA256 != p.PreviousSHA256 || source.Authorization.ConfigSHA256 != p.ConfigSHA256 || source.Authorization.ProfileSHA256 != p.ProfileSHA256 {
		return nil, "reconciliation_unavailable", errors.New("原任务与平台核实依据不一致")
	}
	// 有恢复材料时先执行同一事务的恢复；摘要变化需要平台重新观察后发起核实。
	journal, err := readRegularBounded(e.ruleJournalPath(), 900*1024*4/3+8192, true)
	if err == nil {
		var transaction ruleTransaction
		if json.Unmarshal(journal, &transaction) != nil || transaction.TaskID != p.UnknownTaskID {
			return nil, "result_unknown", errors.New("规则恢复材料不属于本次核实事务")
		}
		if err = e.Recover(ctx); err != nil {
			return nil, "result_unknown", err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, "local_storage_unavailable", err
	}
	if !e.ruleApplyMu.TryLock() {
		return nil, "rule_operation_in_progress", errors.New("规则安装或核实正在执行")
	}
	defer e.ruleApplyMu.Unlock()
	if err = e.ensureManagedPath(ctx); err != nil {
		return nil, "managed_rules_mismatch", err
	}
	current, err := readRegularBounded(e.Config.SuricataRulesPath, 900*1024, false)
	if err != nil || control.Digest(current) != p.ExpectedSHA256 || store.ValidateRules(string(current)) != nil {
		return nil, "active_rules_changed", errors.New("当前规则不属于平台观察到的事务状态")
	}
	payload, err := control.RulePayload(control.RulePackage{PackageID: "reconcile", Revision: 1, EngineVersion: "8.0.7", Text: string(current), SHA256: p.ExpectedSHA256})
	if err != nil {
		return nil, "invalid_package", err
	}
	validation, code, err := e.Execute(ctx, control.Command{Kind: "rules.validate", Payload: payload})
	if err != nil {
		return validation, code, err
	}
	var checked struct {
		ConfigSHA256  string `json:"config_sha256"`
		ProfileSHA256 string `json:"profile_sha256"`
	}
	if json.Unmarshal(validation, &checked) != nil || checked.ConfigSHA256 != p.ConfigSHA256 || checked.ProfileSHA256 != p.ProfileSHA256 {
		return nil, "release_configuration_changed", errors.New("核实配置与中断前的检测配置不一致")
	}
	verified, err := readRegularBounded(e.Config.SuricataRulesPath, 900*1024, false)
	if err != nil || control.Digest(verified) != p.ExpectedSHA256 {
		return nil, "active_rules_changed", errors.New("装载检查期间规则文件发生变化")
	}
	if err = e.ensureManagedPath(ctx); err != nil {
		return nil, "managed_rules_mismatch", err
	}
	stats, err := e.reloadAndRead(ctx, ruleCount(string(current)))
	if err != nil {
		return nil, "result_unknown", err
	}
	verified, err = readRegularBounded(e.Config.SuricataRulesPath, 900*1024, false)
	if err != nil || control.Digest(verified) != p.ExpectedSHA256 {
		return nil, "result_unknown", errors.New("核实回读发现规则文件发生变化")
	}
	result, err := json.Marshal(control.RuleReconcileResult{Verified: true, UnknownTaskID: p.UnknownTaskID, UnknownCommandSHA256: p.UnknownCommandSHA256, ActiveSHA256: p.ExpectedSHA256, ConfigSHA256: p.ConfigSHA256, ProfileSHA256: p.ProfileSHA256, Stats: stats})
	return result, "", err
}
