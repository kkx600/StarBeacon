package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/control"
	bolt "go.etcd.io/bbolt"
)

func walState(t *testing.T, w *WAL) string {
	t.Helper()
	var output bytes.Buffer
	if err := w.DB.View(func(tx *bolt.Tx) error {
		for _, name := range []string{"sensor_tasks", "task_receipts", "task_history", "meta"} {
			output.WriteString(name)
			if err := tx.Bucket([]byte(name)).ForEach(func(k, v []byte) error {
				output.Write(k)
				output.WriteByte(0)
				output.Write(v)
				output.WriteByte(0)
				return nil
			}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return control.Digest(output.Bytes())
}

// 签名、重启和存储均为真实操作；这里仅检查执行前置拒绝，不作为原生引擎成功证据。
func reconciliationFixture(t *testing.T) (*Engine, *TaskManager, control.Command, control.RuleReconcile, LocalTask) {
	t.Helper()
	e, _ := recoveryFixture(t)
	m, private := taskFixture(t, terminalRunner{})
	e.WAL = m.WAL
	digest := control.Digest([]byte("qualification fixture"))
	grant := &control.RuleAuthorization{ValidationTaskID: "validation", PositiveReplayTaskID: "positive", NegativeReplayTaskID: "negative", ExpectedRulesSHA256: control.Digest([]byte(recoveryPrevious)), ConfigSHA256: digest, ProfileSHA256: digest, ValidationReceiptSHA256: digest, PositiveReceiptSHA256: digest, NegativeReceiptSHA256: digest}
	payload, err := control.RulePayload(control.RulePackage{PackageID: "rules", Revision: 1, EngineVersion: "8.0.7", Text: recoveryTarget, SHA256: control.Digest([]byte(recoveryTarget)), Authorization: grant})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	original := control.Command{ID: "task_interrupted", TenantID: m.WAL.TenantID, SensorID: m.WAL.SensorID, RegistrationID: m.WAL.RegistrationID, Kind: "rules.apply", IssuedAt: now, ExpiresAt: now.Add(time.Minute), Payload: payload}
	raw, signature, err := control.Encode(original, private)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.Accept(raw, signature); err != nil {
		t.Fatal(err)
	}
	m, err = NewTaskManager(m.WAL, m.PublicKey, terminalRunner{})
	if err != nil {
		t.Fatal(err)
	}
	p := control.RuleReconcile{UnknownTaskID: original.ID, UnknownCommandSHA256: control.Digest(raw), ExpectedSHA256: control.Digest([]byte(recoveryTarget)), TargetSHA256: control.Digest([]byte(recoveryTarget)), PreviousSHA256: grant.ExpectedRulesSHA256, ConfigSHA256: digest, ProfileSHA256: digest}
	c := original
	c.ID = "task_reconcile"
	c.Kind = "rules.reconcile"
	c.Payload, _ = json.Marshal(p)
	var record LocalTask
	if err = m.WAL.DB.View(func(tx *bolt.Tx) error {
		return json.Unmarshal(tx.Bucket([]byte("sensor_tasks")).Get([]byte(original.ID)), &record)
	}); err != nil {
		t.Fatal(err)
	}
	return e, m, c, p, record
}

func TestReconciliationRejectsUntrustedOriginalAndPreservesFiles(t *testing.T) {
	for _, name := range []string{"未授权", "缺少WAL", "无效任务", "自身任务", "未知字段", "缺失记录", "缺失存储桶", "损坏记录", "本地来源", "已结束任务", "其他任务标识", "其他任务类型", "其他摘要", "其他租户", "其他探针", "其他注册代次", "损坏规则包", "其他目标摘要", "其他历史摘要", "其他检测配置", "其他检测剖面", "其他恢复任务", "恢复材料损坏", "恢复材料不可读取", "恢复失败", "并发操作", "未登记引擎"} {
		t.Run(name, func(t *testing.T) {
			e, m, c, p, record := reconciliationFixture(t)
			switch name {
			case "未授权":
				e.Config.AllowRuleApply = false
			case "缺少WAL":
				e.WAL = nil
			case "无效任务":
				c.Payload = json.RawMessage(`{}`)
			case "自身任务":
				c.ID = p.UnknownTaskID
			case "未知字段":
				c.Payload = append(c.Payload[:len(c.Payload)-1], []byte(`,"path":"foreign"}`)...)
			case "缺失记录":
				if err := m.WAL.DB.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte("sensor_tasks")).Delete([]byte(p.UnknownTaskID)) }); err != nil {
					t.Fatal(err)
				}
			case "缺失存储桶":
				if err := m.WAL.DB.Update(func(tx *bolt.Tx) error { return tx.DeleteBucket([]byte("sensor_tasks")) }); err != nil {
					t.Fatal(err)
				}
			case "损坏记录":
				if err := m.WAL.DB.Update(func(tx *bolt.Tx) error {
					return tx.Bucket([]byte("sensor_tasks")).Put([]byte(p.UnknownTaskID), []byte(`{`))
				}); err != nil {
					t.Fatal(err)
				}
			case "本地来源":
				record.Origin = "local"
			case "已结束任务":
				record.Receipt.State = "succeeded"
			case "其他任务标识":
				record.Command.ID = "other"
			case "其他任务类型":
				record.Command.Kind = "diagnostics"
			case "其他摘要":
				record.SHA256 = control.Digest([]byte("other"))
			case "其他租户":
				record.Command.TenantID = "foreign"
			case "其他探针":
				record.Command.SensorID = "foreign"
			case "其他注册代次":
				record.Command.RegistrationID = "foreign"
			case "损坏规则包":
				record.Command.Payload = json.RawMessage(`{}`)
			case "其他目标摘要":
				p.TargetSHA256 = control.Digest([]byte("other target"))
				p.ExpectedSHA256 = p.PreviousSHA256
				c.Payload, _ = json.Marshal(p)
			case "其他历史摘要":
				p.PreviousSHA256 = control.Digest([]byte("other previous"))
				c.Payload, _ = json.Marshal(p)
			case "其他检测配置":
				p.ConfigSHA256 = control.Digest([]byte("other config"))
				c.Payload, _ = json.Marshal(p)
			case "其他检测剖面":
				p.ProfileSHA256 = control.Digest([]byte("other profile"))
				c.Payload, _ = json.Marshal(p)
			case "其他恢复任务", "恢复失败":
				id := p.UnknownTaskID
				if name == "其他恢复任务" {
					id = "foreign"
				}
				saveRecoveryFixture(t, e, ruleTransaction{TaskID: id, Path: e.Config.SuricataRulesPath, Previous: []byte(recoveryPrevious), TargetSHA256: p.TargetSHA256})
			case "恢复材料损坏":
				if err := os.WriteFile(e.ruleJournalPath(), []byte(`{`), 0600); err != nil {
					t.Fatal(err)
				}
			case "恢复材料不可读取":
				if err := os.Mkdir(e.ruleJournalPath(), 0700); err != nil {
					t.Fatal(err)
				}
			case "并发操作":
				e.ruleApplyMu.Lock()
				defer e.ruleApplyMu.Unlock()
			}
			if strings.HasPrefix(name, "其他") && name != "其他目标摘要" && name != "其他历史摘要" && name != "其他检测配置" && name != "其他检测剖面" && name != "其他恢复任务" || name == "本地来源" || name == "已结束任务" || name == "损坏规则包" {
				raw, _ := json.Marshal(record)
				if err := m.WAL.DB.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte("sensor_tasks")).Put([]byte(p.UnknownTaskID), raw) }); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.ReadFile(e.Config.SuricataRulesPath)
			if err != nil {
				t.Fatal(err)
			}
			if _, code, err := e.Execute(context.Background(), c); err == nil || code == "" {
				t.Fatal("未核实的事务被接受", code, err)
			}
			after, err := os.ReadFile(e.Config.SuricataRulesPath)
			if err != nil || string(after) != string(before) {
				t.Fatal("前置拒绝改写了规则文件", err)
			}
		})
	}
}

func TestAcknowledgedUnknownRuleTaskRetainsReconciliationEvidence(t *testing.T) {
	_, m, _, p, original := reconciliationFixture(t)
	pending, err := m.Pending()
	if err != nil || len(pending) != 1 {
		t.Fatal("中断回执未进入持久队列", err)
	}
	if err = m.Confirm(p.UnknownTaskID, control.HashBytes(pending[0])); err != nil {
		t.Fatal(err)
	}
	if err = m.WAL.DB.Update(func(tx *bolt.Tx) error { return m.prune(tx, time.Now().AddDate(0, 0, 181)) }); err != nil {
		t.Fatal(err)
	}
	var saved LocalTask
	if err = m.WAL.DB.View(func(tx *bolt.Tx) error {
		return json.Unmarshal(tx.Bucket([]byte("sensor_tasks")).Get([]byte(p.UnknownTaskID)), &saved)
	}); err != nil {
		t.Fatal(err)
	}
	if !saved.Acknowledged || saved.Receipt.State != "unknown" || saved.SHA256 != original.SHA256 || !bytes.Equal(saved.Command.Payload, original.Command.Payload) || control.Validate(saved.Command) != nil {
		t.Fatal("平台确认或留存清理销毁了尚待核实的规则依据")
	}
	if pending, err = m.Pending(); err != nil || len(pending) != 0 {
		t.Fatal("已确认回执仍重复上报", err)
	}
}

func TestLocalReconciliationProofIsAtomicAndPrunableAfterAcknowledgement(t *testing.T) {
	_, m, c, p, original := reconciliationFixture(t)
	proof := control.RuleReconcileResult{Verified: true, UnknownTaskID: p.UnknownTaskID, UnknownCommandSHA256: p.UnknownCommandSHA256, ActiveSHA256: p.ExpectedSHA256, ConfigSHA256: p.ConfigSHA256, ProfileSHA256: p.ProfileSHA256, Stats: json.RawMessage(`[{"rules_loaded":1,"rules_failed":0}]`)}
	raw, _ := json.Marshal(proof)
	originalReceipt, _ := json.Marshal(original.Receipt)
	before := walState(t, m.WAL)
	for _, candidate := range []json.RawMessage{json.RawMessage(`{}`), json.RawMessage(`{"verified":true}`), json.RawMessage(`{`)} {
		err := m.WAL.DB.Update(func(tx *bolt.Tx) error { return m.resolveRuleTask(tx, c, candidate) })
		if err == nil || walState(t, m.WAL) != before {
			t.Fatal("无效核实改变了设备存储", err)
		}
	}
	if err := m.WAL.DB.Update(func(tx *bolt.Tx) error { return m.resolveRuleTask(tx, c, raw) }); err != nil {
		t.Fatal(err)
	}
	rows, err := m.List()
	if err != nil || len(rows) != 1 || len(rows[0].RuleResolution) == 0 || rows[0].Receipt.State != "unknown" {
		t.Fatal("中断事实或核实依据未保留", rows, err)
	}
	receipt, _ := json.Marshal(rows[0].Receipt)
	if string(receipt) != string(originalReceipt) {
		t.Fatal("核实改写了原中断回执")
	}
	pending, err := m.Pending()
	if err != nil || len(pending) != 1 {
		t.Fatal(err)
	}
	if err = m.Confirm(p.UnknownTaskID, control.HashBytes(pending[0])); err != nil {
		t.Fatal(err)
	}
	if err = m.WAL.DB.Update(func(tx *bolt.Tx) error { return m.prune(tx, time.Now().AddDate(0, 0, 181)) }); err != nil {
		t.Fatal(err)
	}
	rows, err = m.List()
	if err != nil || len(rows) != 0 {
		t.Fatal("已确认且已核实的到期任务未回收", rows, err)
	}
}
