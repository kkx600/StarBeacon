package agent

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/kkx600/StarBeacon/internal/control"
	bolt "go.etcd.io/bbolt"
)

func (m *TaskManager) resolveRuleTask(tx *bolt.Tx, c control.Command, result json.RawMessage) error {
	var p control.RuleReconcile
	var proof control.RuleReconcileResult
	if json.Unmarshal(c.Payload, &p) != nil || json.Unmarshal(result, &proof) != nil || proof.Validate(p) != nil {
		return errors.New("设备核实回执与原事务不一致")
	}
	var original LocalTask
	if json.Unmarshal(tx.Bucket([]byte("sensor_tasks")).Get([]byte(p.UnknownTaskID)), &original) != nil || original.Origin != "platform" || original.Command.Kind != "rules.apply" || original.SHA256 != p.UnknownCommandSHA256 || original.Receipt.State != "unknown" {
		return errors.New("原规则任务缺少可核实的中断事实")
	}
	raw, err := json.Marshal(struct {
		TaskID      string                      `json:"task_id"`
		ConfirmedAt time.Time                   `json:"confirmed_at"`
		Result      control.RuleReconcileResult `json:"result"`
	}{TaskID: c.ID, ConfirmedAt: time.Now().UTC(), Result: proof})
	if err != nil {
		return err
	}
	original.RuleResolution = raw
	return m.putTask(tx, original)
}
