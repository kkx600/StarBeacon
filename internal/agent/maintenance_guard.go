package agent

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/control"
	bolt "go.etcd.io/bbolt"
)

// InspectStoppedForUpdate 只能在确认原进程停止后调用；只读检查不迁移、不复制或清空 WAL。
// 未决动作即使已超过本机时钟期限也不能当成已解封，须先由原版本回读设备。
func InspectStoppedForUpdate(ctx context.Context, directory string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := os.Lstat(filepath.Join(directory, "rule-transaction.json")); !errors.Is(err, os.ErrNotExist) {
		return errors.New("存在未完成或无法读取的规则事务，禁止切换程序")
	}
	name := filepath.Join(directory, "agent.db")
	info, err := os.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("采集器 WAL 类型不可核对")
	}
	db, err := bolt.Open(name, 0600, &bolt.Options{ReadOnly: true, Timeout: time.Second})
	if err != nil {
		return errors.New("WAL 无法独占核对，请确认原采集器已经停止")
	}
	defer db.Close()
	return db.View(func(tx *bolt.Tx) error {
		meta := tx.Bucket([]byte("meta"))
		if meta == nil || len(meta.Get([]byte("pending_count"))) != 8 {
			return errors.New("WAL 身份或容量元数据无效")
		}
		identity := strings.Split(string(meta.Get([]byte("identity"))), "/")
		if len(identity) != 3 || !contract.ValidID(identity[0]) || !contract.ValidID(identity[1]) || !contract.ValidID(identity[2]) || !contract.ValidID(string(meta.Get([]byte("epoch")))) {
			return errors.New("WAL 身份或代次无效")
		}
		wal := &WAL{DB: db, TenantID: identity[0], SensorID: identity[1], RegistrationID: identity[2]}
		manager := &TaskManager{WAL: wal}
		responder := &ResponseService{WAL: wal}
		var pending uint64
		for _, name := range []string{"alerts", "context"} {
			bucket := tx.Bucket([]byte(name))
			if bucket == nil {
				return errors.New("WAL 事件目录缺失")
			}
			pending += uint64(bucket.Stats().KeyN)
		}
		if pending != binary.BigEndian.Uint64(meta.Get([]byte("pending_count"))) {
			return errors.New("WAL 待传计数与实际记录不一致")
		}
		for _, name := range []string{"sensor_tasks", "response_leases"} {
			bucket := tx.Bucket([]byte(name))
			if bucket == nil {
				continue
			}
			scanned := 0
			if err := bucket.ForEach(func(k, raw []byte) error {
				if err := ctx.Err(); err != nil {
					return err
				}
				scanned++
				if scanned > 16384 || len(raw) == 0 || len(raw) > 2<<20 {
					return errors.New("维护检查目录超限或存在嵌套记录")
				}
				if name == "sensor_tasks" {
					var task LocalTask
					if json.Unmarshal(raw, &task) != nil || manager.validateLocalTask(task, string(k)) != nil || task.Receipt.State == "running" || task.Receipt.State == "unknown" && len(task.RuleResolution) == 0 {
						return errors.New("仍有执行中、结果未知或绑定无效的设备任务")
					}
					if task.Receipt.State == "unknown" && !resolvedForMaintenance(tx, manager, task) {
						return errors.New("规则核实依据不完整，禁止切换程序")
					}
				} else {
					var lease responseRecord
					if json.Unmarshal(raw, &lease) != nil || responder.validRecord(string(k), lease) != nil || lease.Status != "revoked" && lease.Status != "expired" || lease.Result == nil || lease.Result.Validate(lease.Action, "response.read", lease.CheckedAt) != nil || lease.Result.Observation.State != lease.Status {
						return errors.New("仍有待核实、有效或绑定无效的封禁租约，禁止中断撤销责任")
					}
				}
				return nil
			}); err != nil {
				return err
			}
		}
		return ctx.Err()
	})
}

func resolvedForMaintenance(tx *bolt.Tx, manager *TaskManager, original LocalTask) bool {
	var resolution struct {
		TaskID      string                      `json:"task_id"`
		ConfirmedAt time.Time                   `json:"confirmed_at"`
		Result      control.RuleReconcileResult `json:"result"`
	}
	if original.Origin != "platform" || original.Command.Kind != "rules.apply" || json.Unmarshal(original.RuleResolution, &resolution) != nil || !contract.ValidID(resolution.TaskID) || resolution.ConfirmedAt.IsZero() {
		return false
	}
	var reconciled LocalTask
	if json.Unmarshal(tx.Bucket([]byte("sensor_tasks")).Get([]byte(resolution.TaskID)), &reconciled) != nil || manager.validateLocalTask(reconciled, resolution.TaskID) != nil || reconciled.Command.Kind != "rules.reconcile" || reconciled.Receipt.State != "succeeded" {
		return false
	}
	var input control.RuleReconcile
	var result control.RuleReconcileResult
	if json.Unmarshal(reconciled.Command.Payload, &input) != nil || json.Unmarshal(reconciled.Receipt.Result, &result) != nil || input.UnknownTaskID != original.Command.ID || input.UnknownCommandSHA256 != original.SHA256 || resolution.Result.Validate(input) != nil || result.Validate(input) != nil {
		return false
	}
	a, _ := json.Marshal(resolution.Result)
	b, _ := json.Marshal(result)
	return string(a) == string(b)
}
