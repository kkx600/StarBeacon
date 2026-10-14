package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/telemetry"
	bolt "go.etcd.io/bbolt"
)

type TaskRunner interface {
	Execute(context.Context, control.Command) (json.RawMessage, string, error)
}
type LocalTask struct {
	Origin         string          `json:"origin,omitempty"`
	Command        control.Command `json:"command"`
	SHA256         string          `json:"sha256"`
	Receipt        control.Receipt `json:"receipt"`
	Acknowledged   bool            `json:"acknowledged"`
	RuleResolution json.RawMessage `json:"rule_resolution,omitempty"`
	RetainUntil    time.Time       `json:"retain_until"`
}

var ErrLocalTaskNotFound = errors.New("本地任务不存在或已过留存期")

type TaskManager struct {
	WAL           *WAL
	PublicKey     ed25519.PublicKey
	Runner        TaskRunner
	queue         chan control.Command
	mu            sync.Mutex
	MaxBytes      uint64
	RetentionDays int
	Replay        *ReplayService
	Capture       *CaptureSupervisor
}

func NewTaskManager(w *WAL, publicKey ed25519.PublicKey, runner TaskRunner) (*TaskManager, error) {
	m := &TaskManager{WAL: w, PublicKey: publicKey, Runner: runner, queue: make(chan control.Command, 1), MaxBytes: 64 * 1024 * 1024, RetentionDays: 180}
	e := w.DB.Update(func(tx *bolt.Tx) error {
		b, e := tx.CreateBucketIfNotExists([]byte("sensor_tasks"))
		if e != nil {
			return e
		}
		pending, e := tx.CreateBucketIfNotExists([]byte("task_receipts"))
		if e != nil {
			return e
		}
		index, e := tx.CreateBucketIfNotExists([]byte("task_history"))
		if e != nil {
			return e
		}
		var used uint64
		err := b.ForEach(func(k, v []byte) error {
			var task LocalTask
			if e := json.Unmarshal(v, &task); e != nil {
				return e
			}
			changed := false
			if task.RetainUntil.IsZero() {
				// 历史记录继承其接收时的默认期限，不由重启后的配置延长或缩短。
				task.RetainUntil = localTaskRetention(task)
				changed = true
			}
			// 崩溃后的执行阶段不能推断为成功，也不盲目重放有副作用的命令。
			if task.Receipt.State == "running" {
				now := time.Now().UTC()
				task.Receipt.State = "unknown"
				task.Receipt.Code = "execution_interrupted"
				task.Receipt.FinishedAt = &now
				task.Acknowledged = task.Origin == "local"
				changed = true
			}
			if changed {
				raw, e := json.Marshal(task)
				if e != nil {
					return e
				}
				if e = b.Put(k, raw); e != nil {
					return e
				}
				v = raw
			}
			used += taskSize(v, task.Receipt.State)
			if e = index.Put(taskIndex(task), k); e != nil {
				return e
			}
			if !task.Acknowledged && task.Origin != "local" {
				return pending.Put(k, []byte{1})
			}
			return nil
		})
		if err != nil {
			return err
		}
		return tx.Bucket([]byte("meta")).Put([]byte("task_bytes"), key(used))
	})
	return m, e
}
func (m *TaskManager) Accept(raw, signature []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, e := control.Decode(raw, signature, m.PublicKey, m.WAL.TenantID, m.WAL.SensorID, m.WAL.RegistrationID, time.Now().UTC())
	if e != nil && !errors.Is(e, control.ErrExpired) {
		return e
	}
	return m.accept(c, control.Digest(raw), "platform")
}
func (m *TaskManager) accept(c control.Command, digest, origin string) error {
	created := false
	var e error
	e = m.WAL.DB.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("sensor_tasks"))
		if previous := b.Get([]byte(c.ID)); previous != nil {
			var v LocalTask
			if e := json.Unmarshal(previous, &v); e != nil {
				return e
			}
			if v.SHA256 != digest || v.Origin == "local" {
				return errors.New("任务身份对应不同内容")
			}
			v.Acknowledged = false
			if e = m.putTask(tx, v); e != nil {
				return e
			}
			return tx.Bucket([]byte("task_receipts")).Put([]byte(c.ID), []byte{1})
		}
		if len(m.queue) == cap(m.queue) {
			return errors.New("设备执行队列已满")
		}
		now := time.Now().UTC()
		v := LocalTask{Origin: origin, Acknowledged: origin == "local", Command: c, SHA256: digest, RetainUntil: now.AddDate(0, 0, m.RetentionDays), Receipt: control.Receipt{CommandID: c.ID, CommandSHA256: digest, State: "running", StartedAt: now, Result: json.RawMessage(`{}`)}}
		if !c.ExpiresAt.After(now) || c.IssuedAt.After(now.Add(time.Minute)) {
			v.Receipt.State = "failed"
			v.Receipt.Code = "command_expired"
			v.Receipt.FinishedAt = &now
		} else {
			created = true
		}
		if e = m.prune(tx, now); e != nil {
			return e
		}
		if e = m.putTask(tx, v); e != nil {
			return e
		}
		if origin != "local" {
			if e = tx.Bucket([]byte("task_receipts")).Put([]byte(c.ID), []byte{1}); e != nil {
				return e
			}
		}
		return appendAudit(tx, LocalAudit{Username: origin, Action: "task.accept." + c.Kind, RequestID: c.ID, CreatedAt: now, ExpiresAt: now.AddDate(0, 0, 180)})
	})
	if e == nil && created {
		m.queue <- c
	}
	return e
}
func (m *TaskManager) Run(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case c := <-m.queue:
			started := time.Now()
			call, cancel := context.WithTimeout(ctx, 2*time.Minute)
			result, code, e := m.Runner.Execute(call, c)
			cancel()
			state := "succeeded"
			if e != nil {
				state = "failed"
				if code == "result_unknown" {
					state = "unknown"
				}
			}
			if len(result) == 0 {
				result = json.RawMessage(`{}`)
			}
			if len(result) > 64*1024 || !json.Valid(result) {
				result = json.RawMessage(`{}`)
				state = "failed"
				code = "invalid_execution_result"
			}
			e = m.WAL.DB.Update(func(tx *bolt.Tx) error {
				b := tx.Bucket([]byte("sensor_tasks"))
				var v LocalTask
				if e := json.Unmarshal(b.Get([]byte(c.ID)), &v); e != nil {
					return e
				}
				now := time.Now().UTC()
				v.Receipt.State = state
				v.Receipt.Code = code
				v.Receipt.Result = result
				v.Receipt.FinishedAt = &now
				v.Acknowledged = v.Origin == "local"
				if v.Origin == "local" {
					v.Command.Payload = nil
				}
				if e := m.putTask(tx, v); e != nil {
					return e
				}
				if c.Kind == "rules.reconcile" && state == "succeeded" {
					if e := m.resolveRuleTask(tx, c, result); e != nil {
						return e
					}
				}
				if v.Origin != "local" {
					if e = tx.Bucket([]byte("task_receipts")).Put([]byte(c.ID), []byte{1}); e != nil {
						return e
					}
				}
				return appendAudit(tx, LocalAudit{Username: v.Origin, Action: "task." + state + "." + c.Kind, RequestID: c.ID, CreatedAt: now, ExpiresAt: now.AddDate(0, 0, 180)})
			})
			if e != nil {
				return e
			}
			telemetry.CommandDuration.WithLabelValues(c.Kind).Observe(time.Since(started).Seconds())
			telemetry.CommandResults.WithLabelValues(c.Kind, state).Inc()
		}
	}
}
func (m *TaskManager) Pending() ([][]byte, error) {
	out := [][]byte{}
	e := m.WAL.DB.View(func(tx *bolt.Tx) error {
		cursor := tx.Bucket([]byte("task_receipts")).Cursor()
		for k, _ := cursor.First(); k != nil && len(out) < 32; k, _ = cursor.Next() {
			v := tx.Bucket([]byte("sensor_tasks")).Get(k)
			var task LocalTask
			if e := json.Unmarshal(v, &task); e != nil {
				return e
			}
			if !task.Acknowledged && len(out) < 32 {
				raw, e := json.Marshal(task.Receipt)
				if e != nil {
					return e
				}
				out = append(out, raw)
			}
		}
		return nil
	})
	return out, e
}
func (m *TaskManager) Confirm(id string, receiptHash []byte) error {
	return m.WAL.DB.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("sensor_tasks"))
		raw := b.Get([]byte(id))
		if raw == nil {
			return errors.New("回执任务不存在")
		}
		var v LocalTask
		if e := json.Unmarshal(raw, &v); e != nil {
			return e
		}
		receipt, e := json.Marshal(v.Receipt)
		if e != nil {
			return e
		}
		// 较早的 running ACK 不可回收随后产生的完成回执。
		if !bytes.Equal(receiptHash, control.HashBytes(receipt)) {
			return nil
		}
		v.Acknowledged = true
		// 中断的规则安装仍需原签名载荷核实，平台 ACK 不能销毁恢复依据。
		if v.Receipt.State != "running" && !(v.Receipt.State == "unknown" && v.Command.Kind == "rules.apply") {
			v.Command.Payload = nil
		}
		if e = m.putTask(tx, v); e != nil {
			return e
		}
		return tx.Bucket([]byte("task_receipts")).Delete([]byte(id))
	})
}

type LocalTaskSummary struct {
	Origin             string          `json:"origin"`
	ID                 string          `json:"id"`
	SensorID           string          `json:"sensor_id"`
	Kind               string          `json:"kind"`
	State              string          `json:"state"`
	CreatedAt          time.Time       `json:"created_at"`
	ExpiresAt          time.Time       `json:"expires_at"`
	Acknowledged       bool            `json:"acknowledged"`
	Receipt            control.Receipt `json:"receipt"`
	RuleResolution     json.RawMessage `json:"rule_resolution,omitempty"`
	RetainUntil        time.Time       `json:"retain_until"`
	RetentionProtected bool            `json:"retention_protected"`
}

func localTaskRetention(task LocalTask) time.Time {
	if !task.RetainUntil.IsZero() {
		return task.RetainUntil
	}
	return task.Receipt.StartedAt.AddDate(0, 0, 180)
}

func localTaskProtected(task LocalTask) bool {
	return !task.Acknowledged || task.Receipt.State == "running" || task.Receipt.State == "unknown" && len(task.RuleResolution) == 0
}

func summarizeLocalTask(row LocalTask) LocalTaskSummary {
	origin := row.Origin
	if origin == "" {
		origin = "platform"
	}
	return LocalTaskSummary{Origin: origin, ID: row.Command.ID, SensorID: row.Command.SensorID, Kind: row.Command.Kind, State: row.Receipt.State, CreatedAt: row.Command.IssuedAt, ExpiresAt: row.Command.ExpiresAt, Acknowledged: row.Acknowledged, Receipt: row.Receipt, RuleResolution: row.RuleResolution, RetainUntil: localTaskRetention(row), RetentionProtected: localTaskProtected(row)}
}

func (m *TaskManager) validateLocalTask(row LocalTask, id string) error {
	digest, err := hex.DecodeString(row.SHA256)
	if !contract.ValidID(id) || err != nil || len(digest) != 32 || hex.EncodeToString(digest) != row.SHA256 || row.Command.ID != id || row.Command.TenantID != m.WAL.TenantID || row.Command.SensorID != m.WAL.SensorID || row.Command.RegistrationID != m.WAL.RegistrationID || row.Receipt.CommandID != id || row.Receipt.CommandSHA256 != row.SHA256 || row.Receipt.StartedAt.IsZero() || row.Command.IssuedAt.IsZero() || !row.Command.ExpiresAt.After(row.Command.IssuedAt) || !localTaskRetention(row).After(row.Receipt.StartedAt) {
		return errors.New("本地任务身份或回执绑定不一致")
	}
	if row.Origin != "" && row.Origin != "platform" && row.Origin != "local" || row.Origin == "local" && (row.Command.Kind != "rules.replay" || !strings.HasPrefix(id, "localtask_")) {
		return errors.New("本地任务来源不一致")
	}
	switch row.Command.Kind {
	case "diagnostics", "capture.configure", "applications.apply", "rules.validate", "rules.replay", "rules.apply", "rules.reconcile", "response.block", "response.read", "response.revoke":
	default:
		return errors.New("本地任务类型无效")
	}
	switch row.Receipt.State {
	case "running", "succeeded", "failed", "unknown":
	default:
		return errors.New("本地任务回执状态无效")
	}
	if row.Receipt.State != "running" && (row.Receipt.FinishedAt == nil || row.Receipt.FinishedAt.Before(row.Receipt.StartedAt)) {
		return errors.New("本地任务结束回执不完整")
	}
	return nil
}

// Task 按主键读取已留存档案，不返回签名命令载荷，也不重新执行任务。
func (m *TaskManager) Task(id string) (LocalTaskSummary, error) {
	var out LocalTaskSummary
	if !contract.ValidID(id) {
		return out, ErrLocalTaskNotFound
	}
	err := m.WAL.DB.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("sensor_tasks"))
		if bucket == nil {
			return errors.New("本地任务存储不可用")
		}
		raw := bucket.Get([]byte(id))
		if raw == nil {
			return ErrLocalTaskNotFound
		}
		var row LocalTask
		if err := json.Unmarshal(raw, &row); err != nil {
			return err
		}
		if err := m.validateLocalTask(row, id); err != nil {
			return err
		}
		if !localTaskRetention(row).After(time.Now().UTC()) && !localTaskProtected(row) {
			return ErrLocalTaskNotFound
		}
		out = summarizeLocalTask(row)
		return nil
	})
	return out, err
}

func (m *TaskManager) List() ([]LocalTaskSummary, error) {
	out := []LocalTaskSummary{}
	e := m.WAL.DB.View(func(tx *bolt.Tx) error {
		c := tx.Bucket([]byte("task_history")).Cursor()
		// 只读列表限制扫描预算；指定档案不受近期列表窗口影响。
		scanned := 0
		for k, id := c.Last(); k != nil && len(out) < 200 && scanned < 1000; k, id = c.Prev() {
			scanned++
			v := tx.Bucket([]byte("sensor_tasks")).Get(id)
			var row LocalTask
			if e := json.Unmarshal(v, &row); e != nil {
				return e
			}
			if localTaskRetention(row).After(time.Now().UTC()) || localTaskProtected(row) {
				out = append(out, summarizeLocalTask(row))
			}
		}
		return nil
	})
	return out, e
}

func taskIndex(v LocalTask) []byte {
	return append(key(uint64(v.Receipt.StartedAt.UnixNano())), []byte(v.Command.ID)...)
}
func taskSize(raw []byte, state string) uint64 {
	n := uint64(len(raw))
	if state == "running" {
		n += 72 * 1024
	}
	return n
}
func (m *TaskManager) putTask(tx *bolt.Tx, v LocalTask) error {
	b := tx.Bucket([]byte("sensor_tasks"))
	id := []byte(v.Command.ID)
	raw, e := json.Marshal(v)
	if e != nil {
		return e
	}
	meta := tx.Bucket([]byte("meta"))
	used := uintValue(meta.Get([]byte("task_bytes")))
	if previous := b.Get(id); previous != nil {
		var old LocalTask
		if e = json.Unmarshal(previous, &old); e != nil {
			return e
		}
		size := taskSize(previous, old.Receipt.State)
		if size > used {
			return errors.New("任务容量账目不一致")
		}
		used -= size
	}
	size := taskSize(raw, v.Receipt.State)
	if size > m.MaxBytes || used > m.MaxBytes-size {
		return errors.New("本地任务存储额度已满")
	}
	if e = b.Put(id, raw); e != nil {
		return e
	}
	if e = tx.Bucket([]byte("task_history")).Put(taskIndex(v), id); e != nil {
		return e
	}
	return meta.Put([]byte("task_bytes"), key(used+size))
}
func (m *TaskManager) prune(tx *bolt.Tx, now time.Time) error {
	return m.pruneWithContext(context.Background(), tx, now)
}

// SubmitLocal 仅由已经验证本地管理员会话的处理器调用，不绕过平台命令验签入口。
func (m *TaskManager) SubmitLocal(payload json.RawMessage, key string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	digest := control.Digest(payload)
	id := ""
	idKey := "localtask_" + control.Digest([]byte(key))[:32]
	e := m.WAL.DB.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket([]byte("sensor_tasks")).Get([]byte(idKey))
		if raw == nil {
			return nil
		}
		var task LocalTask
		if e := json.Unmarshal(raw, &task); e != nil {
			return e
		}
		if task.Origin != "local" || task.SHA256 != digest {
			return errors.New("幂等键对应不同重放参数")
		}
		id = task.Command.ID
		return nil
	})
	if e != nil {
		return "", e
	}
	if id != "" {
		return id, nil
	}
	now := time.Now().UTC()
	c := control.Command{ID: "localtask_" + control.Digest([]byte(key))[:32], TenantID: m.WAL.TenantID, SensorID: m.WAL.SensorID, RegistrationID: m.WAL.RegistrationID, Kind: "rules.replay", IssuedAt: now, ExpiresAt: now.Add(30 * time.Minute), Payload: payload}
	if e = control.Validate(c); e != nil {
		return "", e
	}
	if e = m.accept(c, digest, "local"); e != nil {
		return "", e
	}
	return c.ID, nil
}
