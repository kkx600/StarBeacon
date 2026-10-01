package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	bolt "go.etcd.io/bbolt"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/control"
)

type taskTestRunner struct {
	calls  atomic.Int32
	finish chan struct{}
}

func TestTaskRestartDoesNotExecuteUncertainCommand(t *testing.T) {
	w, e := OpenWAL(filepath.Join(t.TempDir(), "agent.db"), "tenant_a", "sensor_a", "reg_a", 4*1024*1024)
	if e != nil {
		t.Fatal(e)
	}
	defer w.Close()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	runner := &taskTestRunner{finish: make(chan struct{})}
	manager, e := NewTaskManager(w, pub, runner)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC()
	raw, sig, e := control.Encode(control.Command{ID: "task_crash", TenantID: "tenant_a", SensorID: "sensor_a", RegistrationID: "reg_a", Kind: "diagnostics", IssuedAt: now, ExpiresAt: now.Add(time.Minute), Payload: json.RawMessage(`{}`)}, priv)
	if e != nil {
		t.Fatal(e)
	}
	if e = manager.Accept(raw, sig); e != nil {
		t.Fatal(e)
	}
	recovered, e := NewTaskManager(w, pub, runner)
	if e != nil {
		t.Fatal(e)
	}
	if e = recovered.Accept(raw, sig); e != nil {
		t.Fatal(e)
	}
	rows, e := recovered.List()
	if e != nil || len(rows) != 1 || rows[0].Receipt.State != "unknown" {
		t.Fatal("未完成任务恢复状态错误", rows, e)
	}
	if len(recovered.queue) != 0 || runner.calls.Load() != 0 {
		t.Fatal("崩溃后盲目重放了未确认任务")
	}
}

func TestTaskQuotaIsAtomicAndReservesReceiptSpace(t *testing.T) {
	w, e := OpenWAL(filepath.Join(t.TempDir(), "agent.db"), "tenant_a", "sensor_a", "reg_a", 4*1024*1024)
	if e != nil {
		t.Fatal(e)
	}
	defer w.Close()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	manager, e := NewTaskManager(w, pub, &taskTestRunner{finish: make(chan struct{})})
	if e != nil {
		t.Fatal(e)
	}
	manager.MaxBytes = 1024
	now := time.Now().UTC()
	raw, sig, e := control.Encode(control.Command{ID: "task_quota", TenantID: "tenant_a", SensorID: "sensor_a", RegistrationID: "reg_a", Kind: "diagnostics", IssuedAt: now, ExpiresAt: now.Add(time.Minute), Payload: json.RawMessage(`{}`)}, priv)
	if e != nil {
		t.Fatal(e)
	}
	if e = manager.Accept(raw, sig); e == nil {
		t.Fatal("任务未预留完成回执容量")
	}
	rows, e := manager.List()
	if e != nil || len(rows) != 0 {
		t.Fatal("额度拒绝后留下部分任务")
	}
	pending, e := manager.Pending()
	if e != nil || len(pending) != 0 || len(manager.queue) != 0 {
		t.Fatal("额度拒绝后留下部分回执或执行")
	}
	var used uint64
	if e = w.DB.View(func(tx *bolt.Tx) error {
		used = uintValue(tx.Bucket([]byte("meta")).Get([]byte("task_bytes")))
		return nil
	}); e != nil || used != 0 {
		t.Fatal("任务额度账目未回滚")
	}
}

func (r *taskTestRunner) Execute(ctx context.Context, c control.Command) (json.RawMessage, string, error) {
	r.calls.Add(1)
	select {
	case <-r.finish:
		return json.RawMessage(`{"ok":true}`), "", nil
	case <-ctx.Done():
		return nil, "cancelled", ctx.Err()
	}
}
func TestTaskReplayAndPreciseReceiptACK(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.db")
	wal, e := OpenWAL(path, "tenant_a", "sensor_a", "reg_a", 4*1024*1024)
	if e != nil {
		t.Fatal(e)
	}
	defer wal.Close()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	runner := &taskTestRunner{finish: make(chan struct{})}
	manager, e := NewTaskManager(wal, pub, runner)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- manager.Run(ctx) }()
	now := time.Now().UTC()
	raw, sig, e := control.Encode(control.Command{ID: "task_a", TenantID: "tenant_a", SensorID: "sensor_a", RegistrationID: "reg_a", Kind: "diagnostics", IssuedAt: now, ExpiresAt: now.Add(time.Minute), Payload: json.RawMessage(`{}`)}, priv)
	if e != nil {
		t.Fatal(e)
	}
	if e = manager.Accept(raw, sig); e != nil {
		t.Fatal(e)
	}
	running, e := manager.Pending()
	if e != nil || len(running) != 1 {
		t.Fatal("开始回执未持久化")
	}
	if e = manager.Accept(raw, sig); e != nil {
		t.Fatal(e)
	}
	close(runner.finish)
	deadline := time.Now().Add(2 * time.Second)
	var terminal [][]byte
	for time.Now().Before(deadline) {
		terminal, e = manager.Pending()
		if e != nil {
			t.Fatal(e)
		}
		if len(terminal) == 1 {
			var r control.Receipt
			_ = json.Unmarshal(terminal[0], &r)
			if r.State == "succeeded" {
				break
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	if runner.calls.Load() != 1 {
		t.Fatal("重复命令重复执行")
	}
	if len(terminal) != 1 {
		t.Fatal("完成回执未产生")
	}
	var final control.Receipt
	if e = json.Unmarshal(terminal[0], &final); e != nil || final.State != "succeeded" {
		t.Fatal("执行未在期限内完成", e)
	}
	if e = manager.Confirm("task_a", control.HashBytes(running[0])); e != nil {
		t.Fatal(e)
	}
	pending, e := manager.Pending()
	if e != nil || len(pending) != 1 {
		t.Fatal("开始 ACK 回收了完成回执")
	}
	if e = manager.Confirm("task_a", control.HashBytes(terminal[0])); e != nil {
		t.Fatal(e)
	}
	pending, e = manager.Pending()
	if e != nil || len(pending) != 0 {
		t.Fatal("准确 ACK 未确认完成回执")
	}
	cancel()
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	if e = manager.Accept(raw, sig); e != nil {
		t.Fatal(e)
	}
	if runner.calls.Load() != 1 {
		t.Fatal("已完成任务重复执行")
	}
}
