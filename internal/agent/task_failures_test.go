package agent

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

	"github.com/kkx600/StarBeacon/internal/control"
	bolt "go.etcd.io/bbolt"
)

type terminalRunner struct {
	result json.RawMessage
	code   string
	err    error
	before func()
}

func (r terminalRunner) Execute(context.Context, control.Command) (json.RawMessage, string, error) {
	if r.before != nil {
		r.before()
	}
	return r.result, r.code, r.err
}

func taskFixture(t *testing.T, runner TaskRunner) (*TaskManager, ed25519.PrivateKey) {
	t.Helper()
	w, _, _ := readerFor(t, 8*1024*1024)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m, err := NewTaskManager(w, pub, runner)
	if err != nil {
		t.Fatal(err)
	}
	return m, priv
}
func signedFixtureCommand(t *testing.T, m *TaskManager, priv ed25519.PrivateKey, id string, issued time.Time) ([]byte, []byte) {
	t.Helper()
	c := control.Command{ID: id, TenantID: m.WAL.TenantID, SensorID: m.WAL.SensorID, RegistrationID: m.WAL.RegistrationID, Kind: "diagnostics", IssuedAt: issued, ExpiresAt: issued.Add(time.Minute), Payload: json.RawMessage(`{}`)}
	raw, sig, err := control.Encode(c, priv)
	if err != nil {
		t.Fatal(err)
	}
	return raw, sig
}

func TestTaskExecutionFailureStatesAndInvalidResults(t *testing.T) {
	cases := []struct {
		name, state, code string
		runner            terminalRunner
	}{
		{"failure", "failed", "engine_failed", terminalRunner{code: "engine_failed", err: errors.New("engine stopped")}},
		{"uncertain", "unknown", "result_unknown", terminalRunner{code: "result_unknown", err: errors.New("device outcome unknown")}},
		{"empty_success", "succeeded", "", terminalRunner{}},
		{"invalid_json", "failed", "invalid_execution_result", terminalRunner{result: json.RawMessage(`{`)}},
		{"oversized_result", "failed", "invalid_execution_result", terminalRunner{result: json.RawMessage(`"` + strings.Repeat("a", 64*1024) + `"`)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, priv := taskFixture(t, tc.runner)
			raw, sig := signedFixtureCommand(t, m, priv, "task_terminal", time.Now().UTC())
			if err := m.Accept(raw, sig); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- m.Run(ctx) }()
			defer func() {
				cancel()
				if err := <-done; err != nil {
					t.Error(err)
				}
			}()
			deadline := time.Now().Add(2 * time.Second)
			var receipt control.Receipt
			for {
				pending, err := m.Pending()
				if err != nil {
					t.Fatal(err)
				}
				if len(pending) == 1 {
					if err = json.Unmarshal(pending[0], &receipt); err != nil {
						t.Fatal(err)
					}
					if receipt.State != "running" {
						break
					}
				}
				if time.Now().After(deadline) {
					t.Fatal("未收到任务终态")
				}
				time.Sleep(time.Millisecond)
			}
			if receipt.State != tc.state || receipt.Code != tc.code || receipt.FinishedAt == nil || string(receipt.Result) != "{}" {
				t.Fatal("失败或未知结果被伪造为成功", receipt)
			}
			if err := m.Confirm("task_missing", nil); err == nil {
				t.Fatal("不存在的任务被确认")
			}
		})
	}
}

func TestTaskExpiryQueueConflictAndStorageFailure(t *testing.T) {
	m, priv := taskFixture(t, terminalRunner{})
	expired, sig := signedFixtureCommand(t, m, priv, "task_expired", time.Now().UTC().Add(-2*time.Minute))
	if err := m.Accept(expired, sig); err != nil {
		t.Fatal(err)
	}
	rows, err := m.List()
	if err != nil || len(rows) != 1 || rows[0].Receipt.Code != "command_expired" || rows[0].State != "failed" || len(m.queue) != 0 {
		t.Fatal("过期任务未保存明确失败状态", err, rows)
	}
	raw, sig := signedFixtureCommand(t, m, priv, "task_running", time.Now().UTC())
	if err = m.Accept(raw, sig); err != nil {
		t.Fatal(err)
	}
	second, sig2 := signedFixtureCommand(t, m, priv, "task_second", time.Now().UTC())
	if err = m.Accept(second, sig2); err == nil {
		t.Fatal("满队列继续接受任务")
	}
	if err = m.Accept(raw, []byte("bad")); err == nil {
		t.Fatal("无效签名进入任务队列")
	}
	conflict, sig3 := signedFixtureCommand(t, m, priv, "task_running", time.Now().UTC().Add(-time.Second))
	if err = m.Accept(conflict, sig3); err == nil {
		t.Fatal("相同身份不同命令被接受")
	}
	if _, err = m.SubmitLocal(json.RawMessage(`{}`), "invalid_replay"); err == nil {
		t.Fatal("本地提交绕过重放参数校验")
	}
	payload, _ := control.ReplayPayload(control.Replay{SampleID: "sample_bound", SampleSHA256: control.Digest([]byte("pcap")), SampleSize: 24, RuleMode: "registered"})
	if _, err = m.SubmitLocal(payload, "queue_full"); err == nil {
		t.Fatal("本地任务绕过满队列")
	}
	if err = m.WAL.DB.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte("meta")).Put([]byte("task_bytes"), key(0)) }); err != nil {
		t.Fatal(err)
	}
	if err = m.Accept(raw, sig); err == nil {
		t.Fatal("任务账目不一致仍重新接受")
	}
	m2, _ := taskFixture(t, terminalRunner{})
	if err = m2.WAL.DB.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte("sensor_tasks")).Put([]byte("damaged"), []byte("{")) }); err != nil {
		t.Fatal(err)
	}
	if _, err = NewTaskManager(m2.WAL, m2.PublicKey, m2.Runner); err == nil {
		t.Fatal("损坏历史任务被静默丢弃")
	}
}

func TestTaskHistoryPrunesOnlyConfirmedTerminalTasksWithinBudget(t *testing.T) {
	m, priv := taskFixture(t, terminalRunner{})
	now := time.Now().UTC()
	old := now.AddDate(0, 0, -181)
	if err := m.WAL.DB.Update(func(tx *bolt.Tx) error {
		for i := 0; i < 110; i++ {
			id := fmt.Sprintf("task_old_%03d", i)
			v := archivedLocalTask(m, id, old.Add(time.Duration(i)*time.Second))
			if err := m.putTask(tx, v); err != nil {
				return err
			}
		}
		for i, state := range []string{"running", "unknown", "failed"} {
			id := "task_protect_" + state
			v := archivedLocalTask(m, id, old.Add(-time.Duration(i+1)*time.Second))
			v.Receipt.State, v.Acknowledged = state, state != "failed"
			if state == "running" {
				v.Receipt.FinishedAt = nil
			}
			if err := m.putTask(tx, v); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	raw, sig := signedFixtureCommand(t, m, priv, "task_trigger_gc", now)
	if err := m.Accept(raw, sig); err != nil {
		t.Fatal(err)
	}
	rows, err := m.List()
	if err != nil || len(rows) != 4 {
		t.Fatal("列表仍展示已到期且可清理的任务", len(rows), err)
	}
	if err = m.WAL.DB.View(func(tx *bolt.Tx) error {
		if tx.Bucket([]byte("sensor_tasks")).Stats().KeyN != 14 {
			t.Fatal("有界清理未删除恰好 100 条历史任务")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"task_protect_running", "task_protect_unknown", "task_protect_failed"} {
		found := false
		for _, row := range rows {
			found = found || row.ID == id
		}
		if !found {
			t.Fatal("未确认、未知或执行中的任务被删除", id)
		}
	}
	if err = m.WAL.DB.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte("meta")).Put([]byte("task_bytes"), key(0)) }); err != nil {
		t.Fatal(err)
	}
	if err = m.WAL.DB.Update(func(tx *bolt.Tx) error { return m.prune(tx, time.Now()) }); err == nil {
		t.Fatal("不一致容量账目仍进行历史删除")
	}
}

func TestTaskCorruptReceiptsAndCompletionWritesFailClosed(t *testing.T) {
	for _, mode := range []string{"receipt_json", "completion_json", "completion_quota"} {
		t.Run(mode, func(t *testing.T) {
			m, priv := taskFixture(t, terminalRunner{})
			raw, sig := signedFixtureCommand(t, m, priv, "task_corrupt", time.Now().UTC())
			if err := m.Accept(raw, sig); err != nil {
				t.Fatal(err)
			}
			damage := func() {
				err := m.WAL.DB.Update(func(tx *bolt.Tx) error {
					if mode == "completion_quota" {
						return tx.Bucket([]byte("meta")).Put([]byte("task_bytes"), key(0))
					}
					return tx.Bucket([]byte("sensor_tasks")).Put([]byte("task_corrupt"), []byte("{"))
				})
				if err != nil {
					t.Error(err)
				}
			}
			if mode == "receipt_json" {
				damage()
				if _, err := m.Pending(); err == nil {
					t.Fatal("损坏回执仍上报成功")
				}
				if _, err := m.List(); err == nil {
					t.Fatal("损坏任务被呈现为正常")
				}
				if err := m.Confirm("task_corrupt", nil); err == nil {
					t.Fatal("损坏回执被确认")
				}
				if err := m.Accept(raw, sig); err == nil {
					t.Fatal("损坏重复任务被接受")
				}
				return
			}
			m.Runner = terminalRunner{before: damage}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if err := m.Run(ctx); err == nil {
				t.Fatal("执行结果未持久化仍继续运行")
			}
		})
	}
	t.Run("local_corruption", func(t *testing.T) {
		m, _ := taskFixture(t, terminalRunner{})
		p, _ := control.ReplayPayload(control.Replay{SampleID: "sample_bound", SampleSHA256: control.Digest([]byte("pcap")), SampleSize: 24, RuleMode: "registered"})
		id, err := m.SubmitLocal(p, "bound_key")
		if err != nil {
			t.Fatal(err)
		}
		if err = m.WAL.DB.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte("sensor_tasks")).Put([]byte(id), []byte("{")) }); err != nil {
			t.Fatal(err)
		}
		if _, err = m.SubmitLocal(p, "bound_key"); err == nil {
			t.Fatal("损坏本地幂等索引仍接受重试")
		}
	})
}
