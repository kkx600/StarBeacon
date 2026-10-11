package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func storedTaskCount(t *testing.T, m *TaskManager) int {
	t.Helper()
	n := 0
	if err := m.WAL.DB.View(func(tx *bolt.Tx) error {
		n = tx.Bucket([]byte("sensor_tasks")).Stats().KeyN
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestTaskSweepProgressSurvivesRestartAndProtectedPrefix(t *testing.T) {
	m, _ := taskFixture(t, terminalRunner{})
	old := time.Now().UTC().AddDate(0, 0, -181)
	for i := 0; i < 230; i++ {
		row := archivedLocalTask(m, fmt.Sprintf("task_pending_%03d", i), old.Add(time.Duration(i)*time.Second))
		row.Acknowledged = false
		saveArchivedTask(t, m, row)
	}
	for i := 0; i < 105; i++ {
		saveArchivedTask(t, m, archivedLocalTask(m, fmt.Sprintf("task_expired_%03d", i), old.Add(time.Duration(i+230)*time.Second)))
	}
	fresh := archivedLocalTask(m, "task_fresh", time.Now().UTC().Add(-time.Hour))
	saveArchivedTask(t, m, fresh)
	if err := m.Sweep(context.Background()); err != nil || storedTaskCount(t, m) != 336 {
		t.Fatal("保护记录被清理或扫描预算失效", err)
	}
	recovered, err := NewTaskManager(m.WAL, m.PublicKey, terminalRunner{})
	if err != nil {
		t.Fatal(err)
	}
	if err = recovered.Sweep(context.Background()); err != nil || storedTaskCount(t, recovered) != 236 {
		t.Fatal("重启后的保护前缀阻断了后续到期档案，或相邻记录被遗漏", err)
	}
	if err = recovered.Sweep(context.Background()); err != nil || storedTaskCount(t, recovered) != 231 {
		t.Fatal("清理没有继续完成余下的到期档案", err)
	}
	for _, id := range []string{"task_pending_000", "task_pending_229", "task_fresh"} {
		if _, err := recovered.Task(id); err != nil {
			t.Fatal("保护或有效任务丢失", id, err)
		}
	}
	if len(m.queue) != 0 || len(recovered.queue) != 0 {
		t.Fatal("维护过程重新入队了历史任务")
	}
	if err = m.WAL.DB.View(func(tx *bolt.Tx) error {
		var expected uint64
		if err := tx.Bucket([]byte("sensor_tasks")).ForEach(func(_, raw []byte) error {
			var row LocalTask
			if err := json.Unmarshal(raw, &row); err != nil {
				return err
			}
			expected += taskSize(raw, row.Receipt.State)
			return nil
		}); err != nil {
			return err
		}
		if expected != uintValue(tx.Bucket([]byte("meta")).Get([]byte("task_bytes"))) || tx.Bucket([]byte("task_history")).Stats().KeyN != 231 {
			t.Fatal("历史索引或存储容量账目不一致")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestTaskSweepPreservesFrozenPolicyAndConfirmationEvidence(t *testing.T) {
	m, _ := taskFixture(t, terminalRunner{})
	m.RetentionDays = 1
	now := time.Now().UTC()
	for _, state := range []string{"running", "unknown", "failed", "succeeded"} {
		row := archivedLocalTask(m, "task_protected_"+state, now.AddDate(0, 0, -181))
		row.Receipt.State = state
		row.Acknowledged = state == "running" || state == "unknown"
		if state == "running" {
			row.Receipt.FinishedAt = nil
		}
		saveArchivedTask(t, m, row)
	}
	keep := archivedLocalTask(m, "task_seven_days", now.AddDate(0, 0, -2))
	keep.RetainUntil = keep.Receipt.StartedAt.AddDate(0, 0, 7)
	saveArchivedTask(t, m, keep)
	expired := archivedLocalTask(m, "task_elapsed_seven_days", now.AddDate(0, 0, -8))
	expired.RetainUntil = expired.Receipt.StartedAt.AddDate(0, 0, 7)
	saveArchivedTask(t, m, expired)
	if err := m.WAL.DB.Update(func(tx *bolt.Tx) error {
		for _, id := range []string{expired.Command.ID, "task_protected_succeeded"} {
			if err := tx.Bucket([]byte("task_receipts")).Put([]byte(id), []byte{1}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := m.Sweep(context.Background()); err != nil || storedTaskCount(t, m) != 5 {
		t.Fatal("清理使用当前策略改写了冻结期限，或销毁了未确认结果", err)
	}
	for _, id := range []string{keep.Command.ID, "task_protected_running", "task_protected_unknown", "task_protected_failed", "task_protected_succeeded"} {
		if _, err := m.Task(id); err != nil {
			t.Fatal("受保护档案无法追溯", id, err)
		}
	}
	if err := m.WAL.DB.View(func(tx *bolt.Tx) error {
		if tx.Bucket([]byte("task_receipts")).Get([]byte(expired.Command.ID)) != nil || tx.Bucket([]byte("task_receipts")).Get([]byte("task_protected_succeeded")) == nil {
			t.Fatal("清理损坏了仍需上传的回执索引")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestTaskSweepRollsBackCorruptionAndPartialAccounting(t *testing.T) {
	for _, damage := range []string{"json", "binding", "index", "partial_accounting"} {
		t.Run(damage, func(t *testing.T) {
			m, _ := taskFixture(t, terminalRunner{})
			old := time.Now().UTC().AddDate(0, 0, -181)
			for i := 0; i < 2; i++ {
				saveArchivedTask(t, m, archivedLocalTask(m, fmt.Sprintf("task_atomic_%d", i), old.Add(time.Duration(i)*time.Second)))
			}
			if err := m.WAL.DB.Update(func(tx *bolt.Tx) error {
				tasks := tx.Bucket([]byte("sensor_tasks"))
				switch damage {
				case "json":
					return tasks.Put([]byte("task_atomic_1"), []byte("{"))
				case "binding":
					var row LocalTask
					if err := json.Unmarshal(tasks.Get([]byte("task_atomic_1")), &row); err != nil {
						return err
					}
					row.Command.TenantID = "tenant_other"
					raw, _ := json.Marshal(row)
					return tasks.Put([]byte("task_atomic_1"), raw)
				case "index":
					cursor := tx.Bucket([]byte("task_history")).Cursor()
					k, _ := cursor.First()
					return tx.Bucket([]byte("task_history")).Put(k, []byte("task_atomic_1"))
				default:
					raw := tasks.Get([]byte("task_atomic_0"))
					return tx.Bucket([]byte("meta")).Put([]byte("task_bytes"), key(uint64(len(raw))+1))
				}
			}); err != nil {
				t.Fatal(err)
			}
			before := walState(t, m.WAL)
			if err := m.Sweep(context.Background()); err == nil || walState(t, m.WAL) != before {
				t.Fatal("失败清理没有回滚档案、索引、续点与账目", err)
			}
		})
	}
}

func TestTaskSweepCancellationWhileWaitingForWriter(t *testing.T) {
	m, _ := taskFixture(t, terminalRunner{})
	saveArchivedTask(t, m, archivedLocalTask(m, "task_cancelled", time.Now().UTC().AddDate(0, 0, -181)))
	before := walState(t, m.WAL)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := m.Sweep(ctx); !errors.Is(err, context.Canceled) || walState(t, m.WAL) != before {
		t.Fatal("已取消维护仍改写存储", err)
	}
	writer, err := m.WAL.DB.Begin(true)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	started := make(chan struct{})
	go func() {
		close(started)
		result <- m.Sweep(ctx)
	}()
	<-started
	select {
	case err := <-result:
		_ = writer.Rollback()
		t.Fatal("维护绕过现有写事务", err)
	case <-time.After(15 * time.Millisecond):
	}
	cancel()
	if err := writer.Rollback(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) || walState(t, m.WAL) != before {
			t.Fatal("等待写锁后取消没有阻止提交", err)
		}
	case <-time.After(time.Second):
		t.Fatal("取消维护在写锁释放后未退出")
	}
}

func TestTaskRetentionRunsWithoutIncomingTasksAndRecoversStorageFailure(t *testing.T) {
	m, _ := taskFixture(t, terminalRunner{})
	row := archivedLocalTask(m, "task_idle_retention", time.Now().UTC().AddDate(0, 0, -181))
	saveArchivedTask(t, m, row)
	raw, _ := json.Marshal(row)
	if err := m.WAL.DB.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("sensor_tasks")).Put([]byte(row.Command.ID), []byte("{"))
	}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- m.runRetention(ctx, 5*time.Millisecond) }()
	wait := func(ready func() bool) {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			if ready() {
				return
			}
			time.Sleep(time.Millisecond)
		}
		t.Fatal("周期维护没有达到预期状态")
	}
	failure := func() bool {
		m.WAL.mu.RLock()
		defer m.WAL.mu.RUnlock()
		return m.WAL.failures["task_history_cleanup_unavailable"]
	}
	wait(failure)
	if err := m.WAL.DB.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte("sensor_tasks")).Put([]byte(row.Command.ID), raw) }); err != nil {
		t.Fatal(err)
	}
	wait(func() bool { return storedTaskCount(t, m) == 0 && !failure() })
	if len(m.queue) != 0 {
		t.Fatal("空闲维护重新执行了历史任务")
	}
	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal("维护取消导致采集器错误退出", err)
		}
	case <-time.After(time.Second):
		t.Fatal("周期维护没有随采集器停止")
	}
	if err := m.RunRetention(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestTaskSweepMissingBucketsAndClosedStorage(t *testing.T) {
	for _, bucket := range []string{"task_history", "sensor_tasks", "task_receipts", "meta"} {
		t.Run(bucket, func(t *testing.T) {
			m, _ := taskFixture(t, terminalRunner{})
			if err := m.WAL.DB.Update(func(tx *bolt.Tx) error { return tx.DeleteBucket([]byte(bucket)) }); err != nil {
				t.Fatal(err)
			}
			if err := m.Sweep(context.Background()); err == nil {
				t.Fatal("缺失存储桶被当作清理成功")
			}
		})
	}
	m, _ := taskFixture(t, terminalRunner{})
	if err := m.WAL.Close(); err != nil {
		t.Fatal(err)
	}
	if err := m.Sweep(context.Background()); err == nil {
		t.Fatal("关闭存储仍执行维护")
	}
}
