package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Sweep 回收已经到期且结束确认的档案；读时过滤不能代替存储回收。
func (m *TaskManager) Sweep(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return m.WAL.DB.Update(func(tx *bolt.Tx) error {
		return m.pruneWithContext(ctx, tx, time.Now().UTC())
	})
}

func (m *TaskManager) pruneWithContext(ctx context.Context, tx *bolt.Tx, now time.Time) error {
	index, tasks, receipts, meta := tx.Bucket([]byte("task_history")), tx.Bucket([]byte("sensor_tasks")), tx.Bucket([]byte("task_receipts")), tx.Bucket([]byte("meta"))
	if index == nil || tasks == nil || receipts == nil || meta == nil {
		return errors.New("本地任务清理存储不可用")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	type expiredTask struct {
		index, id []byte
		size      uint64
	}
	expired := make([]expiredTask, 0, 100)
	cursor := index.Cursor()
	k, id := cursor.First()
	if previous := meta.Get([]byte("task_prune_cursor")); len(previous) > 0 {
		k, id = cursor.Seek(previous)
		if bytes.Equal(k, previous) {
			k, id = cursor.Next()
		}
	}
	var last []byte
	for scanned := 0; k != nil && scanned < 200 && len(expired) < 100; scanned++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		var row LocalTask
		raw := tasks.Get(id)
		if err := json.Unmarshal(raw, &row); err != nil {
			return err
		}
		if err := m.validateLocalTask(row, string(id)); err != nil {
			return err
		}
		if !bytes.Equal(k, taskIndex(row)) {
			return errors.New("本地任务历史索引不一致")
		}
		last = bytes.Clone(k)
		if !localTaskRetention(row).After(now) && !localTaskProtected(row) {
			expired = append(expired, expiredTask{index: bytes.Clone(k), id: bytes.Clone(id), size: taskSize(raw, row.Receipt.State)})
		}
		k, id = cursor.Next()
	}
	used := uintValue(meta.Get([]byte("task_bytes")))
	// 扫描结束后按复制的键删除，避免写游标删除后推进而遗漏相邻记录。
	for _, row := range expired {
		if err := ctx.Err(); err != nil {
			return err
		}
		if row.size > used {
			return errors.New("任务容量账目不一致")
		}
		if err := tasks.Delete(row.id); err != nil {
			return err
		}
		if err := index.Delete(row.index); err != nil {
			return err
		}
		if err := receipts.Delete(row.id); err != nil {
			return err
		}
		used -= row.size
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := meta.Put([]byte("task_bytes"), key(used)); err != nil {
		return err
	}
	// 保护记录不能阻止后面的档案清理；续点与删除同事务，重启不从头饥饿扫描。
	if k == nil {
		return meta.Delete([]byte("task_prune_cursor"))
	}
	return meta.Put([]byte("task_prune_cursor"), last)
}

func (m *TaskManager) RunRetention(ctx context.Context) error {
	return m.runRetention(ctx, time.Minute)
}

func (m *TaskManager) runRetention(ctx context.Context, interval time.Duration) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for ctx.Err() == nil {
		call, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := m.Sweep(call)
		cancel()
		if ctx.Err() != nil {
			return nil
		}
		m.WAL.setFailure("task_history_cleanup_unavailable", err != nil)
		if err != nil {
			slog.Warn("本地任务历史清理未完成，请核对设备存储")
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
	return nil
}
