package agent

import (
	"context"
	"encoding/json"
	"github.com/kkx600/StarBeacon/internal/control"
	"path/filepath"
	"testing"
	"time"
)

type localReplayRunner struct{}

func (localReplayRunner) Execute(context.Context, control.Command) (json.RawMessage, string, error) {
	return json.RawMessage(`{"replay":"completed"}`), "", nil
}
func TestLocalReplayIdempotencyAndSeparateOutbox(t *testing.T) {
	wal, e := OpenWAL(filepath.Join(t.TempDir(), "wal.db"), "tenant_test", "sensor_test", "reg_test", 4*1024*1024)
	if e != nil {
		t.Fatal(e)
	}
	defer wal.Close()
	tasks, e := NewTaskManager(wal, nil, localReplayRunner{})
	if e != nil {
		t.Fatal(e)
	}
	p := control.Replay{SampleID: "sample_test", SampleSHA256: control.Digest([]byte("pcap")), SampleSize: 24, RuleMode: "registered"}
	payload, _ := control.ReplayPayload(p)
	id, e := tasks.SubmitLocal(payload, "same_local_request")
	if e != nil {
		t.Fatal(e)
	}
	again, e := tasks.SubmitLocal(payload, "same_local_request")
	if e != nil || id != again {
		t.Fatal("本地重复请求重新创建任务")
	}
	p.SampleSize++
	different, _ := control.ReplayPayload(p)
	if _, e = tasks.SubmitLocal(different, "same_local_request"); e == nil {
		t.Fatal("幂等键参数不一致未拒绝")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- tasks.Run(ctx) }()
	defer func() {
		cancel()
		if e := <-done; e != nil {
			t.Error(e)
		}
	}()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		rows, e := tasks.List()
		if e != nil {
			t.Fatal(e)
		}
		if len(rows) == 1 && rows[0].State == "succeeded" {
			pending, e := tasks.Pending()
			if e != nil || len(pending) != 0 {
				t.Fatal("本地任务进入平台回执队列")
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("本地任务没有完成")
}
