//go:build integration

package integration

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/bus"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/worker"
	"github.com/nats-io/nats.go/jetstream"
)

func TestIndexerStartupFailureDoesNotLeavePartialConsumption(t *testing.T) {
	if os.Getenv("SB_MODE") != "development" || os.Getenv("SB_NATS_URL") == "" {
		t.Skip("需要独立开发依赖")
	}
	ctx, stop := context.WithTimeout(context.Background(), 20*time.Second)
	defer stop()
	queue, err := bus.OpenNamespace(ctx, os.Getenv("SB_NATS_URL"), store.RandomID("it_startup_"))
	require(t, err)
	t.Cleanup(queue.Close)
	t.Cleanup(func() {
		clean, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for _, name := range []string{bus.Alerts, bus.Context, bus.Quarantine, bus.Indexed} {
			err := queue.JS.DeleteStream(clean, queue.StreamName(name))
			if err != nil && !errors.Is(err, jetstream.ErrStreamNotFound) {
				t.Error("专属流回收失败", err)
			}
		}
	})
	require(t, queue.Ensure(ctx, 1, 1<<20))
	es, err := store.OpenES(os.Getenv("SB_ES_URL"), os.Getenv("SB_ES_API_KEY"))
	require(t, err)
	// 第二条流不可用时，第一条流不得在失败的 Run 返回后继续取走后续数据。
	require(t, queue.JS.DeleteStream(ctx, queue.StreamName(bus.Context)))
	indexer := worker.Indexer{Bus: queue, ES: es}
	if err := indexer.Run(ctx); err == nil || ctx.Err() != nil {
		t.Fatal("缺失上下文流没有及时拒绝启动", err)
	}
	require(t, queue.Publish(ctx, "sb.events.alerts", "startup_after_failure", map[string]string{"owned_fixture": "not_business_eve"}))
	consumer, err := queue.Consumer(ctx, bus.Alerts)
	require(t, err)
	// 观察一个实际拉取等待周期；此处的边界是没有任何未授权后台交付。
	timer := time.NewTimer(1200 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		t.Fatal("验收超时")
	}
	info, err := consumer.Info(ctx)
	require(t, err)
	if info.Delivered.Consumer != 0 || info.NumAckPending != 0 || info.NumPending != 1 {
		t.Fatal("失败启动遗留后台取数", info.Delivered.Consumer, info.NumAckPending, info.NumPending)
	}
}
