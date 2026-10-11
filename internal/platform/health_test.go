package platform

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestDependencyFailureDoesNotConsumeOtherProbeDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	started := make(chan struct{})
	results := checkDependencies(ctx, []func(context.Context) error{
		func(ctx context.Context) error {
			select {
			case <-started:
				return errors.New("存储不可用")
			case <-ctx.Done():
				return ctx.Err()
			}
		},
		func(context.Context) error { close(started); return nil },
	})
	if len(results) != 2 || results[0] == nil || errors.Is(results[0], context.DeadlineExceeded) || results[1] != nil {
		t.Fatalf("单个故障影响了独立依赖：%v", results)
	}
}

func TestDependencyProbesRespectCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	results := checkDependencies(ctx, []func(context.Context) error{
		func(ctx context.Context) error { return ctx.Err() },
		func(context.Context) error { return nil },
	})
	if !errors.Is(results[0], context.Canceled) || results[1] != nil || len(checkDependencies(ctx, nil)) != 0 {
		t.Fatalf("取消状态未准确传播：%v", results)
	}
}
