package collectorupdate

import (
	"context"
	"github.com/kkx600/StarBeacon/internal/agent"
)

// GuardData 复用采集器的持久身份、任务和租约契约，检查只在原进程停止后执行。
func GuardData(ctx context.Context, directory string) error {
	return agent.InspectStoppedForUpdate(ctx, directory)
}
