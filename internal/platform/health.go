package platform

import (
	"context"
	"sync"
)

func (a *API) dependencyChecks() []func(context.Context) error {
	return []func(context.Context) error{
		a.DB.Pool.Ping,
		func(ctx context.Context) error { return a.Redis.Ping(ctx).Err() },
		a.ES.Ping,
	}
}

func checkDependencies(ctx context.Context, checks []func(context.Context) error) []error {
	results := make([]error, len(checks))
	var workers sync.WaitGroup
	for i, check := range checks {
		// 每个任务独占一个结果槽；Wait 保证发布结果前所有写入均已完成。
		workers.Go(func() { results[i] = check(ctx) })
	}
	workers.Wait()
	return results
}
