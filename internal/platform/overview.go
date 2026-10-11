package platform

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/kkx600/StarBeacon/internal/analytics"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/redis/go-redis/v9"
	"golang.org/x/sync/errgroup"
)

var errOverviewQuota = errors.New("态势统计请求超出窗口预算")

func (a *API) overview(w http.ResponseWriter, r *http.Request) {
	var window analytics.Window
	if httpapi.Decode(w, r, &window) != nil || window.Validate() != nil {
		httpapi.Fail(w, r, 400, "invalid_window", "请选择不超过 31 天的有效统计时间范围")
		return
	}
	u := httpapi.Principal(r)
	value, err := a.Overview(r.Context(), u, window)
	if errors.Is(err, errOverviewQuota) {
		w.Header().Set("Retry-After", "60")
		httpapi.Fail(w, r, 429, "overview_quota_exceeded", "统计请求过于频繁，请稍后重试")
		return
	}
	if err != nil {
		httpapi.Fail(w, r, 503, "overview_unavailable", "态势统计未能完整返回，请稍后重试")
		return
	}
	httpapi.JSON(w, 200, value)
}

func (a *API) Overview(ctx context.Context, u model.Principal, window analytics.Window) (analytics.Snapshot, error) {
	if err := window.Validate(); err != nil {
		return analytics.Snapshot{}, err
	}
	if a.DB == nil || a.ES == nil {
		return analytics.Snapshot{}, analytics.ErrIncomplete
	}
	work, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	window.Start, window.End = window.Start.UTC(), window.End.UTC()
	raw, _ := json.Marshal(window)
	key := "sb:overview:" + u.TenantID + ":" + u.Role + ":" + control.Digest(raw)
	value, err, _ := a.overviewFlight.Do(key, func() (any, error) { return a.overviewSnapshot(work, u, window, key) })
	if err != nil {
		return analytics.Snapshot{}, err
	}
	return value.(analytics.Snapshot), nil
}

func (a *API) overviewSnapshot(ctx context.Context, u model.Principal, window analytics.Window, key string) (analytics.Snapshot, error) {
	var result analytics.Snapshot
	read := func() (bool, error) {
		if a.Redis == nil {
			return false, nil
		}
		raw, err := a.Redis.Get(ctx, key).Bytes()
		if errors.Is(err, redis.Nil) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if len(raw) > 32768 || json.Unmarshal(raw, &result) != nil || !result.Window.Start.Equal(window.Start) || !result.Window.End.Equal(window.End) || result.Validate() != nil {
			return false, analytics.ErrIncomplete
		}
		return true, nil
	}
	if cached, err := read(); cached || err != nil {
		return result, err
	}
	if a.Redis != nil {
		lockKey, token := key+":lock", store.Token()
		timer := time.NewTicker(100 * time.Millisecond)
		defer timer.Stop()
		for {
			locked, err := a.Redis.SetNX(ctx, lockKey, token, 12*time.Second).Result()
			if err != nil {
				return result, err
			}
			if locked {
				break
			}
			select {
			case <-ctx.Done():
				return result, ctx.Err()
			case <-timer.C:
			}
			if cached, err := read(); cached || err != nil {
				return result, err
			}
		}
		defer func() {
			clean, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_ = a.Redis.Eval(clean, `if redis.call('GET',KEYS[1])==ARGV[1] then return redis.call('DEL',KEYS[1]) else return 0 end`, []string{lockKey}, token).Err()
		}()
		// 相同窗口命中缓存不消耗额度；不同窗口的后台聚合有租户级硬预算。
		quota := "sb:overview:quota:" + u.TenantID + ":" + time.Now().UTC().Format("200601021504")
		count, err := a.Redis.Eval(ctx, `local n=redis.call('INCR',KEYS[1]);if n==1 then redis.call('EXPIRE',KEYS[1],120) end;return n`, []string{quota}).Int64()
		if err != nil {
			return result, err
		}
		if count > 30 {
			return result, errOverviewQuota
		}
	}
	group, work := errgroup.WithContext(ctx)
	result = analytics.Snapshot{Window: window, Limitations: []string{"告警数量表示已索引检测事件，不代表攻击成功或已完成处置。", "趋势按事件时间与 UTC 窗口统计；迟到事件可能改变历史结果。", "Top 10 展示保留其他数量和分布误差上界。", "不同指标的观测时刻可能存在短暂差异。", "当前未计入未采集的流量、应用分类、案件、漏洞和模型研判。"}}
	group.Go(func() error {
		var err error
		result.Events, err = a.ES.OverviewEvents(work, u.TenantID, window)
		return err
	})
	group.Go(func() error {
		var err error
		result.Inventory, err = a.DB.OverviewInventory(work, u.TenantID)
		return err
	})
	if err := group.Wait(); err != nil {
		return analytics.Snapshot{}, err
	}
	result.ObservedAt = time.Now().UTC()
	if a.Redis != nil {
		raw, err := json.Marshal(result)
		if err != nil {
			return analytics.Snapshot{}, err
		}
		if err = a.Redis.Set(ctx, key, raw, 15*time.Second).Err(); err != nil {
			return analytics.Snapshot{}, err
		}
	}
	return result, nil
}
