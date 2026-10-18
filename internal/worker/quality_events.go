package worker

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/notify"
	"github.com/kkx600/StarBeacon/internal/qualityevent"
	"github.com/kkx600/StarBeacon/internal/store"
)

// ProcessQuality 先确认不可变索引，再确认持久通知流；结果未知时使用原事件键重试。
func (w *Indexer) ProcessQuality(ctx context.Context, l store.QualityLease) error {
	e, err := qualityevent.Decode(l.Document)
	if err != nil || e.ID != l.ID || e.TenantID != l.TenantID || l.Partition != e.CreatedAt.UTC().Format("2006-01-02") || !time.Now().Before(l.ExpiresAt) {
		return qualityevent.ErrEvent
	}
	index, err := contract.IndexName(l.TenantID, "context", l.Partition)
	if err != nil {
		return err
	}
	days := 180
	if !w.ES.IndexKnown(index) {
		days, err = w.DB.EventRetention(ctx, l.TenantID, "context")
		if err != nil {
			return err
		}
	}
	if err = w.ES.EnsureIndexRetention(ctx, index, l.Partition, days); err != nil {
		return err
	}
	results := w.ES.Bulk(ctx, index, []model.Alert{l.Document})
	if len(results) != 1 {
		return qualityevent.ErrEvent
	}
	if results[0] != nil {
		return results[0]
	}
	return w.Bus.Publish(ctx, "sb.indexed", "quality:"+e.ID, map[string]any{"tenant_id": e.TenantID, "batch_id": "quality_" + e.ID[:56], "quality": []notify.QualitySummary{notify.QualityFrom(e)}})
}

func (w *Indexer) qualityLoop(ctx context.Context) error {
	cursor := ""
	slots := make(chan struct{}, 8)
	var pending sync.WaitGroup
	defer pending.Wait()
	for ctx.Err() == nil {
		call, cancel := context.WithTimeout(ctx, 5*time.Second)
		tenants, err := w.DB.NotificationTenants(call, cursor)
		cancel()
		if err == nil {
			complete := true
			for _, tenant := range tenants {
				select {
				case slots <- struct{}{}:
				default:
					complete = false
				}
				if !complete {
					break
				}
				cursor = tenant
				call, cancel := context.WithTimeout(ctx, 5*time.Second)
				lease, leaseErr := w.DB.LeaseQuality(call, tenant)
				cancel()
				if lease.ID == "" {
					<-slots
					if leaseErr != nil {
						slog.Warn("探针质量待办暂不可读取")
					}
					continue
				}
				pending.Go(func() {
					defer func() { <-slots }()
					work, stop := context.WithTimeout(ctx, 20*time.Second)
					err := leaseErr
					if err == nil {
						err = w.ProcessQuality(work, lease)
					}
					stop()
					finish, done := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
					defer done()
					if w.DB.FinishQuality(finish, lease, err == nil) != nil || err != nil {
						slog.Warn("探针质量事件索引或通知受理待重试")
					}
				})
			}
			if complete && len(tenants) < 100 {
				cursor = ""
			}
		} else {
			slog.Warn("探针质量调度暂不可用")
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(200 * time.Millisecond):
		}
	}
	return nil
}
