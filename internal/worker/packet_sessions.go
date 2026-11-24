package worker

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/kkx600/StarBeacon/internal/store"
)

func (w *Indexer) projectPacketSessions(ctx context.Context, tenant string) error {
	return w.DB.ProjectPacketSessions(ctx, tenant, func(batch store.PacketSessionBatch) error {
		if err := w.ES.EnsureIndex(ctx, batch.Index, batch.Partition); err != nil {
			return err
		}
		return errors.Join(w.ES.Bulk(ctx, batch.Index, batch.Documents)...)
	})
}

func (w *Indexer) packetSessionsLoop(ctx context.Context) error {
	tenants := make(chan string, 4)
	var active sync.WaitGroup
	for range cap(tenants) {
		active.Go(func() {
			for tenant := range tenants {
				work, cancel := context.WithTimeout(ctx, 20*time.Second)
				err := w.projectPacketSessions(work, tenant)
				cancel()
				if err != nil && ctx.Err() == nil {
					slog.Warn("会话分段索引待重试", "tenant_id", tenant, "error", err)
				}
			}
		})
	}
	defer func() {
		close(tenants)
		active.Wait()
	}()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	cursor := ""
	for ctx.Err() == nil {
		call, cancel := context.WithTimeout(ctx, 5*time.Second)
		page, err := w.DB.NotificationTenants(call, cursor)
		cancel()
		if err != nil && ctx.Err() == nil {
			slog.Warn("会话分段待办暂不可读取")
		}
		for _, tenant := range page {
			select {
			case tenants <- tenant:
				cursor = tenant
			case <-ctx.Done():
				return nil
			}
		}
		if err == nil && len(page) < 100 {
			cursor = ""
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
	return nil
}
