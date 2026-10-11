package worker

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/bus"
	"github.com/kkx600/StarBeacon/internal/notify"
	"github.com/kkx600/StarBeacon/internal/secrets"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/nats-io/nats.go/jetstream"
	"golang.org/x/sync/errgroup"
)

type Notifier struct {
	Bus    *bus.Bus
	DB     *store.Postgres
	Vault  *secrets.Vault
	Sender notify.Sender
}

func (n *Notifier) Enqueue(ctx context.Context, data []byte) error {
	var batch struct {
		TenantID string           `json:"tenant_id"`
		BatchID  string           `json:"batch_id"`
		Alerts   []notify.Summary `json:"alerts"`
	}
	if len(data) > 4*1024*1024 || json.Unmarshal(data, &batch) != nil {
		return notify.ErrBatch
	}
	if err := notify.ValidateBatch(batch.TenantID, batch.BatchID, batch.Alerts); err != nil {
		return err
	}
	if len(batch.Alerts) == 0 {
		return nil
	}
	return n.DB.EnqueueNotifications(ctx, batch.TenantID, batch.BatchID, batch.Alerts, n.Vault, "")
}

func (n *Notifier) consume(ctx context.Context) error {
	for ctx.Err() == nil {
		consumer, err := n.Bus.JS.CreateOrUpdateConsumer(ctx, n.Bus.StreamName(bus.Indexed), jetstream.ConsumerConfig{Durable: "notification-outbox-v1", AckPolicy: jetstream.AckExplicitPolicy, DeliverPolicy: jetstream.DeliverAllPolicy, AckWait: 60 * time.Second, MaxAckPending: 4, MaxDeliver: -1, MaxWaiting: 4})
		if err == nil {
			for ctx.Err() == nil {
				messages, fetchError := consumer.Fetch(1, jetstream.FetchMaxWait(time.Second))
				if fetchError != nil {
					err = fetchError
					break
				}
				for message := range messages.Messages() {
					work, cancel := context.WithTimeout(ctx, 45*time.Second)
					enqueueError := n.Enqueue(work, message.Data())
					if errors.Is(enqueueError, notify.ErrBatch) {
						// 永久错误先持久隔离摘要再确认，坏批次不能无限占据消费槽位。
						// 不保留未经验证的正文，避免把注入的凭据写入隔离日志。
						digest := store.Hash(string(message.Data()))
						enqueueError = n.Bus.Publish(work, "sb.quarantine", "notify_"+digest, map[string]any{"reason": "notification_batch_invalid", "sha256": digest, "bytes": len(message.Data()), "quarantined_at": time.Now().UTC()})
					}
					if enqueueError == nil {
						enqueueError = message.DoubleAck(work)
					} else {
						_ = message.NakWithDelay(5 * time.Second)
					}
					cancel()
					if enqueueError != nil && ctx.Err() == nil {
						slog.Warn("通知批次持久化待重试")
					}
				}
				if fetchError := messages.Error(); fetchError != nil && !errors.Is(fetchError, context.DeadlineExceeded) {
					err = fetchError
					break
				}
			}
		}
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			slog.Warn("通知队列暂时不可用")
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(5 * time.Second):
		}
	}
	return nil
}

func (n *Notifier) deliver(ctx context.Context) error {
	cursor := ""
	slots := make(chan struct{}, 8)
	var pending sync.WaitGroup
	defer pending.Wait()
	for ctx.Err() == nil {
		work, cancel := context.WithTimeout(ctx, 5*time.Second)
		tenants, err := n.DB.NotificationTenants(work, cursor)
		cancel()
		if err == nil {
			completedPage := true
			for _, tenant := range tenants {
				select {
				case slots <- struct{}{}:
				default:
					completedPage = false
				}
				if !completedPage {
					break
				}
				cursor = tenant
				work, cancel := context.WithTimeout(ctx, 5*time.Second)
				lease, leaseError := n.DB.LeaseNotification(work, tenant, n.Vault)
				cancel()
				if errors.Is(leaseError, pgx.ErrNoRows) || lease.ID == "" {
					<-slots
					continue
				}
				if leaseError != nil {
					<-slots
					slog.Warn("通知任务暂时无法读取")
					continue
				}
				// 获取执行容量后才租赁任务，避免排队消耗租约或慢速渠道阻塞其他租户。
				pending.Go(func() {
					defer func() { <-slots }()
					outcome := n.Sender.Send(ctx, lease.Config, lease.Message)
					work, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
					defer cancel()
					if n.DB.FinishNotification(work, lease, outcome) != nil {
						slog.Warn("通知回执未持久化，投递结果待核实")
					}
				})
			}
			if completedPage && len(tenants) < 100 {
				cursor = ""
			}
		} else {
			slog.Warn("通知控制面暂时不可用")
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(200 * time.Millisecond):
		}
	}
	return nil
}

func (n *Notifier) Run(ctx context.Context) error {
	group, ctx := errgroup.WithContext(ctx)
	group.Go(func() error { return n.consume(ctx) })
	group.Go(func() error { return n.deliver(ctx) })
	return group.Wait()
}
