// Package worker 逐项处理索引结果，后续通知持久化后才确认原消息。
package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	sensorv1 "github.com/kkx600/StarBeacon/api/sensor/v1"
	"github.com/kkx600/StarBeacon/internal/application"
	"github.com/kkx600/StarBeacon/internal/bus"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/normalize"
	"github.com/kkx600/StarBeacon/internal/notify"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/telemetry"
	"github.com/kkx600/StarBeacon/internal/watchlist"
	"github.com/nats-io/nats.go/jetstream"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"
)

type Indexer struct {
	Bus *bus.Bus
	ES  *store.Elasticsearch
	DB  *store.Postgres
}

// eventIndex 核对路由冻结的共享索引属于同一数据流并覆盖路由日；重投沿用同一索引，按同一 _id 去重。
func eventIndex(stream, partition, frozen string) (string, error) {
	target, err := contract.ParseEventIndex(frozen)
	if err != nil || target.Stream != stream || !target.Covers(partition) {
		return "", errors.New("路由索引与数据流或分区不一致")
	}
	return frozen, nil
}

// deterministicWatchlistError 判断命中登记错误是否属于重投也不会改变结果的确定性错误。
// 上下文超时或取消与哨兵错误合并出现时仍按暂时性处理，保证重投机会不被误吞。
func deterministicWatchlistError(e error) bool {
	if errors.Is(e, context.DeadlineExceeded) || errors.Is(e, context.Canceled) {
		return false
	}
	return errors.Is(e, watchlist.ErrSource) || errors.Is(e, watchlist.ErrLimit) || errors.Is(e, watchlist.ErrInput)
}

// recordWatchlistHits 登记观察名单命中，并区分错误类型以免单个租户的名单问题拖住整条告警流。
// 消费者无限重投（MaxDeliver=-1），名单修订损坏、数量超限等确定性错误重投多少次结果都一样，
// 整批 NAK 会让所有租户的告警索引永久停住；此类错误只记录并计数，该批次的命中不再补登，批次照常确认。
// 数据库超时、锁超时、连接失败等暂时性错误原样返回，由整批重投补登。
func recordWatchlistHits(ctx context.Context, record func(context.Context, string, []model.Alert) error, tenant string, docs []model.Alert) error {
	e := record(ctx, tenant, docs)
	if e == nil || !deterministicWatchlistError(e) {
		return e
	}
	telemetry.WatchlistHitsSkipped.Inc()
	slog.Warn("观察名单命中未登记，告警批次照常确认", "tenant_id", tenant, "alerts", len(docs), "error", e)
	return nil
}

func (w *Indexer) Process(ctx context.Context, data []byte) error {
	started := time.Now()
	defer func() { telemetry.IndexDuration.Observe(time.Since(started).Seconds()) }()
	var envelope bus.Envelope
	if e := json.Unmarshal(data, &envelope); e != nil {
		return fmt.Errorf("信封编码无效: %w", e)
	}
	var batch sensorv1.EventBatch
	if e := proto.Unmarshal(envelope.Batch, &batch); e != nil {
		return e
	}
	if e := contract.Validate(envelope.TenantID, batch.SensorId, batch.SensorRegistrationId, &batch); e != nil {
		return e
	}
	index, e := eventIndex(batch.StreamId, envelope.Partition, envelope.Index)
	if e != nil {
		return e
	}
	if e = w.ES.EnsureIndex(ctx, index, envelope.Partition); e != nil {
		return e
	}
	if batch.StreamId == "logs" {
		return w.processLogs(ctx, index, envelope, &batch)
	}
	docs := make([]model.Alert, 0, len(batch.Records))
	quarantined := 0
	matchers := map[string]*application.Matcher{}
	for _, r := range batch.Records {
		v, e := normalize.Normalize(envelope.TenantID, batch.SensorId, batch.SensorRegistrationId, r, envelope.ReceivedAt)
		if e != nil {
			q := map[string]any{"tenant_id": envelope.TenantID, "event_id": r.EventId, "reason": "normalize_failed", "partition": envelope.Partition, "record": r, "received_at": envelope.ReceivedAt}
			if e = w.Bus.Publish(ctx, "sb.quarantine", r.EventId, q); e != nil {
				return e
			}
			quarantined++
			continue
		}
		if (v.Event.Kind == "alert") != (batch.StreamId == "alerts") {
			q := map[string]any{"tenant_id": envelope.TenantID, "event_id": r.EventId, "reason": "stream_type_mismatch", "record": r, "received_at": envelope.ReceivedAt}
			if e = w.Bus.Publish(ctx, "sb.quarantine", r.EventId, q); e != nil {
				return e
			}
			quarantined++
			continue
		}
		if len(r.ApplicationJson) > 0 {
			a, err := application.ReadAttribution(r.ApplicationJson)
			if err == nil {
				matcher, known := matchers[a.DeploymentID]
				if !known {
					if w.DB == nil {
						return errors.New("应用分类缺少部署档案服务")
					}
					matcher, err = w.DB.ApplicationDeployment(ctx, envelope.TenantID, batch.SensorId, batch.SensorRegistrationId, a.DeploymentID)
					if err != nil && !errors.Is(err, store.ErrApplicationProvenance) {
						return err
					}
					matchers[a.DeploymentID] = matcher
				}
				if matcher == nil {
					err = store.ErrApplicationProvenance
				} else {
					err = matcher.Verify(a, r.Payload, a.DeploymentID, r.ObservedAt.AsTime())
				}
			}
			if err != nil {
				// 分类依据失败只隔离附加数据；基础告警仍照常入库和推送。
				if e := w.Bus.Publish(ctx, "sb.quarantine", r.EventId+"_application", map[string]any{"tenant_id": envelope.TenantID, "event_id": r.EventId, "reason": "application_attribution_rejected", "classification": r.ApplicationJson, "received_at": envelope.ReceivedAt}); e != nil {
					return e
				}
				quarantined++
			} else {
				v.Application = &a
			}
		}
		docs = append(docs, v)
	}
	indexed := make([]model.Alert, 0, len(docs))
	for i, err := range w.ES.Bulk(ctx, index, docs) {
		if err != nil {
			var failure *store.IndexItemError
			if errors.As(err, &failure) && failure.Status == 400 {
				if e := w.Bus.Publish(ctx, "sb.quarantine", docs[i].EventID, map[string]any{"tenant_id": envelope.TenantID, "event_id": docs[i].EventID, "reason": "index_mapping_rejected", "document": docs[i]}); e != nil {
					return e
				}
				quarantined++
				continue
			}
			return err
		}
		indexed = append(indexed, docs[i])
	}
	docs = indexed
	if batch.StreamId == "alerts" && w.DB != nil && len(docs) > 0 {
		// 触发登记与索引重投共享稳定事件身份；持久登记失败时不确认原消息。
		if e := w.DB.RecordAutomaticTriage(ctx, envelope.TenantID, docs); e != nil {
			return e
		}
		// 观察名单命中同样以稳定事件身份去重；暂时性失败整批重投，确定性失败只记录而不阻塞告警流。
		if e := recordWatchlistHits(ctx, w.DB.RecordWatchlistHits, envelope.TenantID, docs); e != nil {
			return e
		}
	}
	ids := make([]string, 0, len(docs))
	for _, d := range docs {
		ids = append(ids, d.EventID)
		telemetry.ObserveCommit(d.ObservedAt)
	}
	telemetry.Indexed.WithLabelValues(batch.StreamId).Add(float64(len(docs)))
	telemetry.Quarantined.Add(float64(quarantined))
	return w.Bus.Publish(ctx, "sb.indexed", batch.BatchId, map[string]any{"tenant_id": envelope.TenantID, "batch_id": batch.BatchId, "index": index, "event_ids": ids, "alerts": notify.Summaries(docs), "quarantined": quarantined, "indexed_at": time.Now().UTC()})
}
func (w *Indexer) Run(ctx context.Context) error {
	if e := w.ES.EnsurePolicy(ctx); e != nil {
		return e
	}
	// 所有持久消费者就绪后才启动取数，避免后续流不可用时遗留后台消费。
	consumers := make([]jetstream.Consumer, 0, 3)
	for _, name := range []string{bus.Alerts, bus.Context, bus.Logs} {
		consumer, e := w.Bus.Consumer(ctx, name)
		if e != nil {
			return e
		}
		consumers = append(consumers, consumer)
	}
	group, ctx := errgroup.WithContext(ctx)
	if w.DB != nil {
		group.Go(func() error { return w.qualityLoop(ctx) })
	}
	for i, name := range []string{bus.Alerts, bus.Context, bus.Logs} {
		consumer := consumers[i]
		group.Go(func() error {
			for ctx.Err() == nil {
				messages, e := consumer.Fetch(1, jetstream.FetchMaxWait(time.Second))
				if e != nil {
					if ctx.Err() != nil {
						return nil
					}
					return e
				}
				for m := range messages.Messages() {
					work, cancel := context.WithTimeout(ctx, 45*time.Second)
					e = w.Process(work, m.Data())
					if e == nil {
						e = m.DoubleAck(work)
					} else {
						_ = m.NakWithDelay(5 * time.Second)
					}
					cancel()
					if e != nil {
						slog.Error("索引批次待重试", "stream", name, "error", e)
					}
				}
				if e = messages.Error(); e != nil && e != context.DeadlineExceeded && ctx.Err() == nil {
					slog.Warn("等待消息结束", "stream", name, "error", e)
				}
			}
			return nil
		})
	}
	return group.Wait()
}
