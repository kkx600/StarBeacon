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
	"github.com/kkx600/StarBeacon/internal/bus"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/normalize"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/telemetry"
	"github.com/nats-io/nats.go/jetstream"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"
)

type Indexer struct {
	Bus *bus.Bus
	ES  *store.Elasticsearch
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
	index, e := contract.IndexName(envelope.TenantID, batch.StreamId, envelope.Partition)
	if e != nil {
		return e
	}
	if e = w.ES.EnsureIndex(ctx, index, envelope.Partition); e != nil {
		return e
	}
	docs := make([]model.Alert, 0, len(batch.Records))
	quarantined := 0
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
	ids := make([]string, 0, len(docs))
	for _, d := range docs {
		ids = append(ids, d.EventID)
		telemetry.ObserveCommit(d.ObservedAt)
	}
	telemetry.Indexed.WithLabelValues(batch.StreamId).Add(float64(len(docs)))
	telemetry.Quarantined.Add(float64(quarantined))
	return w.Bus.Publish(ctx, "sb.indexed", batch.BatchId, map[string]any{"tenant_id": envelope.TenantID, "batch_id": batch.BatchId, "index": index, "event_ids": ids, "quarantined": quarantined, "indexed_at": time.Now().UTC()})
}
func (w *Indexer) Run(ctx context.Context) error {
	if e := w.ES.EnsurePolicy(ctx); e != nil {
		return e
	}
	group, ctx := errgroup.WithContext(ctx)
	for _, name := range []string{bus.Alerts, bus.Context} {
		consumer, e := w.Bus.Consumer(ctx, name)
		if e != nil {
			return e
		}
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
