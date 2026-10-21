package worker

import (
	"context"
	"encoding/hex"
	"strconv"

	sensorv1 "github.com/kkx600/StarBeacon/api/sensor/v1"
	"github.com/kkx600/StarBeacon/internal/bus"
	"github.com/kkx600/StarBeacon/internal/syslogdata"
	"github.com/kkx600/StarBeacon/internal/telemetry"
)

func (w *Indexer) processLogs(ctx context.Context, index string, envelope bus.Envelope, batch *sensorv1.EventBatch) error {
	items := make([]syslogdata.Document, 0, len(batch.Records))
	for _, r := range batch.Records {
		record, raw, err := syslogdata.DecodeRecord(r.Payload)
		if err != nil {
			return err
		}
		items = append(items, syslogdata.Document{SchemaVersion: "syslog.index.v1", EventID: r.EventId, TenantID: envelope.TenantID, SensorID: batch.SensorId, RegistrationID: batch.SensorRegistrationId, Sequence: strconv.FormatUint(r.Sequence, 10), PayloadSHA256: hex.EncodeToString(r.PayloadSha256), ReceivedAt: envelope.ReceivedAt, Partition: envelope.Partition, Record: record, Parsed: syslogdata.Parse(record, raw)})
	}
	for _, err := range w.ES.BulkLogs(ctx, index, items) {
		if err != nil {
			return err
		}
	}
	// 日志接入不触发告警通知、模型分析或自动封禁。
	telemetry.Indexed.WithLabelValues("logs").Add(float64(len(items)))
	return nil
}
