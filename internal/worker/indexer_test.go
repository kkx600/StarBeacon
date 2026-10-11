package worker

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"testing"
	"time"

	sensorv1 "github.com/kkx600/StarBeacon/api/sensor/v1"
	"github.com/kkx600/StarBeacon/internal/bus"
	"github.com/kkx600/StarBeacon/internal/contract"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestIndexerRejectsMalformedAndUnroutableBatchesBeforeDependencies(t *testing.T) {
	payload := []byte(`{"event_type":"alert"}`)
	hash := sha256.Sum256(payload)
	at := timestamppb.New(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC))
	record := &sensorv1.EventRecord{Sequence: 1, SourceGenerationId: "src_owned", EventTime: at, ObservedAt: at, Payload: payload, PayloadSchema: "suricata.eve.v1", ContentType: "application/json", RawSha256: hash[:], PayloadSha256: hash[:]}
	record.EventId = contract.EventID("tenant_owned", "sr_owned", record.SourceGenerationId, 0, 0)
	batch := &sensorv1.EventBatch{SensorId: "sensor_owned", SensorRegistrationId: "sr_owned", ProducerEpoch: "wal_owned", SchemaVersion: "1.0", RouteToken: "route_owned", StreamId: "alerts", Records: []*sensorv1.EventRecord{record}}
	contract.Seal(batch)
	encoded, err := proto.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		data []byte
	}{{"信封 JSON 损坏", []byte(`{`)}, {"信封字段类型错误", []byte(`{"batch":3}`)}}
	for _, envelope := range []bus.Envelope{
		{TenantID: "tenant_owned", Batch: []byte{0xff}, Partition: "2026-10-01"},
		{TenantID: "foreign_tenant", Batch: encoded, Partition: "2026-10-01"},
		{TenantID: "tenant_owned", Batch: encoded, Partition: "unroutable"},
	} {
		raw, err := json.Marshal(envelope)
		if err != nil {
			t.Fatal(err)
		}
		cases = append(cases, struct {
			name string
			data []byte
		}{"批次身份或路由不合法", raw})
	}
	for i, tc := range cases {
		t.Run(tc.name+string(rune('A'+i)), func(t *testing.T) {
			// 未连接依赖意味着任何索引、通知或确认尝试都会失败，非法输入必须先被拒绝。
			w := &Indexer{}
			if err := w.Process(context.Background(), tc.data); err == nil {
				t.Fatal("损坏或不可路由批次被接受")
			}
		})
	}
}
