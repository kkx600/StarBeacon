package worker

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	sensorv1 "github.com/kkx600/StarBeacon/api/sensor/v1"
	"github.com/kkx600/StarBeacon/internal/bus"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/watchlist"
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
	// 前三项携带合法共享索引，确保分别由批次编码、租户身份与路由日拒绝；第四项缺少路由冻结的索引。
	for _, envelope := range []bus.Envelope{
		{TenantID: "tenant_owned", Batch: []byte{0xff}, Partition: "2026-10-01", Index: "sb-v2-alerts-r180-d2026.10.01"},
		{TenantID: "foreign_tenant", Batch: encoded, Partition: "2026-10-01", Index: "sb-v2-alerts-r180-d2026.10.01"},
		{TenantID: "tenant_owned", Batch: encoded, Partition: "unroutable", Index: "sb-v2-alerts-r180-d2026.10.01"},
		{TenantID: "tenant_owned", Batch: encoded, Partition: "2026-10-01"},
		{TenantID: "tenant_owned", Batch: encoded, Partition: "2026-10-01", Index: "sb-v2-context-r180-d2026.10.01"},
		{TenantID: "tenant_owned", Batch: encoded, Partition: "2026-10-01", Index: "sb-v2-alerts-r180-d2026.10.02"},
		{TenantID: "tenant_owned", Batch: encoded, Partition: "2026-10-01", Index: "sb-alerts-tenant_owned-2026.10.01"},
		{TenantID: "tenant_owned", Batch: encoded, Partition: "2026-10-01", Index: "sb-v2-alerts-r180-x2026.10.01"},
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

func TestEventIndexRequiresFrozenSharedIndexCoveringPartition(t *testing.T) {
	for _, tc := range [][2]string{{"alerts", "sb-v2-alerts-r180-w2026.09.28"}, {"context", "sb-v2-context-r180-d2026.10.01"}} {
		if index, err := eventIndex(tc[0], "2026-10-01", tc[1]); err != nil || index != tc[1] {
			t.Fatal("路由冻结的共享索引被拒绝", tc, err)
		}
	}
	// 质量事件与批次共用该核对：缺失、旧版、其他数据流、未覆盖路由日或非分区起点的索引均拒绝。
	for _, tc := range [][2]string{{"alerts", ""}, {"context", ""}, {"alerts", "sb-alerts-tenant_owned-2026.10.01"}, {"context", "sb-context-tenant_owned-2026.10.01"}, {"alerts", "sb-v2-context-r180-d2026.10.01"}, {"alerts", "sb-v2-alerts-r180-d2026.10.02"}, {"alerts", "sb-v2-alerts-r180-w2026.10.01"}} {
		if index, err := eventIndex(tc[0], "2026-10-01", tc[1]); err == nil || index != "" {
			t.Fatal("不可用的路由索引被接受", tc)
		}
	}
}

// 命中登记的错误分类决定告警流是否被单个租户的名单问题拖住：
// 消费者无限重投，确定性错误整批 NAK 会让所有租户的告警索引永久停住。
func TestRecordWatchlistHitsSeparatesDeterministicFromTransientFailures(t *testing.T) {
	docs := []model.Alert{{TenantID: "tenant_owned", EventID: "event_owned"}}
	transient := errors.New("数据库连接中断")
	cases := []struct {
		name     string
		failure  error
		returned bool
	}{
		{"登记成功", nil, false},
		{"名单修订损坏", watchlist.ErrSource, false},
		{"名单数量超限", watchlist.ErrLimit, false},
		{"批次内容非法", watchlist.ErrInput, false},
		{"包装后的确定性错误", fmt.Errorf("读取名单目录: %w", watchlist.ErrSource), false},
		{"数据库暂时性失败", transient, true},
		{"锁等待超时", context.DeadlineExceeded, true},
		{"上下文取消", context.Canceled, true},
		// 确定性哨兵与超时同时出现时按暂时性处理，否则一次超时会永久丢弃该批命中。
		{"超时与哨兵合并", errors.Join(watchlist.ErrSource, context.DeadlineExceeded), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			calls := 0
			e := recordWatchlistHits(context.Background(), func(context.Context, string, []model.Alert) error {
				calls++
				return c.failure
			}, "tenant_owned", docs)
			if calls != 1 {
				t.Fatalf("登记调用 %d 次，期望 1 次", calls)
			}
			if (e != nil) != c.returned {
				t.Fatalf("返回错误 %v，期望返回=%v", e, c.returned)
			}
			if c.returned && !errors.Is(e, c.failure) {
				t.Fatalf("暂时性错误未原样返回：%v", e)
			}
		})
	}
}
