package contract

import (
	"bytes"
	"crypto/sha256"
	"testing"
	"time"

	sensorv1 "github.com/kkx600/StarBeacon/api/sensor/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func batch() *sensorv1.EventBatch {
	p := []byte(`{"event_type":"alert"}`)
	h := sha256.Sum256(p)
	at := timestamppb.New(time.Date(2026, 10, 1, 0, 0, 0, 123456789, time.UTC))
	b := &sensorv1.EventBatch{SensorId: "sensor_test", SensorRegistrationId: "sr_test", ProducerEpoch: "wal_test", SchemaVersion: "1.0", RouteToken: "route_test", StreamId: "alerts"}
	for i, sequence := range []uint64{1, 3} {
		r := &sensorv1.EventRecord{Sequence: sequence, SourceGenerationId: "src_test", SourceOffset: uint64(i * 100), EventTime: at, ObservedAt: at, EventType: "alert", Payload: p, PayloadSchema: "suricata.eve.v1", ContentType: "application/json", RawSha256: h[:], PayloadSha256: h[:]}
		r.EventId = EventID("tenant_test", "sr_test", r.SourceGenerationId, r.SourceOffset, 0)
		b.Records = append(b.Records, r)
	}
	Seal(b)
	return b
}
func TestCanonicalIdentityAndWireRoundTrip(t *testing.T) {
	if EventID("ab", "c", "src_test", 1, 0) == EventID("a", "bc", "src_test", 1, 0) {
		t.Fatal("身份编码存在歧义")
	}
	b := batch()
	if e := Validate("tenant_test", "sensor_test", "sr_test", b); e != nil {
		t.Fatal(e)
	}
	raw, e := proto.Marshal(b)
	if e != nil {
		t.Fatal(e)
	}
	var restored sensorv1.EventBatch
	if e = proto.Unmarshal(raw, &restored); e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(BatchDigest(b), BatchDigest(&restored)) {
		t.Fatal("线格式影响稳定摘要")
	}
}
func TestPayloadIdentityAndBatchTampering(t *testing.T) {
	for _, mutate := range []func(*sensorv1.EventBatch){func(b *sensorv1.EventBatch) { b.Records[0].Payload = []byte("篡改") }, func(b *sensorv1.EventBatch) { b.SensorRegistrationId = "sr_other" }, func(b *sensorv1.EventBatch) { b.Records[1].Sequence = 1 }, func(b *sensorv1.EventBatch) { b.Records[0].SourceOffset++ }, func(b *sensorv1.EventBatch) { b.BatchId = "bad" }} {
		b := batch()
		mutate(b)
		if Validate("tenant_test", "sensor_test", "sr_test", b) == nil {
			t.Fatal("篡改未被拒绝")
		}
	}
}
func TestAckCannotInventContinuousPrefix(t *testing.T) {
	b := batch()
	a := &sensorv1.IngestAck{BatchId: b.BatchId, ProducerEpoch: b.ProducerEpoch, SensorRegistrationId: b.SensorRegistrationId, StreamId: b.StreamId, BatchSha256: b.BatchSha256, Status: sensorv1.AckStatus_ACK_STATUS_ACCEPTED, AcceptedRanges: Ranges(b.Records)}
	if e := ValidateAck(b, a); e != nil {
		t.Fatal(e)
	}
	a.AcceptedRanges = []*sensorv1.SequenceRange{{First: 1, Last: 3}}
	if ValidateAck(b, a) == nil {
		t.Fatal("未发送的序号 2 被确认")
	}
	a.AcceptedRanges = Ranges(b.Records)
	a.ProducerEpoch = "wal_other"
	if ValidateAck(b, a) == nil {
		t.Fatal("旧代次确认未被拒绝")
	}
}
