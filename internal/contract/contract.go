// Package contract 固化来源定位与批次摘要，不依赖 Protobuf 或 JSON 的序列化顺序。
package contract

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	sensorv1 "github.com/kkx600/StarBeacon/api/sensor/v1"
	"github.com/kkx600/StarBeacon/internal/syslogdata"
)

const MaxPayloadBytes = 1024 * 1024
const MaxBatchBytes = 2 * 1024 * 1024
const MaxBatchRecords = 500
const MaxApplicationBytes = 32 * 1024

var safeID = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

func ValidID(id string) bool { return safeID.MatchString(id) }
func field(b *bytes.Buffer, s []byte) {
	_ = binary.Write(b, binary.BigEndian, uint32(len(s)))
	b.Write(s)
}
func text(b *bytes.Buffer, s string)   { field(b, []byte(s)) }
func number(b *bytes.Buffer, n uint64) { _ = binary.Write(b, binary.BigEndian, n) }
func EventID(tenant, registration, generation string, offset uint64, ordinal uint32) string {
	var b bytes.Buffer
	text(&b, "starbeacon.event.v1")
	text(&b, tenant)
	text(&b, registration)
	text(&b, generation)
	number(&b, offset)
	number(&b, uint64(ordinal))
	h := sha256.Sum256(b.Bytes())
	return hex.EncodeToString(h[:])
}

// SyslogEventID 把来源和递增序列绑定到认证注册身份，同文日志不按内容去重。
func SyslogEventID(tenant, registration, source, epoch string, sequence uint64) string {
	var b bytes.Buffer
	for _, s := range []string{"starbeacon.syslog-event.v1", tenant, registration, source, epoch} {
		text(&b, s)
	}
	number(&b, sequence)
	h := sha256.Sum256(b.Bytes())
	return hex.EncodeToString(h[:])
}
func ValidStream(stream string) bool {
	return stream == "alerts" || stream == "context" || stream == "logs"
}
func BatchDigest(b *sensorv1.EventBatch) []byte {
	var v bytes.Buffer
	text(&v, "starbeacon.batch.v1")
	for _, s := range []string{b.SensorId, b.SensorRegistrationId, b.StreamId, b.ProducerEpoch, b.SchemaVersion, b.RouteToken} {
		text(&v, s)
	}
	number(&v, uint64(len(b.Records)))
	for _, r := range b.Records {
		for _, s := range []string{r.EventId, r.SourceGenerationId, r.EventType, r.EngineRunId, r.PayloadSchema, r.ContentType} {
			text(&v, s)
		}
		number(&v, r.Sequence)
		number(&v, r.SourceOffset)
		number(&v, uint64(r.RecordOrdinal))
		for _, t := range []time.Time{r.EventTime.AsTime(), r.ObservedAt.AsTime()} {
			number(&v, uint64(t.Unix()))
			number(&v, uint64(t.Nanosecond()))
		}
		field(&v, r.RawSha256)
		field(&v, r.PayloadSha256)
		if r.SourceId != "" || r.SourceSequence != 0 {
			text(&v, "starbeacon.syslog-source.v1")
			text(&v, r.SourceId)
			number(&v, r.SourceSequence)
		}
		// 无附加分类的既有批次保持原摘要；附加数据使用独立域且参与重传身份。
		if len(r.ApplicationJson) > 0 || len(r.ApplicationSha256) > 0 {
			text(&v, "starbeacon.application-attribution.v1")
			field(&v, r.ApplicationSha256)
		}
	}
	h := sha256.Sum256(v.Bytes())
	return h[:]
}
func Seal(b *sensorv1.EventBatch) {
	b.BatchSha256 = BatchDigest(b)
	b.BatchId = hex.EncodeToString(b.BatchSha256)
}
func Validate(tenant, sensor, registration string, b *sensorv1.EventBatch) error {
	if b == nil || b.SensorId != sensor || b.SensorRegistrationId != registration || !ValidID(b.ProducerEpoch) || b.SchemaVersion != "1.0" || !ValidStream(b.StreamId) || b.RouteToken == "" {
		return fmt.Errorf("批次身份或版本不合法")
	}
	if len(b.Records) == 0 || len(b.Records) > MaxBatchRecords {
		return fmt.Errorf("批次记录数超限")
	}
	n := 0
	var previous uint64
	for _, r := range b.Records {
		if r == nil || r.Sequence == 0 || r.Sequence <= previous || !ValidID(r.SourceGenerationId) || len(r.Payload) == 0 || len(r.Payload) > MaxPayloadBytes {
			return fmt.Errorf("来源或记录长度不合法")
		}
		previous = r.Sequence
		n += len(r.Payload) + len(r.ApplicationJson)
		if n > MaxBatchBytes {
			return fmt.Errorf("批次字节数超限")
		}
		if r.EventTime == nil || r.EventTime.CheckValid() != nil || r.ObservedAt == nil || r.ObservedAt.CheckValid() != nil {
			return fmt.Errorf("时间不合法")
		}
		h := sha256.Sum256(r.Payload)
		if r.ContentType != "application/json" || !bytes.Equal(h[:], r.PayloadSha256) {
			return fmt.Errorf("载荷摘要或类型不匹配")
		}
		if b.StreamId == "logs" {
			v, raw, err := syslogdata.DecodeRecord(r.Payload)
			rawHash := sha256.Sum256(raw)
			if err != nil || r.PayloadSchema != syslogdata.Schema || r.EventType != "syslog" || r.SourceOffset != 0 || r.RecordOrdinal != 0 || r.EngineRunId != "" || len(r.ApplicationJson) != 0 || len(r.ApplicationSha256) != 0 || r.SourceId != v.Binding.SourceID || r.SourceGenerationId != v.SourceEpoch || fmt.Sprint(r.SourceSequence) != v.SourceSequence || r.EventId != SyslogEventID(tenant, registration, r.SourceId, r.SourceGenerationId, r.SourceSequence) || !bytes.Equal(rawHash[:], r.RawSha256) || !r.ObservedAt.AsTime().Equal(v.ObservedAt) || !r.EventTime.AsTime().Equal(v.ObservedAt) {
				return fmt.Errorf("Syslog 来源身份或原始摘要不合法")
			}
		} else if r.PayloadSchema != "suricata.eve.v1" || r.SourceId != "" || r.SourceSequence != 0 || r.EventId != EventID(tenant, registration, r.SourceGenerationId, r.SourceOffset, r.RecordOrdinal) || !bytes.Equal(h[:], r.RawSha256) {
			return fmt.Errorf("事件身份或 schema 不合法")
		}
		if len(r.ApplicationJson) > 0 {
			digest := sha256.Sum256(r.ApplicationJson)
			if len(r.ApplicationJson) > MaxApplicationBytes || !json.Valid(r.ApplicationJson) || !bytes.Equal(digest[:], r.ApplicationSha256) {
				return fmt.Errorf("应用分类长度或摘要不合法")
			}
		} else if len(r.ApplicationSha256) > 0 {
			return fmt.Errorf("应用分类摘要缺少对应内容")
		}
	}
	h := BatchDigest(b)
	if !bytes.Equal(h, b.BatchSha256) || b.BatchId != hex.EncodeToString(h) {
		return fmt.Errorf("批次摘要不匹配")
	}
	return nil
}
func Ranges(records []*sensorv1.EventRecord) []*sensorv1.SequenceRange {
	out := make([]*sensorv1.SequenceRange, 0)
	for _, r := range records {
		if len(out) > 0 && out[len(out)-1].Last+1 == r.Sequence {
			out[len(out)-1].Last = r.Sequence
		} else {
			out = append(out, &sensorv1.SequenceRange{First: r.Sequence, Last: r.Sequence})
		}
	}
	return out
}
func ValidateAck(b *sensorv1.EventBatch, a *sensorv1.IngestAck) error {
	if b == nil || a == nil || a.Status != sensorv1.AckStatus_ACK_STATUS_ACCEPTED || a.BatchId != b.BatchId || a.SensorRegistrationId != b.SensorRegistrationId || a.StreamId != b.StreamId || a.ProducerEpoch != b.ProducerEpoch || !bytes.Equal(a.BatchSha256, b.BatchSha256) {
		return fmt.Errorf("确认身份或摘要不匹配")
	}
	want := Ranges(b.Records)
	if len(want) != len(a.AcceptedRanges) || len(a.RejectedRecords) != 0 || len(a.QuarantinedRanges) != 0 {
		return fmt.Errorf("确认范围不匹配")
	}
	for i, r := range want {
		if a.AcceptedRanges[i] == nil || r.First != a.AcceptedRanges[i].First || r.Last != a.AcceptedRanges[i].Last {
			return fmt.Errorf("确认范围不匹配")
		}
	}
	return nil
}
func IndexName(tenant, stream, partition string) (string, error) {
	if !ValidID(tenant) || !ValidStream(stream) {
		return "", fmt.Errorf("索引身份不合法")
	}
	if _, err := time.Parse("2006-01-02", partition); err != nil {
		return "", err
	}
	return "sb-" + stream + "-" + tenant + "-" + strings.ReplaceAll(partition, "-", "."), nil
}
