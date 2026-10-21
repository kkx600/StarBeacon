package agent

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	sensorv1 "github.com/kkx600/StarBeacon/api/sensor/v1"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/syslogdata"
	bolt "go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type SyslogInput struct {
	Binding    syslogdata.ReceiverBinding
	ObservedAt time.Time
	Peer       syslogdata.Peer
	Raw        []byte
}

// AppendSyslogBatch 在同一事务提交来源序列与原文；日志最多占总队列的四分之一。
// 同文事件分别编号，上传重试保持身份，避免内容去重吞掉连续重复日志。
func (w *WAL) AppendSyslogBatch(items []SyslogInput) error {
	if len(items) == 0 || len(items) > 64 {
		return syslogdata.ErrInput
	}
	return w.DB.Update(func(tx *bolt.Tx) error {
		meta := tx.Bucket([]byte("meta"))
		pending := uintValue(meta.Get([]byte("pending_bytes")))
		logs := uintValue(meta.Get([]byte("logs_pending_bytes")))
		for _, input := range items {
			sourceKey := []byte("syslog/" + input.Binding.SourceID + "/sequence")
			sourceSequence := uintValue(meta.Get(sourceKey)) + 1
			sequence := uintValue(meta.Get([]byte("logs_sequence"))) + 1
			if sourceSequence == 0 || sequence == 0 {
				return fmt.Errorf("日志来源序列已耗尽")
			}
			record := syslogdata.Record{SchemaVersion: syslogdata.Schema, Binding: input.Binding, SourceEpoch: w.Epoch, SourceSequence: strconv.FormatUint(sourceSequence, 10), ObservedAt: input.ObservedAt.UTC(), Peer: input.Peer, RawBase64: base64.StdEncoding.EncodeToString(input.Raw), RawSHA256: syslogdata.Hash(input.Raw)}
			raw, err := json.Marshal(record)
			if err != nil {
				return err
			}
			if _, _, err = syslogdata.DecodeRecord(raw); err != nil {
				return err
			}
			payloadHash, rawHash := sha256.Sum256(raw), sha256.Sum256(input.Raw)
			event := &sensorv1.EventRecord{EventId: contract.SyslogEventID(w.TenantID, w.RegistrationID, input.Binding.SourceID, w.Epoch, sourceSequence), Sequence: sequence, SourceId: input.Binding.SourceID, SourceSequence: sourceSequence, SourceGenerationId: w.Epoch, EventTime: timestamppb.New(input.ObservedAt), ObservedAt: timestamppb.New(input.ObservedAt), EventType: "syslog", RawSha256: rawHash[:], Payload: raw, PayloadSchema: syslogdata.Schema, ContentType: "application/json", PayloadSha256: payloadHash[:]}
			data, err := proto.Marshal(event)
			if err != nil {
				return err
			}
			saved, err := json.Marshal(Pending{Record: data})
			if err != nil {
				return err
			}
			size := uint64(len(saved) + 64)
			if pending > w.MaxBytes || size > w.MaxBytes-pending || logs > w.MaxBytes/4 || size > w.MaxBytes/4-logs {
				return ErrWALFull
			}
			if err = tx.Bucket([]byte("logs")).Put(key(sequence), saved); err != nil {
				return err
			}
			if err = meta.Put(sourceKey, key(sourceSequence)); err != nil {
				return err
			}
			if err = meta.Put([]byte("logs_sequence"), key(sequence)); err != nil {
				return err
			}
			pending += size
			logs += size
		}
		if err := meta.Put([]byte("pending_bytes"), key(pending)); err != nil {
			return err
		}
		if err := meta.Put([]byte("logs_pending_bytes"), key(logs)); err != nil {
			return err
		}
		count := uintValue(meta.Get([]byte("pending_count")))
		if ^uint64(0)-count < uint64(len(items)) {
			return fmt.Errorf("本地队列计数已耗尽")
		}
		return meta.Put([]byte("pending_count"), key(count+uint64(len(items))))
	})
}

// BindSyslogRoute 在第一次发送前冻结路由；断线、跨日和确认丢失不得把原事件写入另一分区。
// 入队已为每条记录预留 64 B 路由，绑定不再竞争队列剩余容量。
func (w *WAL) BindSyslogRoute(batch *sensorv1.EventBatch, token string) error {
	digest, err := hex.DecodeString(token)
	if batch == nil || batch.StreamId != "logs" || batch.RouteToken != "" || len(digest) != 32 || err != nil || hex.EncodeToString(digest) != token {
		return syslogdata.ErrInput
	}
	candidate := proto.Clone(batch).(*sensorv1.EventBatch)
	candidate.RouteToken = token
	contract.Seal(candidate)
	if candidate.ProducerEpoch != w.Epoch || contract.Validate(w.TenantID, w.SensorID, w.RegistrationID, candidate) != nil {
		return syslogdata.ErrInput
	}
	err = w.DB.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("logs"))
		for _, r := range candidate.Records {
			raw := bucket.Get(key(r.Sequence))
			var p Pending
			if len(raw) == 0 || json.Unmarshal(raw, &p) != nil || p.Route != "" {
				return fmt.Errorf("日志待传路由已经变化")
			}
			want, e := proto.Marshal(r)
			if e != nil {
				return e
			}
			if !bytes.Equal(want, p.Record) {
				return fmt.Errorf("日志待传内容已经变化")
			}
			p.Route = token
			saved, e := json.Marshal(p)
			if e != nil {
				return e
			}
			if len(saved) != len(raw)+64 {
				return fmt.Errorf("日志路由预留不一致")
			}
			if e = bucket.Put(key(r.Sequence), saved); e != nil {
				return e
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	batch.RouteToken = token
	contract.Seal(batch)
	return nil
}
