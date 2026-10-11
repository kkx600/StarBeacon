package agent

import (
	"context"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"

	sensorv1 "github.com/kkx600/StarBeacon/api/sensor/v1"
	"github.com/kkx600/StarBeacon/internal/contract"
	bolt "go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"
)

func acceptedBatch(b *sensorv1.EventBatch) *sensorv1.IngestAck {
	return &sensorv1.IngestAck{BatchId: b.BatchId, ProducerEpoch: b.ProducerEpoch, SensorRegistrationId: b.SensorRegistrationId, StreamId: b.StreamId, BatchSha256: b.BatchSha256, Status: sensorv1.AckStatus_ACK_STATUS_ACCEPTED, AcceptedRanges: contract.Ranges(b.Records)}
}

func TestWALInvalidRecordsAndSequenceOverflowAreAtomic(t *testing.T) {
	w, r, _ := readerFor(t, 8*1024*1024)
	if err := r.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	batch, err := w.Next("alerts")
	if err != nil {
		t.Fatal(err)
	}
	source, _ := w.Source()
	count, bytes, _ := w.Stats()
	valid := Entry{Stream: "alerts", Route: "route_test", Record: batch.Records[0]}
	badUTF8 := proto.Clone(valid.Record).(*sensorv1.EventRecord)
	badUTF8.EventType = string([]byte{0xff})
	for _, entries := range [][]Entry{nil, make([]Entry, contract.MaxBatchRecords+1), {{Stream: "bad", Route: "route_test", Record: valid.Record}}, {{Stream: "alerts", Record: valid.Record}}, {{Stream: "alerts", Route: "route_test"}}, {valid, {Stream: "alerts", Route: "route_test", Record: badUTF8}}} {
		if err := w.AppendBatch(Source{Offset: 999}, entries); err == nil {
			t.Fatal("无效记录进入本地队列")
		}
		n, size, _ := w.Stats()
		s, _ := w.Source()
		if n != count || size != bytes || s != source {
			t.Fatal("无效批次留下部分提交")
		}
	}
	if err := w.DB.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("meta")).Put([]byte("alerts_sequence"), key(math.MaxUint64))
	}); err != nil {
		t.Fatal(err)
	}
	if err := w.Append(source, "alerts", "route_test", valid.Record); err == nil {
		t.Fatal("序列溢出后复用了身份")
	}
	if _, err := w.Next("nonexistent"); err == nil {
		t.Fatal("接受未知数据流")
	}
	bad := proto.Clone(batch).(*sensorv1.EventBatch)
	bad.StreamId = "nonexistent"
	contract.Seal(bad)
	if err := w.Confirm(bad, acceptedBatch(bad)); err == nil {
		t.Fatal("未知数据流确认被接受")
	}
	path := filepath.Join(t.TempDir(), "not_dir")
	if err := os.WriteFile(path, []byte("file"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenWAL(filepath.Join(path, "wal.db"), "t", "s", "r", 4096); err == nil {
		t.Fatal("无法创建 WAL 目录仍启动")
	}
	if _, err := OpenWAL(t.TempDir(), "t", "s", "r", 4096); err == nil {
		t.Fatal("目录被作为 WAL 数据库打开")
	}
}

func TestWALBatchesDoNotMixRoutesOrExceedBudgets(t *testing.T) {
	for _, mode := range []string{"routes", "bytes", "records"} {
		t.Run(mode, func(t *testing.T) {
			w, r, _ := readerFor(t, 32*1024*1024)
			if err := r.Poll(context.Background()); err != nil {
				t.Fatal(err)
			}
			first, _ := w.Next("alerts")
			if err := w.Confirm(first, acceptedBatch(first)); err != nil {
				t.Fatal(err)
			}
			n := 3
			if mode == "records" {
				n = contract.MaxBatchRecords + 1
			}
			for i := 0; i < n; i++ {
				record := proto.Clone(first.Records[0]).(*sensorv1.EventRecord)
				record.SourceOffset = uint64(i + 1)
				route := "route_a"
				if mode == "routes" && i > 0 {
					route = "route_b"
				}
				if mode == "bytes" {
					record.Payload = make([]byte, 600*1024)
				}
				if err := w.Append(Source{}, "alerts", route, record); err != nil {
					t.Fatal(err)
				}
			}
			batch, err := w.Next("alerts")
			if err != nil {
				t.Fatal(err)
			}
			want := 1
			if mode == "records" {
				want = contract.MaxBatchRecords
			}
			if len(batch.Records) != want {
				t.Fatal("批次边界不正确", len(batch.Records), want)
			}
			if err = w.Confirm(batch, acceptedBatch(batch)); err != nil {
				t.Fatal(err)
			}
			if err = w.Confirm(batch, acceptedBatch(batch)); err != nil {
				t.Fatal("重复 ACK 破坏幂等性", err)
			}
			remaining, _, _ := w.Stats()
			if remaining != uint64(n-want) {
				t.Fatal("ACK 回收了未确认记录")
			}
		})
	}
}

func TestWALCorruptionFailsClosedAndPreservesUnconfirmedRecords(t *testing.T) {
	for _, mode := range []string{"json", "protobuf", "changed_route", "changed_record", "count_zero", "bytes_zero"} {
		t.Run(mode, func(t *testing.T) {
			w, r, _ := readerFor(t, 1024*1024)
			if err := r.Poll(context.Background()); err != nil {
				t.Fatal(err)
			}
			batch, err := w.Next("alerts")
			if err != nil {
				t.Fatal(err)
			}
			if err = w.DB.Update(func(tx *bolt.Tx) error {
				b := tx.Bucket([]byte("alerts"))
				k := key(batch.Records[0].Sequence)
				raw := b.Get(k)
				var v Pending
				if err := json.Unmarshal(raw, &v); err != nil {
					return err
				}
				switch mode {
				case "json":
					return b.Put(k, []byte("{"))
				case "protobuf":
					v.Record = []byte{0xff}
				case "changed_route":
					v.Route = "route_other"
				case "changed_record":
					p := proto.Clone(batch.Records[0]).(*sensorv1.EventRecord)
					p.Payload = []byte("changed")
					v.Record, _ = proto.Marshal(p)
				case "count_zero":
					return tx.Bucket([]byte("meta")).Put([]byte("pending_count"), key(0))
				case "bytes_zero":
					return tx.Bucket([]byte("meta")).Put([]byte("pending_bytes"), key(0))
				}
				replacement, err := json.Marshal(v)
				if err != nil {
					return err
				}
				return b.Put(k, replacement)
			}); err != nil {
				t.Fatal(err)
			}
			if mode == "json" || mode == "protobuf" {
				if _, err = w.Next("alerts"); err == nil {
					t.Fatal("损坏持久队列仍生成上传批次")
				}
			}
			if err = w.Confirm(batch, acceptedBatch(batch)); err == nil {
				t.Fatal("不一致 ACK 回收了数据")
			}
			if err = w.DB.View(func(tx *bolt.Tx) error {
				if tx.Bucket([]byte("alerts")).Get(key(batch.Records[0].Sequence)) == nil {
					t.Error("确认失败仍删除了事件")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
	t.Run("closed_database", func(t *testing.T) {
		w, r, _ := readerFor(t, 1024*1024)
		if err := r.Poll(context.Background()); err != nil {
			t.Fatal(err)
		}
		batch, _ := w.Next("alerts")
		w.Close()
		if _, err := w.Next("alerts"); err == nil {
			t.Fatal("关闭的 WAL 仍能读取")
		}
		if err := w.Confirm(batch, acceptedBatch(batch)); err == nil {
			t.Fatal("关闭的 WAL 仍确认成功")
		}
	})
}

func TestLocalAuditExpiryAndConfigurationTransaction(t *testing.T) {
	w, _, _ := readerFor(t, 1024*1024)
	old := time.Now().AddDate(0, 0, -181)
	if err := w.DB.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte("local_audits"))
		if err != nil {
			return err
		}
		if err = b.SetSequence(1); err != nil {
			return err
		}
		v, err := json.Marshal(LocalAudit{Username: "admin", Action: "old", CreatedAt: old})
		if err != nil {
			return err
		}
		return b.Put(key(1), v)
	}); err != nil {
		t.Fatal(err)
	}
	if err := w.SaveLocalConfig([]byte(`{"interfaces":[]}`), "admin", "request_config"); err != nil {
		t.Fatal(err)
	}
	if err := w.DB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("local_audits"))
		if b.Stats().KeyN != 1 {
			t.Error("到期审计未清理")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := w.DB.Update(func(tx *bolt.Tx) error {
		_, err := tx.Bucket([]byte("local_config")).CreateBucket([]byte("capture"))
		return err
	}); err == nil {
		t.Fatal("已有配置键应阻止建立同名子桶")
	}
	w2, _, _ := readerFor(t, 1024*1024)
	if err := w2.DB.Update(func(tx *bolt.Tx) error {
		_, err := tx.Bucket([]byte("local_config")).CreateBucket([]byte("capture"))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := w2.SaveLocalConfig([]byte(`{}`), "admin", "request_reject"); err == nil {
		t.Fatal("存储异常被返回为配置成功")
	}
}
