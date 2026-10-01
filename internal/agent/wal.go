// Package agent 保持来源检查点、待传事件和路由身份的同步持久化。
package agent

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	sensorv1 "github.com/kkx600/StarBeacon/api/sensor/v1"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/store"
	bolt "go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"
)

var ErrWALFull = errors.New("本地待传队列容量已满")

type WAL struct {
	DB                                        *bolt.DB
	TenantID, SensorID, RegistrationID, Epoch string
	MaxBytes                                  uint64
	mu                                        sync.RWMutex
	failures                                  map[string]bool
}
type Source struct {
	FileID       string `json:"file_id"`
	Generation   string `json:"generation"`
	Offset       uint64 `json:"offset"`
	PrefixSHA256 string `json:"prefix_sha256,omitempty"`
	PrefixBytes  int    `json:"prefix_bytes,omitempty"`
}
type Pending struct {
	Route  string `json:"route"`
	Record []byte `json:"record"`
}
type Entry struct {
	Stream, Route string
	Record        *sensorv1.EventRecord
}

func key(n uint64) []byte { b := make([]byte, 8); binary.BigEndian.PutUint64(b, n); return b }
func uintValue(b []byte) uint64 {
	if len(b) != 8 {
		return 0
	}
	return binary.BigEndian.Uint64(b)
}
func OpenWAL(path, tenant, sensor, registration string, maxBytes uint64) (*WAL, error) {
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return nil, e
	}
	db, e := bolt.Open(path, 0600, &bolt.Options{Timeout: time.Second})
	if e != nil {
		return nil, e
	}
	w := &WAL{DB: db, TenantID: tenant, SensorID: sensor, RegistrationID: registration, MaxBytes: maxBytes, failures: map[string]bool{}}
	e = db.Update(func(tx *bolt.Tx) error {
		for _, s := range []string{"meta", "alerts", "context", "local_config"} {
			if _, e := tx.CreateBucketIfNotExists([]byte(s)); e != nil {
				return e
			}
		}
		m := tx.Bucket([]byte("meta"))
		if m.Get([]byte("pending_count")) == nil {
			var count uint64
			for _, stream := range []string{"alerts", "context"} {
				count += uint64(tx.Bucket([]byte(stream)).Stats().KeyN)
			}
			if e := m.Put([]byte("pending_count"), key(count)); e != nil {
				return e
			}
		}
		identity := tenant + "/" + sensor + "/" + registration
		if saved := m.Get([]byte("identity")); saved != nil && string(saved) != identity {
			return fmt.Errorf("本地队列属于其他注册身份，禁止覆盖")
		}
		if e := m.Put([]byte("identity"), []byte(identity)); e != nil {
			return e
		}
		w.Epoch = string(m.Get([]byte("epoch")))
		if w.Epoch == "" {
			w.Epoch = store.RandomID("wal_")
			return m.Put([]byte("epoch"), []byte(w.Epoch))
		}
		return nil
	})
	if e != nil {
		db.Close()
		return nil, e
	}
	return w, nil
}
func (w *WAL) Close() error { return w.DB.Close() }
func (w *WAL) Source() (Source, error) {
	var s Source
	e := w.DB.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket([]byte("meta")).Get([]byte("source"))
		if raw == nil {
			return nil
		}
		return json.Unmarshal(raw, &s)
	})
	return s, e
}
func (w *WAL) Append(source Source, stream, route string, r *sensorv1.EventRecord) error {
	return w.AppendBatch(source, []Entry{{Stream: stream, Route: route, Record: r}})
}

// AppendBatch 一次同步提交事件和最终来源位置，避免逐行刷盘限制吞吐。
func (w *WAL) AppendBatch(source Source, entries []Entry) error {
	if len(entries) == 0 || len(entries) > contract.MaxBatchRecords {
		return fmt.Errorf("本地提交记录数不合法")
	}
	return w.DB.Update(func(tx *bolt.Tx) error {
		m := tx.Bucket([]byte("meta"))
		n := uintValue(m.Get([]byte("pending_bytes")))
		for _, entry := range entries {
			if (entry.Stream != "alerts" && entry.Stream != "context") || entry.Route == "" || entry.Record == nil {
				return fmt.Errorf("数据流、路由或事件不合法")
			}
			r := proto.Clone(entry.Record).(*sensorv1.EventRecord)
			seq := uintValue(m.Get([]byte(entry.Stream+"_sequence"))) + 1
			if seq == 0 {
				return fmt.Errorf("本地序列已耗尽")
			}
			r.Sequence = seq
			r.EventId = contract.EventID(w.TenantID, w.RegistrationID, r.SourceGenerationId, r.SourceOffset, r.RecordOrdinal)
			data, e := proto.Marshal(r)
			if e != nil {
				return e
			}
			p, e := json.Marshal(Pending{entry.Route, data})
			if e != nil {
				return e
			}
			if n > w.MaxBytes || uint64(len(p)) > w.MaxBytes-n {
				return ErrWALFull
			}
			if e = tx.Bucket([]byte(entry.Stream)).Put(key(seq), p); e != nil {
				return e
			}
			if e = m.Put([]byte(entry.Stream+"_sequence"), key(seq)); e != nil {
				return e
			}
			n += uint64(len(p))
		}
		if e := m.Put([]byte("pending_bytes"), key(n)); e != nil {
			return e
		}
		state, e := json.Marshal(source)
		if e := m.Put([]byte("pending_count"), key(uintValue(m.Get([]byte("pending_count")))+uint64(len(entries)))); e != nil {
			return e
		}
		if e != nil {
			return e
		}
		return m.Put([]byte("source"), state)
	})
}
func (w *WAL) Next(stream string) (*sensorv1.EventBatch, error) {
	b := &sensorv1.EventBatch{SensorId: w.SensorID, SensorRegistrationId: w.RegistrationID, ProducerEpoch: w.Epoch, SchemaVersion: "1.0", StreamId: stream}
	e := w.DB.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(stream))
		if bucket == nil {
			return fmt.Errorf("数据流不合法")
		}
		c := bucket.Cursor()
		size := 0
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var p Pending
			if e := json.Unmarshal(v, &p); e != nil {
				return e
			}
			if b.RouteToken == "" {
				b.RouteToken = p.Route
			}
			if b.RouteToken != p.Route {
				break
			}
			var r sensorv1.EventRecord
			if e := proto.Unmarshal(p.Record, &r); e != nil {
				return e
			}
			if len(b.Records) > 0 && size+len(r.Payload) > 1024*1024 {
				break
			}
			b.Records = append(b.Records, &r)
			size += len(r.Payload)
			if len(b.Records) >= contract.MaxBatchRecords {
				break
			}
		}
		return nil
	})
	if e != nil {
		return nil, e
	}
	if len(b.Records) == 0 {
		return nil, nil
	}
	contract.Seal(b)
	return b, nil
}
func (w *WAL) Confirm(b *sensorv1.EventBatch, ack *sensorv1.IngestAck) error {
	if e := contract.ValidateAck(b, ack); e != nil {
		return e
	}
	return w.DB.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(b.StreamId))
		if bucket == nil {
			return fmt.Errorf("数据流不存在")
		}
		m := tx.Bucket([]byte("meta"))
		n := uintValue(m.Get([]byte("pending_bytes")))
		for _, r := range b.Records {
			raw := bucket.Get(key(r.Sequence))
			if raw == nil {
				continue
			}
			var p Pending
			if e := json.Unmarshal(raw, &p); e != nil {
				return e
			}
			want, e := proto.Marshal(r)
			if e != nil {
				return e
			}
			if p.Route != b.RouteToken || !bytes.Equal(want, p.Record) {
				return fmt.Errorf("确认与本地记录不一致")
			}
			n -= uint64(len(raw))
			count := uintValue(m.Get([]byte("pending_count")))
			if count == 0 {
				return fmt.Errorf("本地队列计数不一致")
			}
			if e := m.Put([]byte("pending_count"), key(count-1)); e != nil {
				return e
			}
			if e = bucket.Delete(key(r.Sequence)); e != nil {
				return e
			}
		}
		return m.Put([]byte("pending_bytes"), key(n))
	})
}
func (w *WAL) Stats() (uint64, uint64, error) {
	var count, n uint64
	e := w.DB.View(func(tx *bolt.Tx) error {
		count = uintValue(tx.Bucket([]byte("meta")).Get([]byte("pending_count")))
		n = uintValue(tx.Bucket([]byte("meta")).Get([]byte("pending_bytes")))
		return nil
	})
	return count, n, e
}
func (w *WAL) LocalConfig() (json.RawMessage, error) {
	var v json.RawMessage
	e := w.DB.View(func(tx *bolt.Tx) error {
		v = bytes.Clone(tx.Bucket([]byte("local_config")).Get([]byte("capture")))
		return nil
	})
	if len(v) == 0 {
		v = json.RawMessage(`{"interfaces":[],"status":"not_applied"}`)
	}
	return v, e
}
func (w *WAL) SaveLocalConfig(data []byte, username, requestID string) error {
	return w.DB.Update(func(tx *bolt.Tx) error {
		if e := tx.Bucket([]byte("local_config")).Put([]byte("capture"), data); e != nil {
			return e
		}
		return appendAudit(tx, LocalAudit{Username: username, Action: "capture.configure", RequestID: requestID, CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().AddDate(0, 0, 180)})
	})
}
func (w *WAL) setFailure(code string, active bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.failures[code] = active
}
