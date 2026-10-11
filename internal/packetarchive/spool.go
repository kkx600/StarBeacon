package packetarchive

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/kkx600/StarBeacon/internal/contract"
	bolt "go.etcd.io/bbolt"
)

var ErrQuota = errors.New("原包暂存容量不足；尚未持久确认的原包不会回收")

const maxSpoolRecords = 10000
const maxConfirmedCache = 200

var spoolBucket = []byte("packet_archives")
var spoolIndex = []byte("packet_archive_index")
var spoolQueue = []byte("packet_archive_queue")
var spoolWork = []byte("packet_archive_work")
var spoolConfirmed = []byte("packet_archive_confirmed")
var spoolUsage = []byte("packet_archive_usage")

type LocalRecord struct {
	ID              string           `json:"id"`
	State           string           `json:"state"`
	Code            string           `json:"code,omitempty"`
	Capture         Capture          `json:"capture"`
	Manifest        *Manifest        `json:"manifest,omitempty"`
	ManifestSHA256  string           `json:"manifest_sha256,omitempty"`
	ReservedBytes   int64            `json:"reserved_bytes"`
	CreatedAt       time.Time        `json:"created_at"`
	Sequence        uint64           `json:"sequence"`
	Acknowledgement *Acknowledgement `json:"acknowledgement,omitempty"`
}

// 索引只包含调度所需字段；轮转和页面列表不扫描或反序列化完整帧目录。
type spoolEntry struct {
	ID            string    `json:"id"`
	State         string    `json:"state"`
	Code          string    `json:"code,omitempty"`
	Capture       Capture   `json:"capture"`
	ReservedBytes int64     `json:"reserved_bytes"`
	CreatedAt     time.Time `json:"created_at"`
	Sequence      uint64    `json:"sequence"`
}

func entry(row LocalRecord) spoolEntry {
	return spoolEntry{row.ID, row.State, row.Code, row.Capture, row.ReservedBytes, row.CreatedAt, row.Sequence}
}
func sequenceKey(v uint64) []byte {
	out := make([]byte, 8)
	binary.BigEndian.PutUint64(out, v)
	return out
}
func usageValue(tx *bolt.Tx) (int64, error) {
	raw := tx.Bucket(spoolUsage).Get([]byte("reserved"))
	if len(raw) != 8 || binary.BigEndian.Uint64(raw) > uint64(^uint64(0)>>1) {
		return 0, ErrIntegrity
	}
	return int64(binary.BigEndian.Uint64(raw)), nil
}
func writeUsage(tx *bolt.Tx, v int64) error {
	if v < 0 {
		return ErrIntegrity
	}
	return tx.Bucket(spoolUsage).Put([]byte("reserved"), sequenceKey(uint64(v)))
}
func indexRecord(tx *bolt.Tx, row LocalRecord) error {
	data, err := json.Marshal(entry(row))
	if err != nil {
		return err
	}
	if err = tx.Bucket(spoolIndex).Put([]byte(row.ID), data); err != nil {
		return err
	}
	key := sequenceKey(row.Sequence)
	// 上传游标只包含可处理状态；保留现场的隔离记录仍占用容量和历史目录。
	if row.State == "sealed" || row.State == "ready" || row.State == "acknowledged" {
		if err = tx.Bucket(spoolWork).Put(key, []byte(row.ID)); err != nil {
			return err
		}
	} else if err = tx.Bucket(spoolWork).Delete(key); err != nil {
		return err
	}
	if row.State == "confirmed" {
		if err = tx.Bucket(spoolQueue).Delete(key); err != nil {
			return err
		}
		return tx.Bucket(spoolConfirmed).Put(key, []byte(row.ID))
	}
	return tx.Bucket(spoolQueue).Put(key, []byte(row.ID))
}

// 确认记录属于本地重试缓存；正式目录已由主平台按租户留存策略持久保存。
// 只清理已确认且不再含原包的缓存元数据，不能缩短主平台默认 180 天的证据留存。
func compactConfirmed(tx *bolt.Tx) error {
	b := tx.Bucket(spoolConfirmed)
	type cached struct{ key, id []byte }
	rows := []cached{}
	c := b.Cursor()
	for k, id := c.First(); k != nil; k, id = c.Next() {
		rows = append(rows, cached{append([]byte(nil), k...), append([]byte(nil), id...)})
	}
	for i := 0; i < len(rows)-maxConfirmedCache; i++ {
		k, id := rows[i].key, rows[i].id
		if err := tx.Bucket(spoolBucket).Delete(id); err != nil {
			return err
		}
		if err := tx.Bucket(spoolIndex).Delete(id); err != nil {
			return err
		}
		if err := b.Delete(k); err != nil {
			return err
		}
	}
	return nil
}

type Acknowledgement struct {
	ID             string    `json:"id"`
	ManifestSHA256 string    `json:"manifest_sha256"`
	RawSHA256      string    `json:"raw_sha256"`
	StoredSHA256   string    `json:"stored_sha256"`
	StoredBytes    int64     `json:"stored_bytes"`
	ObjectVersion  string    `json:"object_version"`
	ExpiresAt      time.Time `json:"expires_at"`
}

type Spool struct {
	DB                                 *bolt.DB
	Dir                                string
	Quota                              int64
	SegmentBytes                       int64
	TenantID, SensorID, RegistrationID string
	mu                                 sync.Mutex
}

type PendingCapture struct {
	spool    *Spool
	File     *os.File
	Recorder *Recorder
	ID       string
	closed   bool
}

func NewSpool(db *bolt.DB, dir, tenant, sensor, registration string, quota, segmentBytes int64) (*Spool, error) {
	if db == nil || !contract.ValidID(tenant) || !contract.ValidID(sensor) || !contract.ValidID(registration) || segmentBytes < 1024*1024 || segmentBytes > MaxSegmentBytes || quota < segmentBytes*3+MaxManifestBytes {
		return nil, ErrQuota
	}
	dir, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if err = os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return nil, ErrIntegrity
	}
	s := &Spool{DB: db, Dir: dir, Quota: quota, SegmentBytes: segmentBytes, TenantID: tenant, SensorID: sensor, RegistrationID: registration}
	err = db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(spoolBucket)
		if err != nil {
			return err
		}
		if b.Stats().KeyN > maxSpoolRecords+maxConfirmedCache {
			return ErrQuota
		}
		for _, name := range [][]byte{spoolIndex, spoolQueue, spoolWork, spoolConfirmed, spoolUsage} {
			if tx.Bucket(name) != nil {
				if err = tx.DeleteBucket(name); err != nil {
					return err
				}
			}
			if _, err = tx.CreateBucket(name); err != nil {
				return err
			}
		}
		var used int64
		ids := make([][]byte, 0, b.Stats().KeyN)
		if err = b.ForEach(func(k, v []byte) error { ids = append(ids, append([]byte(nil), k...)); return nil }); err != nil {
			return err
		}
		for _, k := range ids {
			v := b.Get(k)
			var row LocalRecord
			if json.Unmarshal(v, &row) != nil || row.ID != string(k) || !s.owns(row.Capture) || row.ReservedBytes < 0 {
				return ErrIntegrity
			}
			if row.State == "capturing" {
				row.State, row.Code = "quarantined", "capture_interrupted"
			}
			if row.Sequence == 0 {
				row.Sequence, err = b.NextSequence()
				if err != nil {
					return err
				}
			}
			if row.Sequence > b.Sequence() || tx.Bucket(spoolQueue).Get(sequenceKey(row.Sequence)) != nil || tx.Bucket(spoolConfirmed).Get(sequenceKey(row.Sequence)) != nil {
				return ErrIntegrity
			}
			if row.State == "confirmed" {
				if row.ReservedBytes != 0 || row.Acknowledgement == nil {
					return ErrIntegrity
				}
				row.Manifest = nil
			}
			switch row.State {
			case "sealed", "ready", "acknowledged", "quarantined", "confirmed":
			default:
				return ErrIntegrity
			}
			if row.ReservedBytes > int64(^uint64(0)>>1)-used {
				return ErrIntegrity
			}
			used += row.ReservedBytes
			data, _ := json.Marshal(row)
			if err = b.Put(k, data); err != nil {
				return err
			}
			if err = indexRecord(tx, row); err != nil {
				return err
			}
		}
		if err = writeUsage(tx, used); err != nil {
			return err
		}
		return compactConfirmed(tx)
	})
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Spool) owns(c Capture) bool {
	return c.TenantID == s.TenantID && c.SensorID == s.SensorID && c.RegistrationID == s.RegistrationID && contract.ValidID(c.ID)
}
func (s *Spool) path(id, suffix string) (string, error) {
	if !contract.ValidID(id) {
		return "", ErrIntegrity
	}
	return filepath.Join(s.Dir, id+suffix), nil
}

func (s *Spool) Record(id string) (LocalRecord, error) {
	var row LocalRecord
	if !contract.ValidID(id) {
		return row, ErrIntegrity
	}
	err := s.DB.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(spoolBucket).Get([]byte(id))
		if raw == nil {
			return os.ErrNotExist
		}
		if json.Unmarshal(raw, &row) != nil || row.ID != id || !s.owns(row.Capture) {
			return ErrIntegrity
		}
		return nil
	})
	return row, err
}

func (s *Spool) List() (rows []LocalRecord, err error) {
	rows = []LocalRecord{}
	err = s.DB.View(func(tx *bolt.Tx) error {
		// 业务列表有界；待传任务通过独立 FIFO 索引读取，列表大小不限制真实上传队列。
		pending, confirmed := tx.Bucket(spoolQueue).Cursor(), tx.Bucket(spoolConfirmed).Cursor()
		pk, pv := pending.Last()
		ck, cv := confirmed.Last()
		for len(rows) < 200 && (pk != nil || ck != nil) {
			if pk != nil && len(pk) != 8 || ck != nil && len(ck) != 8 {
				return ErrIntegrity
			}
			id := cv
			if pk != nil && (ck == nil || binary.BigEndian.Uint64(pk) > binary.BigEndian.Uint64(ck)) {
				id = pv
				pk, pv = pending.Prev()
			} else {
				ck, cv = confirmed.Prev()
			}
			var row LocalRecord
			if json.Unmarshal(tx.Bucket(spoolIndex).Get(id), &row) != nil || row.ID != string(id) || !s.owns(row.Capture) {
				return ErrIntegrity
			}
			rows = append(rows, row)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return rows, err
}

// NextPending 只返回一个可处理任务，隔离现场保留的中断文件不会阻塞其他已封存切片。
func (s *Spool) NextPending() (row LocalRecord, err error) {
	err = s.DB.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(spoolWork).Cursor()
		if k, id := c.First(); k != nil {
			var meta spoolEntry
			if len(k) != 8 || json.Unmarshal(tx.Bucket(spoolIndex).Get(id), &meta) != nil || meta.ID != string(id) || !s.owns(meta.Capture) || meta.Sequence != binary.BigEndian.Uint64(k) {
				return ErrIntegrity
			}
			if meta.State == "sealed" || meta.State == "ready" || meta.State == "acknowledged" {
				if json.Unmarshal(tx.Bucket(spoolBucket).Get(id), &row) != nil || row.ID != meta.ID || row.State != meta.State || row.Sequence != meta.Sequence || !reflect.DeepEqual(row.Capture, meta.Capture) || !s.owns(row.Capture) {
					return ErrIntegrity
				}
				return nil
			}
			return ErrIntegrity
		}
		return os.ErrNotExist
	})
	return row, err
}

func (s *Spool) Reserved() (int64, error) {
	var used int64
	err := s.DB.View(func(tx *bolt.Tx) error { var err error; used, err = usageValue(tx); return err })
	return used, err
}

// 异常退出可能留下派生临时文件；计入容量但不自动删除未知原包或跳过符号链接。
func (s *Spool) untrackedBytes(tx *bolt.Tx) (int64, error) {
	dir, err := os.Open(s.Dir)
	if err != nil {
		return 0, err
	}
	defer dir.Close()
	var total int64
	count := 0
	knownUsage := map[string]int64{}
	for {
		files, e := dir.ReadDir(128)
		if e != nil && e != io.EOF {
			return 0, e
		}
		for _, file := range files {
			count++
			if count > 3*maxSpoolRecords+1024 {
				return 0, ErrQuota
			}
			info, e := file.Info()
			if e != nil {
				return 0, e
			}
			if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
				return 0, ErrIntegrity
			}
			id := ""
			for _, suffix := range []string{".part", ".raw", ".stored"} {
				if strings.HasSuffix(file.Name(), suffix) {
					id = strings.TrimSuffix(file.Name(), suffix)
					break
				}
			}
			known := false
			if contract.ValidID(id) {
				var meta spoolEntry
				raw := tx.Bucket(spoolIndex).Get([]byte(id))
				if raw != nil {
					if json.Unmarshal(raw, &meta) != nil || meta.ID != id || !s.owns(meta.Capture) {
						return 0, ErrIntegrity
					}
					known = meta.ReservedBytes > 0
					if known {
						if info.Size() > meta.ReservedBytes-knownUsage[id] {
							return 0, ErrQuota
						}
						knownUsage[id] += info.Size()
					}
				}
			}
			if !known {
				if info.Size() > s.Quota-total {
					return 0, ErrQuota
				}
				total += info.Size()
			}
		}
		if e == io.EOF {
			break
		}
	}
	return total, nil
}

func (s *Spool) Begin(header Capture) (*PendingCapture, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if header.ID == "" {
		value := make([]byte, 16)
		if _, err := rand.Read(value); err != nil {
			return nil, err
		}
		header.ID = "packet_" + hex.EncodeToString(value)
	}
	if !s.owns(header) {
		return nil, ErrIntegrity
	}
	if _, err := captureStart(header); err != nil {
		return nil, err
	}
	path, err := s.path(header.ID, ".part")
	if err != nil {
		return nil, err
	}
	// 容量同时预留原始副本、压缩制品和派生目录，不以假设压缩率承诺空间。
	reserve := s.SegmentBytes*3 + MaxManifestBytes
	row := LocalRecord{ID: header.ID, State: "capturing", Capture: header, ReservedBytes: reserve, CreatedAt: time.Now().UTC()}
	err = s.DB.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(spoolBucket)
		if b.Get([]byte(row.ID)) != nil {
			return ErrIntegrity
		}
		if tx.Bucket(spoolQueue).Stats().KeyN >= maxSpoolRecords {
			return ErrQuota
		}
		used, err := usageValue(tx)
		if err != nil {
			return err
		}
		orphans, err := s.untrackedBytes(tx)
		if err != nil {
			return err
		}
		if used > s.Quota || orphans > s.Quota-used || reserve > s.Quota-used-orphans {
			return ErrQuota
		}
		row.Sequence, err = b.NextSequence()
		if err != nil {
			return err
		}
		raw, _ := json.Marshal(row)
		if err = b.Put([]byte(row.ID), raw); err != nil {
			return err
		}
		if err = indexRecord(tx, row); err != nil {
			return err
		}
		return writeUsage(tx, used+reserve)
	})
	if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		_ = s.fail(row.ID, "capture_file_unavailable")
		return nil, err
	}
	recorder, err := NewRecorder(file, header, s.SegmentBytes)
	if err != nil {
		_ = file.Close()
		_ = s.fail(row.ID, "capture_header_unavailable")
		return nil, err
	}
	return &PendingCapture{spool: s, File: file, Recorder: recorder, ID: header.ID}, nil
}

func (s *Spool) update(id string, apply func(*LocalRecord) error) error {
	return s.DB.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(spoolBucket)
		raw := b.Get([]byte(id))
		if raw == nil {
			return os.ErrNotExist
		}
		var row LocalRecord
		if json.Unmarshal(raw, &row) != nil || !s.owns(row.Capture) {
			return ErrIntegrity
		}
		oldReserve := row.ReservedBytes
		if err := apply(&row); err != nil {
			return err
		}
		encoded, err := json.Marshal(row)
		if err != nil || len(encoded) > MaxManifestBytes+8192 {
			return ErrLimit
		}
		used, err := usageValue(tx)
		if err != nil || used < oldReserve || row.ReservedBytes < 0 {
			return ErrIntegrity
		}
		if row.ReservedBytes > int64(^uint64(0)>>1)-(used-oldReserve) {
			return ErrIntegrity
		}
		if err = b.Put([]byte(id), encoded); err != nil {
			return err
		}
		if err = indexRecord(tx, row); err != nil {
			return err
		}
		if err = writeUsage(tx, used-oldReserve+row.ReservedBytes); err != nil {
			return err
		}
		return compactConfirmed(tx)
	})
}
func (s *Spool) fail(id, code string) error {
	return s.update(id, func(r *LocalRecord) error { r.State, r.Code = "quarantined", code; return nil })
}

func (s *Spool) Quarantine(id, code string) error {
	if !contract.ValidID(code) {
		return ErrIntegrity
	}
	return s.update(id, func(row *LocalRecord) error {
		if row.State != "sealed" && row.State != "ready" {
			return ErrIntegrity
		}
		row.State, row.Code = "quarantined", code
		return nil
	})
}

func (p *PendingCapture) Seal(ended time.Time, termination string, drops *uint64) error {
	if p.closed {
		return io.ErrClosedPipe
	}
	p.closed = true
	c, err := p.Recorder.Seal(ended, termination, drops)
	if err == nil {
		err = p.File.Sync()
	}
	if err == nil {
		err = p.File.Chmod(0400)
	}
	closed := p.File.Close()
	if err == nil {
		err = closed
	}
	if err != nil {
		_ = p.spool.fail(p.ID, "capture_seal_unconfirmed")
		return err
	}
	part, _ := p.spool.path(p.ID, ".part")
	raw, _ := p.spool.path(p.ID, ".raw")
	if err = os.Rename(part, raw); err == nil {
		err = syncDirectory(p.spool.Dir)
	}
	if err != nil {
		_ = p.spool.fail(p.ID, "capture_seal_unconfirmed")
		return err
	}
	return p.spool.update(p.ID, func(row *LocalRecord) error {
		if row.State != "capturing" {
			return ErrIntegrity
		}
		row.State, row.Capture = "sealed", c
		return nil
	})
}

// Abort 保留已经写入的原始字节与容量账目，不能把中断文件当作完整切片或提前回收。
func (p *PendingCapture) Abort(code string) error {
	if p.closed {
		return io.ErrClosedPipe
	}
	p.closed = true
	_ = p.Recorder.Flush()
	_ = p.File.Sync()
	_ = p.File.Close()
	return p.spool.fail(p.ID, code)
}

func syncDirectory(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func openFile(path string, limit int64) (*os.File, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Mode().Perm()&0077 != 0 || before.Size() < 1 || before.Size() > limit {
		return nil, ErrIntegrity
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) {
		_ = f.Close()
		return nil, ErrIntegrity
	}
	return f, nil
}

func (s *Spool) Prepare(ctx context.Context, id, codec string) (LocalRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	row, err := s.Record(id)
	if err != nil {
		return row, err
	}
	if row.State == "ready" {
		return row, nil
	}
	if row.State != "sealed" {
		return row, ErrIntegrity
	}
	if err = s.DB.View(func(tx *bolt.Tx) error {
		used, e := usageValue(tx)
		if e != nil {
			return e
		}
		orphan, e := s.untrackedBytes(tx)
		if e != nil {
			return e
		}
		if used > s.Quota || orphan > s.Quota-used {
			return ErrQuota
		}
		return nil
	}); err != nil {
		return row, err
	}
	rawPath, _ := s.path(id, ".raw")
	targetPath, _ := s.path(id, ".stored")
	source, err := openFile(rawPath, s.SegmentBytes)
	if err != nil {
		return row, err
	}
	defer source.Close()
	file, err := os.CreateTemp(s.Dir, ".packet-encoding-")
	if err != nil {
		return row, err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	index, err := EncodeFrames(ctx, file, source, codec, DefaultFrameBytes)
	if err == nil {
		err = file.Sync()
	}
	if err == nil {
		err = file.Chmod(0400)
	}
	closed := file.Close()
	if err == nil {
		err = closed
	}
	if err != nil {
		return row, err
	}
	// 从真实落盘制品逐帧读取并核对往返摘要，校验成功才允许进入上传队列。
	stored, err := openFile(temporary, MaxStoredBytes)
	if err != nil {
		return row, err
	}
	ranges := func(_ context.Context, offset, length int64) (io.ReadCloser, error) {
		return io.NopCloser(io.NewSectionReader(stored, offset, length)), nil
	}
	err = ReadRange(ctx, io.Discard, ranges, index, 0, index.RawBytes)
	_ = stored.Close()
	if err != nil {
		return row, err
	}
	manifest := Manifest{Capture: row.Capture, Encoding: index}
	_, digest, err := manifest.JSON()
	if err != nil {
		return row, err
	}
	if err = os.Rename(temporary, targetPath); err == nil {
		err = syncDirectory(s.Dir)
	}
	if err != nil {
		return row, err
	}
	err = s.update(id, func(r *LocalRecord) error {
		if r.State != "sealed" {
			return ErrIntegrity
		}
		r.State, r.Manifest, r.ManifestSHA256 = "ready", &manifest, digest
		return nil
	})
	if err != nil {
		return row, err
	}
	return s.Record(id)
}

func (s *Spool) OpenStored(id string) (*os.File, LocalRecord, error) {
	row, err := s.Record(id)
	if err != nil {
		return nil, row, err
	}
	if row.State != "ready" || row.Manifest == nil || row.Manifest.Validate() != nil {
		return nil, row, ErrIntegrity
	}
	path, _ := s.path(id, ".stored")
	file, err := openFile(path, MaxStoredBytes)
	if err != nil {
		return nil, row, err
	}
	info, err := file.Stat()
	if err != nil || info.Size() != row.Manifest.Encoding.StoredBytes {
		file.Close()
		return nil, row, ErrIntegrity
	}
	return file, row, nil
}

func (s *Spool) Confirm(ack Acknowledgement) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	row, err := s.Record(ack.ID)
	if err != nil {
		return err
	}
	if row.State == "confirmed" {
		if row.Acknowledgement == nil || !sameAcknowledgement(*row.Acknowledgement, ack) {
			return ErrIntegrity
		}
		return nil
	}
	if row.State != "ready" && row.State != "acknowledged" || row.Manifest == nil {
		return ErrIntegrity
	}
	_, digest, err := row.Manifest.JSON()
	if err != nil {
		return err
	}
	if ack.ManifestSHA256 != digest || digest != row.ManifestSHA256 || ack.RawSHA256 != row.Manifest.Encoding.RawSHA256 || ack.StoredSHA256 != row.Manifest.Encoding.StoredSHA256 || ack.StoredBytes != row.Manifest.Encoding.StoredBytes || !ValidObjectVersion(ack.ObjectVersion) || row.State == "ready" && !ack.ExpiresAt.After(time.Now()) {
		return ErrIntegrity
	}
	if row.State == "acknowledged" && (row.Acknowledgement == nil || !sameAcknowledgement(*row.Acknowledgement, ack)) {
		return ErrIntegrity
	}
	if err = s.update(ack.ID, func(r *LocalRecord) error { r.State, r.Acknowledgement = "acknowledged", &ack; return nil }); err != nil {
		return err
	}
	for _, suffix := range []string{".raw", ".stored"} {
		path, _ := s.path(ack.ID, suffix)
		info, e := os.Lstat(path)
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil {
			return e
		}
		if !info.Mode().IsRegular() {
			return ErrIntegrity
		}
		if e = os.Remove(path); e != nil {
			return e
		}
	}
	if err = syncDirectory(s.Dir); err != nil {
		return err
	}
	return s.update(ack.ID, func(r *LocalRecord) error { r.State, r.ReservedBytes, r.Manifest = "confirmed", 0, nil; return nil })
}

func sameAcknowledgement(first, second Acknowledgement) bool {
	if !first.ExpiresAt.Equal(second.ExpiresAt) {
		return false
	}
	first.ExpiresAt, second.ExpiresAt = time.Time{}, time.Time{}
	return first == second
}
