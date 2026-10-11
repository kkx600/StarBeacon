package packetarchive

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	bolt "go.etcd.io/bbolt"
)

func testSpool(t *testing.T) (*Spool, *bolt.DB) {
	t.Helper()
	root := t.TempDir()
	db, err := bolt.Open(filepath.Join(root, "state.db"), 0600, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s, err := NewSpool(db, filepath.Join(root, "packets"), "tenant_one", "sensor_one", "registration_one", 16*1024*1024, 1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	return s, db
}

func readyCapture(t *testing.T, s *Spool, id string) LocalRecord {
	t.Helper()
	header := captureHeader()
	header.ID = id
	p, err := s.Begin(header)
	if err != nil {
		t.Fatal(err)
	}
	data := bytes.Repeat([]byte{0xac}, 70000)
	if err = p.Recorder.Write(gopacket.CaptureInfo{Timestamp: header.StartedAt, CaptureLength: len(data), Length: len(data)}, data, nil); err != nil {
		t.Fatal(err)
	}
	if err = p.Seal(header.StartedAt.Add(time.Second), "rotation", nil); err != nil {
		t.Fatal(err)
	}
	row, err := s.Prepare(context.Background(), id, "zstd")
	if err != nil {
		t.Fatal(err)
	}
	return row
}

func acknowledgement(row LocalRecord) Acknowledgement {
	return Acknowledgement{ID: row.ID, ManifestSHA256: row.ManifestSHA256, RawSHA256: row.Manifest.Encoding.RawSHA256, StoredSHA256: row.Manifest.Encoding.StoredSHA256, StoredBytes: row.Manifest.Encoding.StoredBytes, ObjectVersion: "immutable_test_version", ExpiresAt: time.Now().UTC().AddDate(0, 0, 180)}
}

func TestSpoolPreservesOriginalUntilExactDurableConfirmation(t *testing.T) {
	s, _ := testSpool(t)
	row := readyCapture(t, s, "packet_ready")
	rawPath, _ := s.path(row.ID, ".raw")
	original, err := os.ReadFile(rawPath)
	if err != nil {
		t.Fatal(err)
	}
	file, loaded, err := s.OpenStored(row.ID)
	if err != nil || loaded.ManifestSHA256 != row.ManifestSHA256 {
		t.Fatal(err)
	}
	defer file.Close()
	var out bytes.Buffer
	source := func(_ context.Context, offset, size int64) (io.ReadCloser, error) {
		return io.NopCloser(io.NewSectionReader(file, offset, size)), nil
	}
	if err = ReadRange(context.Background(), &out, source, row.Manifest.Encoding, 0, row.Manifest.Encoding.RawBytes); err != nil || !bytes.Equal(out.Bytes(), original) {
		t.Fatal("落盘制品与原包不一致", err)
	}
	good := acknowledgement(row)
	for _, mutate := range []func(*Acknowledgement){func(v *Acknowledgement) { v.ManifestSHA256 = Digest([]byte("other")) }, func(v *Acknowledgement) { v.RawSHA256 = Digest([]byte("other")) }, func(v *Acknowledgement) { v.StoredSHA256 = Digest([]byte("other")) }, func(v *Acknowledgement) { v.StoredBytes++ }, func(v *Acknowledgement) { v.ObjectVersion = "" }, func(v *Acknowledgement) { v.ExpiresAt = time.Now().Add(-time.Hour) }} {
		bad := good
		mutate(&bad)
		if err = s.Confirm(bad); err == nil {
			t.Fatal("不完整确认被接受")
		}
		if got, e := os.ReadFile(rawPath); e != nil || !bytes.Equal(got, original) {
			t.Fatal("原始文件被提前回收", e)
		}
	}
	used, err := s.Reserved()
	if err != nil || used < 3*1024*1024 {
		t.Fatal(used, err)
	}
	if err = s.Confirm(good); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{".raw", ".stored"} {
		path, _ := s.path(row.ID, suffix)
		if _, err = os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("确认后仍占用载荷缓存", err)
		}
	}
	used, err = s.Reserved()
	if err != nil || used != 0 {
		t.Fatal(used, err)
	}
	confirmed, err := s.Record(row.ID)
	if err != nil || confirmed.State != "confirmed" || confirmed.Acknowledgement == nil {
		t.Fatal(err)
	}
	if err = s.Confirm(good); err != nil {
		t.Fatal("幂等确认失败", err)
	}
	bad := good
	bad.ObjectVersion = "different_version"
	if err = s.Confirm(bad); err == nil {
		t.Fatal("确认版本漂移被接受")
	}
}

func TestSpoolInterruptedCaptureRetainsBytesAndRemainsQuarantined(t *testing.T) {
	s, db := testSpool(t)
	header := captureHeader()
	header.ID = "packet_interrupted"
	p, err := s.Begin(header)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte{1, 2, 3, 4}
	if err = p.Recorder.Write(gopacket.CaptureInfo{Timestamp: header.StartedAt, CaptureLength: 4, Length: 4}, data, nil); err != nil {
		t.Fatal(err)
	}
	if err = p.Recorder.Flush(); err != nil {
		t.Fatal(err)
	}
	if err = p.File.Sync(); err != nil {
		t.Fatal(err)
	}
	if err = p.File.Close(); err != nil {
		t.Fatal(err)
	}
	path, _ := s.path(header.ID, ".part")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := NewSpool(db, s.Dir, s.TenantID, s.SensorID, s.RegistrationID, s.Quota, s.SegmentBytes)
	if err != nil {
		t.Fatal(err)
	}
	row, err := recovered.Record(header.ID)
	if err != nil || row.State != "quarantined" || row.Code != "capture_interrupted" {
		t.Fatal(row, err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("中断现场字节丢失", err)
	}
	if _, err = recovered.Prepare(context.Background(), row.ID, "zstd"); err == nil {
		t.Fatal("中断文件被误认为完整切片")
	}
	if _, err = NewSpool(db, s.Dir, "other_tenant", s.SensorID, s.RegistrationID, s.Quota, s.SegmentBytes); err == nil {
		t.Fatal("原包归属被改写")
	}
}

func TestSpoolQuotasAbortsAndEncodingFailuresDoNotDiscardEvidence(t *testing.T) {
	s, _ := testSpool(t)
	header := captureHeader()
	header.ID = "packet_abort"
	p, err := s.Begin(header)
	if err != nil {
		t.Fatal(err)
	}
	if err = p.Abort("capture_source_unavailable"); err != nil {
		t.Fatal(err)
	}
	if err = p.Abort("again"); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
	if err = p.Seal(header.StartedAt, "shutdown", nil); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
	if _, err = s.Begin(header); err == nil {
		t.Fatal("相同原包身份被覆盖")
	}
	bad := header
	bad.ID = "packet_foreign"
	bad.RegistrationID = "other_registration"
	if _, err = s.Begin(bad); err == nil {
		t.Fatal("归属边界无效")
	}
	bad = header
	bad.ID = "packet_bad_mac"
	bad.InterfaceMAC = "bad"
	before, _ := s.Reserved()
	if _, err = s.Begin(bad); err == nil {
		t.Fatal("无效捕获身份被接受")
	}
	after, _ := s.Reserved()
	if before != after {
		t.Fatal("无效参数消耗原包额度")
	}
	row := readyCapture(t, s, "packet_encoding")
	if retry, err := s.Prepare(context.Background(), row.ID, "none"); err != nil || retry.ManifestSHA256 != row.ManifestSHA256 {
		t.Fatal("已封存编码被重新解释", err)
	}
	rows, err := s.List()
	if err != nil || len(rows) != 2 {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		h := captureHeader()
		h.ID = ""
		active, e := s.Begin(h)
		if e != nil {
			t.Fatal(e)
		}
		if e = active.Abort("capture_failure"); e != nil {
			t.Fatal(e)
		}
	}
	h := captureHeader()
	h.ID = "packet_quota"
	if _, err = s.Begin(h); !errors.Is(err, ErrQuota) {
		t.Fatal("容量不足未阻止新切片", err)
	}
	if _, err = s.Record("../outside"); err == nil {
		t.Fatal("路径穿越被接受")
	}
	if _, err = s.Record("packet_absent"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
}

func TestSpoolClosedDatabaseAndDamagedFilesFailClosed(t *testing.T) {
	t.Run("取消编码保留原包", func(t *testing.T) {
		s, _ := testSpool(t)
		h := captureHeader()
		h.ID = "packet_cancel"
		p, err := s.Begin(h)
		if err != nil {
			t.Fatal(err)
		}
		if err = p.Seal(h.StartedAt, "shutdown", nil); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err = s.Prepare(ctx, h.ID, "zstd"); !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
		row, err := s.Record(h.ID)
		if err != nil || row.State != "sealed" {
			t.Fatal(err)
		}
		path, _ := s.path(h.ID, ".raw")
		if _, err = os.Stat(path); err != nil {
			t.Fatal("原包被删除", err)
		}
	})
	t.Run("制品截断", func(t *testing.T) {
		s, _ := testSpool(t)
		row := readyCapture(t, s, "packet_short")
		path, _ := s.path(row.ID, ".stored")
		if err := os.Chmod(path, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Truncate(path, 1); err != nil {
			t.Fatal(err)
		}
		if _, _, err := s.OpenStored(row.ID); err == nil {
			t.Fatal("制品长度漂移被接受")
		}
	})
	t.Run("原包路径被替换", func(t *testing.T) {
		s, _ := testSpool(t)
		h := captureHeader()
		h.ID = "packet_symlink"
		p, err := s.Begin(h)
		if err != nil {
			t.Fatal(err)
		}
		if err = p.Seal(h.StartedAt, "shutdown", nil); err != nil {
			t.Fatal(err)
		}
		path, _ := s.path(h.ID, ".raw")
		if err = os.Rename(path, path+".retained"); err != nil {
			t.Fatal(err)
		}
		if err = os.Symlink(path+".retained", path); err != nil {
			t.Fatal(err)
		}
		if _, err = s.Prepare(context.Background(), h.ID, "zstd"); err == nil {
			t.Fatal("符号链接原包被接受")
		}
	})
	t.Run("事务连接中断", func(t *testing.T) {
		s, db := testSpool(t)
		row := readyCapture(t, s, "packet_db_closed")
		path, _ := s.path(row.ID, ".raw")
		before, _ := os.ReadFile(path)
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		if err := s.Confirm(acknowledgement(row)); err == nil {
			t.Fatal("数据库不可用仍确认回收")
		}
		after, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("事务失败破坏原包", err)
		}
	})
}
