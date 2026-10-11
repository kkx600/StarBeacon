package packetarchive

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	bolt "go.etcd.io/bbolt"
)

func TestConfirmedCacheDoesNotExhaustHighVolumeQueue(t *testing.T) {
	s, _ := testSpool(t)
	for i := 0; i < maxConfirmedCache+7; i++ {
		id := fmt.Sprintf("packet_%06d", i)
		row := readyCapture(t, s, id)
		if err := s.Confirm(acknowledgement(row)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Record("packet_000000"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("正式已确认目录的本地重试缓存未回收", err)
	}
	latest, err := s.Record("packet_000206")
	if err != nil || latest.Manifest != nil || latest.Acknowledgement == nil {
		t.Fatal("确认记录缓存仍保留无界帧目录", err)
	}
	used, err := s.Reserved()
	if err != nil || used != 0 {
		t.Fatal(used, err)
	}
	rows, err := s.List()
	if err != nil || len(rows) != 200 || rows[0].ID != "packet_000206" {
		t.Fatal("列表没有按有界最近记录读取", err)
	}
	row := readyCapture(t, s, "packet_pending")
	if _, err := s.NextPending(); err != nil {
		t.Fatal(err)
	}
	if err = s.Confirm(acknowledgement(row)); err != nil {
		t.Fatal(err)
	}
	if _, err = s.NextPending(); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
}

func TestOrphanedDerivativeCountsTowardQuotaWithoutDeletingBytes(t *testing.T) {
	s, _ := testSpool(t)
	path := filepath.Join(s.Dir, ".packet-encoding-interrupted")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Truncate(s.Quota); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	h := captureHeader()
	h.ID = "packet_no_room"
	if _, err = s.Begin(h); !errors.Is(err, ErrQuota) {
		t.Fatal("未知落盘制品未计入容量", err)
	}
	if info, e := os.Stat(path); e != nil || info.Size() != s.Quota {
		t.Fatal("未知原包或派生现场被自动删除", e)
	}
	if _, err = s.Record(h.ID); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("容量拒绝仍创建占用记录", err)
	}
}

func TestArchiveQueueSkipsQuarantineAndRejectsCorruptIndexes(t *testing.T) {
	s, db := testSpool(t)
	h := captureHeader()
	h.ID = "packet_quarantined"
	p, err := s.Begin(h)
	if err != nil {
		t.Fatal(err)
	}
	if err = p.Abort("source_error"); err != nil {
		t.Fatal(err)
	}
	first := readyCapture(t, s, "packet_first")
	second := readyCapture(t, s, "packet_second")
	got, err := s.NextPending()
	if err != nil || got.ID != first.ID {
		t.Fatal("隔离记录阻塞有序任务", err)
	}
	if err = s.Confirm(acknowledgement(first)); err != nil {
		t.Fatal(err)
	}
	got, err = s.NextPending()
	if err != nil || got.ID != second.ID {
		t.Fatal(err)
	}
	if err = db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(spoolIndex).Put([]byte(second.ID), []byte(`{"id":"foreign"}`))
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.NextPending(); !errors.Is(err, ErrIntegrity) {
		t.Fatal("索引身份漂移被接受", err)
	}
	if _, err = s.List(); !errors.Is(err, ErrIntegrity) {
		t.Fatal(err)
	}
}

func TestSpoolRecoveryRejectsReservedCounterAndScopeDrift(t *testing.T) {
	s, db := testSpool(t)
	row := readyCapture(t, s, "packet_scope")
	if err := db.Update(func(tx *bolt.Tx) error { return tx.Bucket(spoolUsage).Put([]byte("reserved"), []byte("bad")) }); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Reserved(); !errors.Is(err, ErrIntegrity) {
		t.Fatal(err)
	}
	h := captureHeader()
	h.ID = "packet_corrupt_usage"
	if _, err := s.Begin(h); !errors.Is(err, ErrIntegrity) {
		t.Fatal(err)
	}
	recovered, err := NewSpool(db, s.Dir, s.TenantID, s.SensorID, s.RegistrationID, s.Quota, s.SegmentBytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = recovered.Prepare(context.Background(), row.ID, "zstd"); err != nil {
		t.Fatal(err)
	}
	if err = db.Update(func(tx *bolt.Tx) error {
		r := row
		r.Capture.TenantID = "other_tenant"
		raw, _ := json.Marshal(r)
		return tx.Bucket(spoolBucket).Put([]byte(r.ID), raw)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = recovered.Record(row.ID); !errors.Is(err, ErrIntegrity) {
		t.Fatal(err)
	}
	if _, err = NewSpool(db, s.Dir, s.TenantID, s.SensorID, s.RegistrationID, s.Quota, s.SegmentBytes); !errors.Is(err, ErrIntegrity) {
		t.Fatal(err)
	}
}
