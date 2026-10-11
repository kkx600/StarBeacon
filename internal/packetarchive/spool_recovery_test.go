package packetarchive

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	bolt "go.etcd.io/bbolt"
)

func TestUploadCursorIsIndependentOfQuarantinedHistory(t *testing.T) {
	s, db := testSpool(t)
	// 大量故障现场只构造元数据，不冒充实际捕获或容量性能测量。
	if err := db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(spoolBucket)
		for i := 0; i < 8000; i++ {
			h := captureHeader()
			h.ID = fmt.Sprintf("packet_quarantine_%05d", i)
			seq, err := b.NextSequence()
			if err != nil {
				return err
			}
			row := LocalRecord{ID: h.ID, State: "quarantined", Code: "capture_interrupted", Capture: h, Sequence: seq}
			raw, err := json.Marshal(row)
			if err != nil {
				return err
			}
			if err = b.Put([]byte(row.ID), raw); err != nil {
				return err
			}
			if err = indexRecord(tx, row); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	row := readyCapture(t, s, "packet_deliverable")
	if err := db.View(func(tx *bolt.Tx) error {
		if tx.Bucket(spoolQueue).Stats().KeyN != 8001 || tx.Bucket(spoolWork).Stats().KeyN != 1 {
			t.Fatal("上传队列包含故障历史")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// 历史摘要损坏也不能阻塞独立的上传游标；目录读取仍必须报告损坏。
	if err := db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(spoolIndex).Put([]byte("packet_quarantine_07999"), []byte("corrupt"))
	}); err != nil {
		t.Fatal(err)
	}
	got, err := s.NextPending()
	if err != nil || got.ID != row.ID {
		t.Fatal("历史隔离记录阻塞原包传输", err)
	}
	if _, err = s.List(); !errors.Is(err, ErrIntegrity) {
		t.Fatal("损坏目录被掩盖", err)
	}
	if err = s.Quarantine(row.ID, "integrity_failure"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.NextPending(); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("已隔离记录仍被重复上传", err)
	}
	if info, err := os.Stat(filepath.Join(s.Dir, row.ID+".raw")); err != nil || info.Size() == 0 {
		t.Fatal("隔离删除了原件", err)
	}
}

func TestSpoolRebuildsDerivedQueuesWithoutChangingOriginals(t *testing.T) {
	s, db := testSpool(t)
	first := readyCapture(t, s, "packet_first")
	second := readyCapture(t, s, "packet_second")
	if err := s.Quarantine(first.ID, "capture_failure"); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(s.Dir, second.ID+".raw"))
	if err != nil {
		t.Fatal(err)
	}
	used, err := s.Reserved()
	if err != nil {
		t.Fatal(err)
	}
	// 旧版暂存目录没有工作索引；启动必须从持久记录恢复同一 FIFO。
	if err = db.Update(func(tx *bolt.Tx) error { return tx.DeleteBucket(spoolWork) }); err != nil {
		t.Fatal(err)
	}
	rebuilt, err := NewSpool(db, s.Dir, s.TenantID, s.SensorID, s.RegistrationID, s.Quota, s.SegmentBytes)
	if err != nil {
		t.Fatal(err)
	}
	got, err := rebuilt.NextPending()
	if err != nil || got.ID != second.ID || got.ManifestSHA256 != second.ManifestSHA256 {
		t.Fatal("恢复改变了待传对象", err)
	}
	after, err := os.ReadFile(filepath.Join(s.Dir, second.ID+".raw"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("恢复改变了捕获原字节", err)
	}
	if now, err := rebuilt.Reserved(); err != nil || now != used {
		t.Fatal("恢复改变了容量账目", err)
	}
	if err = rebuilt.Confirm(acknowledgement(second)); err != nil {
		t.Fatal(err)
	}
	if _, err = rebuilt.NextPending(); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("确认对象仍在传输队列", err)
	}
	rows, err := rebuilt.List()
	if err != nil || len(rows) != 2 || rows[0].State != "confirmed" || rows[1].State != "quarantined" {
		t.Fatal("恢复丢失已确认或故障记录", err)
	}
}

func TestSpoolCursorRejectsIdentityStateAndSequenceDrift(t *testing.T) {
	for _, kind := range []string{"sequence", "state", "scope", "record_state", "record_scope", "record_corrupt", "work_key", "history_key"} {
		t.Run(kind, func(t *testing.T) {
			s, db := testSpool(t)
			row := readyCapture(t, s, "packet_corrupt")
			original, err := os.ReadFile(filepath.Join(s.Dir, row.ID+".raw"))
			if err != nil {
				t.Fatal(err)
			}
			if err = db.Update(func(tx *bolt.Tx) error {
				switch kind {
				case "record_corrupt":
					return tx.Bucket(spoolBucket).Put([]byte(row.ID), []byte("corrupt"))
				case "work_key":
					if err := tx.Bucket(spoolWork).Delete(sequenceKey(row.Sequence)); err != nil {
						return err
					}
					return tx.Bucket(spoolWork).Put([]byte{0}, []byte(row.ID))
				case "history_key":
					return tx.Bucket(spoolQueue).Put([]byte{255}, []byte(row.ID))
				case "record_state", "record_scope":
					if kind == "record_state" {
						row.State = "quarantined"
					} else {
						row.Capture.TenantID = "other_tenant"
					}
					data, err := json.Marshal(row)
					if err != nil {
						return err
					}
					return tx.Bucket(spoolBucket).Put([]byte(row.ID), data)
				default:
					meta := entry(row)
					if kind == "sequence" {
						meta.Sequence++
					} else if kind == "state" {
						meta.State = "quarantined"
					} else {
						meta.Capture.RegistrationID = "other_registration"
					}
					data, err := json.Marshal(meta)
					if err != nil {
						return err
					}
					return tx.Bucket(spoolIndex).Put([]byte(row.ID), data)
				}
			}); err != nil {
				t.Fatal(err)
			}
			if kind == "history_key" {
				if _, err = s.List(); !errors.Is(err, ErrIntegrity) {
					t.Fatal("无效目录游标被接受", err)
				}
			} else if _, err = s.NextPending(); !errors.Is(err, ErrIntegrity) {
				t.Fatal("无效上传对象被接受", err)
			}
			after, err := os.ReadFile(filepath.Join(s.Dir, row.ID+".raw"))
			if err != nil || !bytes.Equal(original, after) {
				t.Fatal("拒绝目录损坏时改变了原件", err)
			}
		})
	}
}

func TestSpoolRecoveryRejectsInvalidPersistentState(t *testing.T) {
	for _, kind := range []string{"sequence_collision", "sequence_future", "negative_reserve", "confirmed_without_ack", "unknown_state", "broken_record"} {
		t.Run(kind, func(t *testing.T) {
			s, db := testSpool(t)
			row := readyCapture(t, s, "packet_recovery")
			if err := db.Update(func(tx *bolt.Tx) error {
				b := tx.Bucket(spoolBucket)
				switch kind {
				case "broken_record":
					return b.Put([]byte(row.ID), []byte("broken"))
				case "sequence_collision":
					copy := row
					copy.ID = "packet_duplicate"
					copy.Capture.ID = copy.ID
					data, err := json.Marshal(copy)
					if err != nil {
						return err
					}
					return b.Put([]byte(copy.ID), data)
				case "sequence_future":
					row.Sequence = b.Sequence() + 1
				case "negative_reserve":
					row.ReservedBytes = -1
				case "confirmed_without_ack":
					row.State = "confirmed"
					row.ReservedBytes = 0
				case "unknown_state":
					row.State = "untrusted"
				}
				data, err := json.Marshal(row)
				if err != nil {
					return err
				}
				return b.Put([]byte(row.ID), data)
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := NewSpool(db, s.Dir, s.TenantID, s.SensorID, s.RegistrationID, s.Quota, s.SegmentBytes); !errors.Is(err, ErrIntegrity) {
				t.Fatal("损坏持久状态被恢复成可传原包", err)
			}
			if _, err := os.Stat(filepath.Join(s.Dir, row.ID+".raw")); err != nil {
				t.Fatal("恢复失败丢失原件", err)
			}
		})
	}
}
