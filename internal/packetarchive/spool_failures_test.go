package packetarchive

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	bolt "go.etcd.io/bbolt"
)

func TestSpoolRejectsUnavailablePrivateDirectoryAndIdentity(t *testing.T) {
	s, db := testSpool(t)
	if _, err := NewSpool(nil, s.Dir, s.TenantID, s.SensorID, s.RegistrationID, s.Quota, s.SegmentBytes); !errors.Is(err, ErrQuota) {
		t.Fatal("无持久目录数据库可启动", err)
	}
	if _, err := s.path("bad/id", ".raw"); !errors.Is(err, ErrIntegrity) {
		t.Fatal("路径身份未拒绝", err)
	}
	for _, kind := range []string{"open_permissions", "symlink", "parent_file"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "packets")
			switch kind {
			case "open_permissions":
				if err := os.Mkdir(path, 0755); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink(s.Dir, path); err != nil {
					t.Fatal(err)
				}
			case "parent_file":
				if err := os.WriteFile(path, []byte("foreign"), 0600); err != nil {
					t.Fatal(err)
				}
				path = filepath.Join(path, "child")
			}
			if _, err := NewSpool(db, path, s.TenantID, s.SensorID, s.RegistrationID, s.Quota, s.SegmentBytes); err == nil {
				t.Fatal("不可信原包目录可启动")
			}
		})
	}
}

func TestSpoolFileCreationAndSealFailuresPreserveRecoveryEvidence(t *testing.T) {
	for _, kind := range []string{"occupied_part", "closed_handle", "rename_conflict"} {
		t.Run(kind, func(t *testing.T) {
			s, _ := testSpool(t)
			h := captureHeader()
			h.ID = "packet_io_failure"
			part, _ := s.path(h.ID, ".part")
			if kind == "occupied_part" {
				if err := os.WriteFile(part, []byte("untracked_evidence"), 0600); err != nil {
					t.Fatal(err)
				}
				if _, err := s.Begin(h); err == nil {
					t.Fatal("已有原包被覆盖")
				}
				raw, err := os.ReadFile(part)
				if err != nil || string(raw) != "untracked_evidence" {
					t.Fatal("未知文件被改写")
				}
				row, err := s.Record(h.ID)
				if err != nil || row.State != "quarantined" || row.Code != "capture_file_unavailable" {
					t.Fatal("创建失败未留下可诊断结果", err)
				}
				return
			}
			p, err := s.Begin(h)
			if err != nil {
				t.Fatal(err)
			}
			data := []byte{1, 2, 3}
			if err = p.Recorder.Write(gopacket.CaptureInfo{Timestamp: h.StartedAt, CaptureLength: 3, Length: 3}, data, nil); err != nil {
				t.Fatal(err)
			}
			if kind == "closed_handle" {
				if err = p.File.Close(); err != nil {
					t.Fatal(err)
				}
			} else {
				raw, _ := s.path(h.ID, ".raw")
				if err = os.Mkdir(raw, 0700); err != nil {
					t.Fatal(err)
				}
			}
			if err = p.Seal(h.StartedAt.Add(time.Second), "rotation", nil); err == nil {
				t.Fatal("不确定封存返回成功")
			}
			row, err := s.Record(h.ID)
			if err != nil || row.State != "quarantined" || row.ReservedBytes <= 0 {
				t.Fatal("失败封存丢失现场或提前释放预算", err)
			}
		})
	}
}

func sealedFailureCapture(t *testing.T, s *Spool) LocalRecord {
	t.Helper()
	h := captureHeader()
	h.ID = "packet_prepare_failure"
	p, err := s.Begin(h)
	if err != nil {
		t.Fatal(err)
	}
	data := bytes.Repeat([]byte{7}, 32)
	if err = p.Recorder.Write(gopacket.CaptureInfo{Timestamp: h.StartedAt, CaptureLength: len(data), Length: len(data)}, data, nil); err != nil {
		t.Fatal(err)
	}
	if err = p.Seal(h.StartedAt.Add(time.Second), "rotation", nil); err != nil {
		t.Fatal(err)
	}
	row, err := s.Record(h.ID)
	if err != nil {
		t.Fatal(err)
	}
	return row
}

func TestSpoolEncodingFailuresNeverAdvertiseReadyObject(t *testing.T) {
	for _, kind := range []string{"missing_raw", "invalid_codec", "rename_conflict", "orphan_quota", "bad_manifest", "invalid_usage"} {
		t.Run(kind, func(t *testing.T) {
			s, db := testSpool(t)
			row := sealedFailureCapture(t, s)
			rawPath, _ := s.path(row.ID, ".raw")
			codec := "zstd"
			switch kind {
			case "missing_raw":
				if err := os.Remove(rawPath); err != nil {
					t.Fatal(err)
				}
			case "invalid_codec":
				codec = "zip"
			case "rename_conflict":
				stored, _ := s.path(row.ID, ".stored")
				if err := os.Mkdir(stored, 0700); err != nil {
					t.Fatal(err)
				}
			case "orphan_quota":
				f, err := os.OpenFile(filepath.Join(s.Dir, "untracked"), os.O_CREATE|os.O_WRONLY, 0600)
				if err != nil {
					t.Fatal(err)
				}
				err = f.Truncate(s.Quota)
				_ = f.Close()
				if err != nil {
					t.Fatal(err)
				}
			case "bad_manifest":
				row.Capture.EndedAt = time.Time{}
				encoded, _ := json.Marshal(row)
				if err := db.Update(func(tx *bolt.Tx) error { return tx.Bucket(spoolBucket).Put([]byte(row.ID), encoded) }); err != nil {
					t.Fatal(err)
				}
			case "invalid_usage":
				if err := db.Update(func(tx *bolt.Tx) error { return tx.Bucket(spoolUsage).Put([]byte("reserved"), []byte("broken")) }); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.Prepare(context.Background(), row.ID, codec); err == nil {
				t.Fatal("编码资格失败返回可上传对象", kind)
			}
			after, err := s.Record(row.ID)
			if err != nil || after.State != "sealed" || after.Manifest != nil {
				t.Fatal("失败派生被当成持久证据", err)
			}
			files, err := os.ReadDir(s.Dir)
			if err != nil {
				t.Fatal(err)
			}
			for _, file := range files {
				if strings.HasPrefix(file.Name(), ".packet-encoding-") {
					t.Fatal("失败编码遗留派生临时文件")
				}
			}
		})
	}
}

func TestSpoolAcknowledgedCleanupResumesWithoutGuessingConfirmation(t *testing.T) {
	s, _ := testSpool(t)
	row := readyCapture(t, s, "packet_confirm_cleanup")
	ack := Acknowledgement{ID: row.ID, ManifestSHA256: row.ManifestSHA256, RawSHA256: row.Manifest.Encoding.RawSHA256, StoredSHA256: row.Manifest.Encoding.StoredSHA256, StoredBytes: row.Manifest.Encoding.StoredBytes, ObjectVersion: "owned_version", ExpiresAt: time.Now().UTC().Add(time.Hour)}
	path, _ := s.path(row.ID, ".raw")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := s.Confirm(ack); !errors.Is(err, ErrIntegrity) {
		t.Fatal("非法回收路径被当成全部确认", err)
	}
	retained, err := s.Record(row.ID)
	if err != nil || retained.State != "acknowledged" || retained.ReservedBytes <= 0 {
		t.Fatal("持久确认边界丢失", err)
	}
	changed := ack
	changed.ExpiresAt = changed.ExpiresAt.Add(time.Hour)
	if err = s.Confirm(changed); !errors.Is(err, ErrIntegrity) {
		t.Fatal("重试改变了原回执期限", err)
	}
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err = s.Confirm(ack); err != nil {
		t.Fatal("已确认的回收不能恢复", err)
	}
	final, err := s.Record(row.ID)
	if err != nil || final.State != "confirmed" || final.ReservedBytes != 0 {
		t.Fatal("回收账目未同步", err)
	}
	if _, _, err = s.OpenStored(row.ID); !errors.Is(err, ErrIntegrity) {
		t.Fatal("已经回收的原包可重新下载", err)
	}
	if err = s.Quarantine(row.ID, "operator_retry"); !errors.Is(err, ErrIntegrity) {
		t.Fatal("确认对象可重新进入原包队列", err)
	}
	if err = s.Quarantine(row.ID, "bad/code"); !errors.Is(err, ErrIntegrity) {
		t.Fatal("非法隔离原因可保存", err)
	}
}
