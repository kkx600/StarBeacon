package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func stoppedSpoolFixture(t *testing.T) (*CaptureSupervisor, *EVEReader) {
	t.Helper()
	s, reader := rotationFixture(t)
	if err := os.Remove(s.rotationPath()); err != nil {
		t.Fatal(err)
	}
	s.Engine.Config.SuricataPIDFile = filepath.Join(s.root, "engine.pid")
	s.Engine.Config.SuricataSocket = filepath.Join(s.root, "engine.sock")
	s.Engine.Config.CaptureRotateBytes = 1
	s.Engine.Config.CaptureSpoolBytes = int64(len(eveSample) + 1)
	s.state.Managed = true
	s.state.Status, s.state.ErrorCode = "failed", "capture_spool_full"
	return s, reader
}

func TestCaptureStoppedSpoolReclaimsOnlyPersistedSource(t *testing.T) {
	s, reader := stoppedSpoolFixture(t)
	before, err := s.WAL.Source()
	if err != nil || s.withinSpoolBudget() {
		t.Fatal("容量保护前提不成立", err)
	}
	if err = s.rotate(context.Background()); err != nil {
		t.Fatal(err)
	}
	rotation, err := s.readRotation()
	if err != nil || rotation.Source != before {
		t.Fatal("封存没有绑定持久来源", err)
	}
	sealed := filepath.Join(s.root, rotation.Name)
	if _, err = os.Stat(sealed); err != nil || s.withinSpoolBudget() {
		t.Fatal("未完成来源切换就释放额度", err)
	}
	if after, _ := s.WAL.Source(); after != before {
		t.Fatal("停机轮转推进了读取检查点")
	}
	if err = reader.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = s.rotate(context.Background()); err != nil || !s.withinSpoolBudget() {
		t.Fatal("持久排空后仍无法恢复额度", err)
	}
	if _, err = os.Stat(sealed); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("已排空的封存来源未回收", err)
	}
	batch, err := s.WAL.Next("alerts")
	if err != nil || batch == nil || len(batch.Records) != 1 || batch.Records[0].SourceGenerationId != before.Generation {
		t.Fatal("回收改变了未确认的待传事件", err)
	}
	after, err := s.WAL.Source()
	if err != nil || after.Offset != 0 || after.Generation == before.Generation || after.FileID == before.FileID || s.Snapshot().Rotations != "1" {
		t.Fatal("后继来源或轮转状态未持久化", err)
	}
}

func TestCaptureStoppedSpoolWaitsForWALCapacityWithoutDiscardingEvents(t *testing.T) {
	s, reader := stoppedSpoolFixture(t)
	before, _ := s.WAL.Source()
	file, err := os.OpenFile(reader.Path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := file.WriteString(eveSample + "\n")
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatal(writeErr, closeErr)
	}
	if err = s.rotate(context.Background()); err != nil {
		t.Fatal(err)
	}
	rotation, _ := s.readRotation()
	sealed := filepath.Join(s.root, rotation.Name)
	s.WAL.MaxBytes = 1
	if err = reader.Poll(context.Background()); !errors.Is(err, ErrWALFull) {
		t.Fatal("待传队列满时未保留来源", err)
	}
	if err = s.rotate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if after, _ := s.WAL.Source(); after != before {
		t.Fatal("背压导致检查点越过未持久记录")
	}
	if info, err := os.Stat(sealed); err != nil || info.Size() != 2*int64(len(eveSample)+1) {
		t.Fatal("背压导致封存数据丢失", err)
	}
	s.WAL.MaxBytes = 8 << 20
	if err = reader.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = s.rotate(context.Background()); err != nil || !s.withinSpoolBudget() {
		t.Fatal("队列恢复后缓冲未回收", err)
	}
	batch, err := s.WAL.Next("alerts")
	if err != nil || batch == nil || len(batch.Records) != 2 || batch.Records[0].EventId == batch.Records[1].EventId || batch.Records[1].SourceOffset != before.Offset {
		t.Fatal("恢复前后事件身份或字节位置不一致", err)
	}
}

func TestCaptureStoppedSpoolRejectsUnconfirmedWriterMarkers(t *testing.T) {
	for _, mode := range []string{"pid", "socket", "symlink", "outside", "empty"} {
		t.Run(mode, func(t *testing.T) {
			s, reader := stoppedSpoolFixture(t)
			path := s.Engine.Config.SuricataPIDFile
			switch mode {
			case "socket":
				path = s.Engine.Config.SuricataSocket
			case "outside":
				s.Engine.Config.SuricataPIDFile = filepath.Join(s.root, "other.pid")
			case "empty":
				s.Engine.Config.SuricataSocket = ""
			}
			if mode == "symlink" {
				if err := os.Symlink(reader.Path, path); err != nil {
					t.Fatal(err)
				}
			} else if mode == "pid" || mode == "socket" {
				if err := os.WriteFile(path, []byte("unconfirmed"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			before, _ := s.WAL.Source()
			if err := s.rotate(context.Background()); err == nil {
				t.Fatal("未知写端仍允许封存", mode)
			}
			if after, _ := s.WAL.Source(); after != before {
				t.Fatal("写端核对失败改变了来源")
			}
			if _, err := os.Stat(reader.Path); err != nil {
				t.Fatal("写端核对失败改变了当前文件", err)
			}
			if _, err := os.Stat(s.rotationPath()); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("写端核对前建立了轮转记录", err)
			}
		})
	}
}

func TestCaptureStoppedSpoolDoesNotRecoverOtherFailureStates(t *testing.T) {
	for _, mode := range []string{"unmanaged", "active", "pid", "stopped", "other_failure"} {
		t.Run(mode, func(t *testing.T) {
			s, reader := stoppedSpoolFixture(t)
			switch mode {
			case "unmanaged":
				s.state.Managed = false
			case "active":
				s.active = &captureProcess{}
			case "pid":
				s.state.PID = 1234
			case "stopped":
				s.state.Status = "stopped"
			case "other_failure":
				s.state.ErrorCode = "capture_process_or_configuration_changed"
			}
			before, _ := s.WAL.Source()
			if err := s.rotate(context.Background()); err != nil {
				t.Fatal(err)
			}
			if after, _ := s.WAL.Source(); after != before {
				t.Fatal("其它状态推进了来源")
			}
			if _, err := os.Stat(reader.Path); err != nil {
				t.Fatal("其它状态封存了当前来源", err)
			}
		})
	}
}
