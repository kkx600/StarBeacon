package agent

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func rotationFixture(t *testing.T) (*CaptureSupervisor, *EVEReader) {
	t.Helper()
	w, r, path := readerFor(t, 8*1024*1024)
	root := filepath.Dir(path)
	e := captureFixture(t)
	e.WAL, e.Config.EVEPath = w, path
	s := &CaptureSupervisor{Engine: e, WAL: w, root: root}
	r.CanSwitch = s.CanSwitchSource
	if err := r.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	source, err := w.Source()
	if err != nil {
		t.Fatal(err)
	}
	rotation := &captureRotation{Version: 1, Phase: "prepared", Name: "eve-segment_" + strings.Repeat("a", 32) + ".json", Source: source}
	if err := s.saveRotation(rotation); err != nil {
		t.Fatal(err)
	}
	return s, r
}

func TestCaptureRotationDrainsSourceBeforeReclaimAndRecoversEmptySuccessor(t *testing.T) {
	s, r := rotationFixture(t)
	original, _ := s.WAL.Source()
	if err := s.rotate(context.Background()); err != nil {
		t.Fatal(err)
	}
	rotation, err := s.readRotation()
	if err != nil {
		t.Fatal(err)
	}
	sealed := filepath.Join(s.root, rotation.Name)
	if _, err = os.Stat(sealed); err != nil || !s.Snapshot().RotationPending {
		t.Fatal("未读来源被提前删除", err)
	}
	file, err := os.OpenFile(sealed, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = file.WriteString(eveSample + "\n"); err != nil {
		t.Fatal(err)
	}
	_ = file.Close()
	if err = r.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	after, err := s.WAL.Source()
	if err != nil || after.FileID == original.FileID || after.Offset != 0 {
		t.Fatal("空后继的来源切换没有持久化", after, err)
	}
	drained, err := s.WAL.DrainedSource()
	if err != nil || drained.Offset != 2*uint64(len(eveSample)+1) || drained.Generation != original.Generation {
		t.Fatal("排空位置未与来源切换同事务保存", drained, err)
	}
	if err = s.rotate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(sealed); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("已持久复制的来源未回收", err)
	}
	if s.Snapshot().RotationPending || s.Snapshot().Rotations != "1" {
		t.Fatal("轮转状态不一致", s.Snapshot())
	}
	batch, err := s.WAL.Next("alerts")
	if err != nil || len(batch.Records) != 2 || batch.Records[0].EventId == batch.Records[1].EventId {
		t.Fatal("轮转改变队列身份或丢弃待传数据", err)
	}
	if err = r.Close(); err != nil {
		t.Fatal(err)
	}
	r.file = nil
	if err = r.Poll(context.Background()); err != nil {
		t.Fatal("旧文件回收后的重启不能继续空后继", err)
	}
	file, err = os.OpenFile(r.Path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, err = file.WriteString(eveSample + "\n")
	_ = file.Close()
	if err != nil {
		t.Fatal(err)
	}
	if err = r.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	batch, err = s.WAL.Next("alerts")
	if err != nil || len(batch.Records) != 3 || batch.Records[2].SourceGenerationId == original.Generation {
		t.Fatal("后继来源未产生独立事件身份", err)
	}
}

func TestCaptureRotationInterruptedCleanupOnlyAcceptsCommittedDrain(t *testing.T) {
	for _, mode := range []string{"prepared_missing", "drained_resume", "drained_changed", "source_prefix", "unread_bytes", "sealed_symlink", "successor_symlink"} {
		t.Run(mode, func(t *testing.T) {
			s, r := rotationFixture(t)
			if err := s.rotate(context.Background()); err != nil {
				t.Fatal(err)
			}
			rotation, err := s.readRotation()
			if err != nil {
				t.Fatal(err)
			}
			sealed := filepath.Join(s.root, rotation.Name)
			switch mode {
			case "source_prefix":
				_ = os.WriteFile(sealed, []byte(strings.Repeat("x", len(eveSample)+1)), 0600)
			case "prepared_missing":
				_ = os.Remove(sealed)
			case "sealed_symlink":
				_ = os.Remove(sealed)
				_ = os.Symlink(r.Path, sealed)
			case "successor_symlink":
				_ = os.Remove(r.Path)
				_ = os.Symlink(sealed, r.Path)
			default:
				if err = r.Poll(context.Background()); err != nil {
					t.Fatal(err)
				}
				source, _ := s.WAL.Source()
				drained, _ := s.WAL.DrainedSource()
				if mode == "unread_bytes" {
					file, err := os.OpenFile(sealed, os.O_APPEND|os.O_WRONLY, 0600)
					if err != nil {
						t.Fatal(err)
					}
					_, err = file.WriteString("{}\n")
					_ = file.Close()
					if err != nil {
						t.Fatal(err)
					}
				} else {
					rotation.Phase, rotation.NextFileID, rotation.NextGeneration, rotation.DrainedBytes = "drained", source.FileID, source.Generation, drained.Offset
					if mode == "drained_changed" {
						rotation.NextGeneration = "changed_generation"
					}
					if err = s.saveRotation(rotation); err != nil {
						t.Fatal(err)
					}
					_ = os.Remove(sealed)
				}
			}
			before, _ := s.WAL.Source()
			err = s.rotate(context.Background())
			if mode == "drained_resume" {
				if err != nil || s.Snapshot().Rotations != "1" {
					t.Fatal("已提交的中断清理不可恢复", err)
				}
				return
			}
			if err == nil {
				t.Fatal("未核对的来源被清理", mode)
			}
			if after, _ := s.WAL.Source(); after != before {
				t.Fatal("失败清理推进来源位置")
			}
			if _, err = os.Lstat(s.rotationPath()); err != nil {
				t.Fatal("失败清理删除了恢复记录", err)
			}
		})
	}
}

func TestCaptureRotationMetadataAndStorageBoundaries(t *testing.T) {
	s, r := rotationFixture(t)
	valid, err := s.readRotation()
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*captureRotation){func(v *captureRotation) { v.Version = 2 }, func(v *captureRotation) { v.Name = "../eve.json" }, func(v *captureRotation) { v.Phase = "unknown" }, func(v *captureRotation) { v.Source.FileID = "" }, func(v *captureRotation) { v.Source.Generation = "" }, func(v *captureRotation) { v.Source.PrefixBytes = 257 }, func(v *captureRotation) { v.Source.PrefixSHA256 = "bad" }, func(v *captureRotation) { v.Phase = "drained" }} {
		value := *valid
		change(&value)
		if err = s.saveRotation(&value); err != nil {
			t.Fatal(err)
		}
		if _, err = s.readRotation(); err == nil {
			t.Fatal("坏轮转记录被接受", value)
		}
	}
	if err = os.WriteFile(s.rotationPath(), []byte(`{`), 0600); err != nil {
		t.Fatal(err)
	}
	if err = s.rotate(context.Background()); err == nil {
		t.Fatal("坏持久记录未阻止轮转")
	}
	if err = s.saveRotation(valid); err != nil {
		t.Fatal(err)
	}
	if ready, err := s.CanSwitchSource(context.Background(), "other"); ready || err == nil {
		t.Fatal("错来源被接受")
	}
	s.op.Lock()
	ready, err := s.CanSwitchSource(context.Background(), valid.Source.FileID)
	s.op.Unlock()
	if ready || err != nil {
		t.Fatal("并发轮转没有等待")
	}
	before, _ := s.WAL.Source()
	next := Source{FileID: "other", Generation: "next"}
	for _, value := range []Source{{}, {FileID: before.FileID, Generation: "next"}, {FileID: "other", Generation: before.Generation}, {FileID: "other", Generation: "next", Offset: 1}, {FileID: "other", Generation: "next", PrefixBytes: 1}} {
		if err = s.WAL.SwitchSource(before, value); err == nil {
			t.Fatal("坏后继被接受", value)
		}
	}
	stale := before
	stale.Offset++
	if err = s.WAL.SwitchSource(stale, next); err == nil {
		t.Fatal("陈旧读取覆盖了来源")
	}
	if err = s.WAL.SwitchSource(before, next); err != nil {
		t.Fatal(err)
	}
	if err = r.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if after, _ := s.WAL.Source(); after != next {
		t.Fatal("失败比较交换改变来源")
	}
	file := filepath.Join(s.root, "eve-segment_"+strings.Repeat("b", 32)+".json")
	if err = os.WriteFile(file, []byte("held"), 0600); err != nil {
		t.Fatal(err)
	}
	used, err := s.spoolUsage()
	if err != nil || used != int64(len(eveSample)+1+4) {
		t.Fatal("封存文件没有占用采集额度", used, err)
	}
	_ = os.Remove(file)
	_ = os.Symlink(r.Path, file)
	if s.withinSpoolBudget() {
		t.Fatal("特殊缓冲来源被接受")
	}
}

func TestEVEWaitingWriterAndEmptyInitialRotation(t *testing.T) {
	for _, initialEmpty := range []bool{false, true} {
		t.Run(map[bool]string{false: "open_writer", true: "empty_initial"}[initialEmpty], func(t *testing.T) {
			w, r, path := readerFor(t, 8*1024*1024)
			if initialEmpty {
				_ = os.WriteFile(path, nil, 0600)
			}
			if err := r.Poll(context.Background()); err != nil {
				t.Fatal(err)
			}
			before, _ := w.Source()
			old := path + ".1"
			if err := os.Rename(path, old); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, nil, 0600); err != nil {
				t.Fatal(err)
			}
			allow := false
			r.CanSwitch = func(context.Context, string) (bool, error) { return allow, nil }
			if err := r.Poll(context.Background()); err != nil {
				t.Fatal(err)
			}
			if after, _ := w.Source(); after != before {
				t.Fatal("写端尚未封存就切换来源")
			}
			if !initialEmpty {
				file, err := os.OpenFile(old, os.O_APPEND|os.O_WRONLY, 0600)
				if err != nil {
					t.Fatal(err)
				}
				_, err = file.WriteString(eveSample + "\n")
				_ = file.Close()
				if err != nil {
					t.Fatal(err)
				}
			}
			allow = true
			if err := r.Poll(context.Background()); err != nil {
				t.Fatal(err)
			}
			after, _ := w.Source()
			if after.FileID == before.FileID || after.Generation == "" || after.Offset != 0 {
				t.Fatal("后继来源没有持久化", after)
			}
			if err := r.Close(); err != nil {
				t.Fatal(err)
			}
			r.file = nil
			_ = os.Remove(old)
			if err := r.Poll(context.Background()); err != nil {
				t.Fatal("空后继不能恢复", err)
			}
			if !initialEmpty {
				batch, err := w.Next("alerts")
				if err != nil || len(batch.Records) != 2 {
					t.Fatal("封存前写入的尾部记录丢失", err)
				}
			}
		})
	}
}

func TestCaptureProcessStartFailureDoesNotLeakWaitThread(t *testing.T) {
	command := exec.Command(filepath.Join(t.TempDir(), "missing-capture-engine"))
	command.SysProcAttr = captureProcessAttributes()
	done := make(chan struct{})
	if err := startCaptureProcess(command, done); err == nil {
		t.Fatal("不存在的程序被启动")
	}
	<-done
}
