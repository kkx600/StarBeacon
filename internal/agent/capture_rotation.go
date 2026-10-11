package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/kkx600/StarBeacon/internal/store"
)

var captureSegmentName = regexp.MustCompile(`^eve-segment_[0-9a-f]{32}\.json$`)
var captureSHA256 = regexp.MustCompile(`^[0-9a-f]{64}$`)

type captureRotation struct {
	Version        int    `json:"version"`
	Phase          string `json:"phase"`
	Name           string `json:"name"`
	Source         Source `json:"source"`
	NextFileID     string `json:"next_file_id,omitempty"`
	NextGeneration string `json:"next_generation,omitempty"`
	DrainedBytes   uint64 `json:"drained_bytes,omitempty"`
}

func (s *CaptureSupervisor) rotationPath() string { return filepath.Join(s.root, "eve-rotation.json") }

func (s *CaptureSupervisor) readRotation() (*captureRotation, error) {
	raw, err := readRegularBounded(s.rotationPath(), 16*1024, true)
	if err != nil {
		return nil, err
	}
	var value captureRotation
	if json.Unmarshal(raw, &value) != nil || value.Version != 1 || !captureSegmentName.MatchString(value.Name) || value.Source.FileID == "" || value.Source.Generation == "" || value.Source.PrefixBytes < 1 || value.Source.PrefixBytes > 256 || !captureSHA256.MatchString(value.Source.PrefixSHA256) || (value.Phase != "prepared" && value.Phase != "drained") {
		return nil, errors.New("EVE 轮转记录不可核对")
	}
	if value.Phase == "drained" && (value.NextFileID == "" || value.NextFileID == value.Source.FileID || value.NextGeneration == "" || value.NextGeneration == value.Source.Generation || value.DrainedBytes < value.Source.Offset) {
		return nil, errors.New("EVE 排空记录不可核对")
	}
	return &value, nil
}

func (s *CaptureSupervisor) saveRotation(value *captureRotation) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return durableFile(s.rotationPath(), raw)
}

// 每次只有一个封存来源。旧文件全部复制进持久队列且来源切换落盘后才能回收。
func (s *CaptureSupervisor) rotate(ctx context.Context) error {
	rotation, err := s.readRotation()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if rotation == nil {
		if !s.Ready() {
			state := s.Snapshot()
			if !state.Managed || s.active != nil || state.PID != 0 || state.Status != "failed" || state.ErrorCode != "capture_spool_full" {
				return nil
			}
			// 容量保护停机后仍需排空封存来源；不得通过截断文件或推进检查点释放额度。
			// 未回收的进程标记表示写端身份尚不明确，保留现场并等待人工核对。
			for name, path := range map[string]string{"engine.pid": s.Engine.Config.SuricataPIDFile, "engine.sock": s.Engine.Config.SuricataSocket} {
				if path != filepath.Join(s.root, name) {
					return errors.New("停止采集的进程标记路径不可核对")
				}
				if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
					return errors.New("停止采集仍有未核对的进程标记")
				}
			}
		}
		info, err := os.Lstat(s.Engine.Config.EVEPath)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil || !info.Mode().IsRegular() {
			return errors.New("EVE 捕获来源不可读取")
		}
		limit := s.Engine.Config.CaptureRotateBytes
		if limit == 0 {
			budget := s.Engine.Config.CaptureSpoolBytes
			if budget == 0 {
				budget = 1024 * 1024 * 1024
			}
			limit = min(64*1024*1024, budget/2)
		}
		if info.Size() < limit {
			return nil
		}
		source, err := s.WAL.Source()
		if err != nil {
			return err
		}
		if source.FileID != fileID(info) || source.Offset == 0 {
			return nil
		}
		if uint64(info.Size()) < source.Offset {
			return errors.New("EVE 文件小于持久来源位置")
		}
		rotation = &captureRotation{Version: 1, Phase: "prepared", Name: "eve-" + store.RandomID("segment_") + ".json", Source: source}
		if err = s.saveRotation(rotation); err != nil {
			return err
		}
	}
	s.mu.Lock()
	s.state.RotationPending = true
	s.mu.Unlock()
	oldPath := filepath.Join(s.root, rotation.Name)
	old, err := os.Lstat(oldPath)
	if errors.Is(err, os.ErrNotExist) && rotation.Phase == "prepared" {
		current, inspectErr := os.Lstat(s.Engine.Config.EVEPath)
		if inspectErr != nil || !current.Mode().IsRegular() || fileID(current) != rotation.Source.FileID {
			return errors.New("EVE 轮转来源已丢失或被替换")
		}
		if err = verifyCapturePrefix(s.Engine.Config.EVEPath, rotation.Source); err != nil {
			return err
		}
		if err = os.Rename(s.Engine.Config.EVEPath, oldPath); err != nil {
			return err
		}
		if err = syncCaptureDirectory(s.root); err != nil {
			return err
		}
		old, err = os.Lstat(oldPath)
	}
	if err != nil && !(errors.Is(err, os.ErrNotExist) && rotation.Phase == "drained") {
		return err
	}
	if old != nil {
		if !old.Mode().IsRegular() || fileID(old) != rotation.Source.FileID || uint64(old.Size()) < rotation.Source.Offset {
			return errors.New("EVE 封存文件已变化")
		}
		if err = verifyCapturePrefix(oldPath, rotation.Source); err != nil {
			return err
		}
	}
	current, err := os.Lstat(s.Engine.Config.EVEPath)
	if errors.Is(err, os.ErrNotExist) {
		// 只建立空的后继文件；事件内容始终由原生引擎写入。
		file, createErr := os.OpenFile(s.Engine.Config.EVEPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if createErr != nil {
			return createErr
		}
		err = file.Sync()
		closed := file.Close()
		if err != nil {
			return err
		}
		if closed != nil {
			return closed
		}
		if err = syncCaptureDirectory(s.root); err != nil {
			return err
		}
		current, err = os.Lstat(s.Engine.Config.EVEPath)
	}
	if err != nil || !current.Mode().IsRegular() || fileID(current) == rotation.Source.FileID {
		return errors.New("EVE 后继文件不可核对")
	}
	if s.active != nil {
		sealed, err := s.captureWriterSealed(ctx, rotation.Source.FileID)
		if err != nil {
			return err
		}
		if !sealed {
			call, cancel := context.WithTimeout(ctx, time.Second)
			_, err = socketCommand(call, s.Engine.Config.SuricataSocket, "reopen-log-files", nil)
			cancel()
			return err
		}
	}
	source, err := s.WAL.Source()
	if err != nil {
		return err
	}
	if source.FileID == rotation.Source.FileID {
		return nil
	}
	drained, err := s.WAL.DrainedSource()
	if err != nil {
		return err
	}
	if source.FileID != fileID(current) || source.Generation == rotation.Source.Generation || drained.FileID != rotation.Source.FileID || drained.Generation != rotation.Source.Generation || drained.PrefixBytes != rotation.Source.PrefixBytes || drained.PrefixSHA256 != rotation.Source.PrefixSHA256 {
		return errors.New("EVE 排空检查点与轮转记录不一致")
	}
	if old != nil && drained.Offset != uint64(old.Size()) {
		return errors.New("EVE 封存来源仍有未提交字节")
	}
	if rotation.Phase == "prepared" {
		rotation.Phase, rotation.NextFileID, rotation.NextGeneration, rotation.DrainedBytes = "drained", source.FileID, source.Generation, drained.Offset
		if err = s.saveRotation(rotation); err != nil {
			return err
		}
	} else if rotation.NextFileID != source.FileID || rotation.NextGeneration != source.Generation || rotation.DrainedBytes != drained.Offset {
		return errors.New("EVE 已提交的排空记录发生变化")
	}
	if old != nil {
		if err = removeDurable(oldPath); err != nil {
			return err
		}
	}
	if err = removeDurable(s.rotationPath()); err != nil {
		return err
	}
	s.mu.Lock()
	s.rotations++
	s.state.Rotations = strconv.FormatUint(s.rotations, 10)
	s.state.RotationPending = false
	s.mu.Unlock()
	return nil
}

func (s *CaptureSupervisor) CanSwitchSource(ctx context.Context, id string) (bool, error) {
	if !s.op.TryLock() {
		return false, nil
	}
	defer s.op.Unlock()
	rotation, err := s.readRotation()
	if err != nil {
		return false, err
	}
	if rotation.Source.FileID != id {
		return false, errors.New("EVE 轮转身份不一致")
	}
	if s.active == nil {
		return true, nil
	}
	return s.captureWriterSealed(ctx, id)
}

func (s *CaptureSupervisor) captureWriterSealed(ctx context.Context, id string) (bool, error) {
	if err := s.Check(ctx); err != nil {
		return false, err
	}
	process := s.active
	entries, err := os.ReadDir(filepath.Join("/proc", strconv.Itoa(process.command.Process.Pid), "fd"))
	if err != nil {
		return false, err
	}
	if len(entries) > 4096 {
		return false, errors.New("检测进程文件句柄超过核对上限")
	}
	for _, entry := range entries {
		info, err := os.Stat(filepath.Join("/proc", strconv.Itoa(process.command.Process.Pid), "fd", entry.Name()))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return false, err
		}
		if info.Mode().IsRegular() && fileID(info) == id {
			return false, nil
		}
	}
	select {
	case <-process.done:
		return false, errors.New("核对期间检测进程退出")
	default:
	}
	return true, nil
}

func verifyCapturePrefix(path string, source Source) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	actual, err := prefix(file, source.PrefixBytes)
	if err != nil || actual != source.PrefixSHA256 {
		return errors.New("EVE 来源前缀不一致")
	}
	return nil
}

func syncCaptureDirectory(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}

func (s *CaptureSupervisor) spoolUsage() (int64, error) {
	root := s.root
	if root == "" {
		root = filepath.Dir(s.Engine.Config.EVEPath)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return 0, err
	}
	var used int64
	for _, entry := range entries {
		if entry.Name() != filepath.Base(s.Engine.Config.EVEPath) && !strings.HasPrefix(entry.Name(), "eve-segment_") {
			continue
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > (1<<63-1)-used {
			return 0, errors.New("采集缓冲文件不可核对")
		}
		used += info.Size()
	}
	return used, nil
}
