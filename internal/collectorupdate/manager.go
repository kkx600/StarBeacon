package collectorupdate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/kkx600/StarBeacon/internal/contract"
	"golang.org/x/sys/unix"
)

var ErrConflict = errors.New("部署修订冲突或另有维护操作")
var ErrRecoveryRequired = errors.New("存在中断的维护操作，必须先恢复并核对实际运行状态")

// Runtime 由部署方式提供固定的停止、启动与实际程序／就绪核验，不执行制品自带脚本。
type Runtime interface {
	Prepare(context.Context, *Release) error
	Stop(context.Context) error
	Start(context.Context, Release) error
	Verify(context.Context, Release) error
}

type Operation struct {
	ID          string     `json:"id"`
	Kind        string     `json:"kind"`
	Phase       string     `json:"phase"`
	Target      Release    `json:"target"`
	Original    *Release   `json:"original,omitempty"`
	StartedAt   time.Time  `json:"started_at"`
	FinishedAt  *time.Time `json:"finished_at,omitempty"`
	RetainUntil time.Time  `json:"retain_until"`
	Code        string     `json:"code,omitempty"`
}

type State struct {
	SchemaVersion int        `json:"schema_version"`
	Instance      string     `json:"instance"`
	Mode          string     `json:"mode"`
	BindingSHA256 string     `json:"binding_sha256"`
	Revision      int64      `json:"revision"`
	MaxGeneration int64      `json:"max_generation"`
	Current       *Release   `json:"current,omitempty"`
	Previous      *Release   `json:"previous,omitempty"`
	Operation     *Operation `json:"operation,omitempty"`
}

type Manager struct {
	Root          string
	Instance      string
	Mode          string
	BindingSHA256 string
	Key           ed25519.PublicKey
	Runtime       Runtime
	Guard         func(context.Context) error
	RetentionDays int
	// Now 只影响记录和签名时间；运行超时继续使用单调时钟。
	Now func() time.Time
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now().UTC()
	}
	return time.Now().UTC()
}

func (m *Manager) initialize() error {
	if !filepath.IsAbs(m.Root) || filepath.Clean(m.Root) != m.Root || m.Root == "/" || !contract.ValidID(m.Instance) || !digestPattern.MatchString(m.BindingSHA256) || (m.Mode != "systemd" && m.Mode != "docker") || m.Runtime == nil || m.Guard == nil || len(m.Key) != ed25519.PublicKeySize || m.RetentionDays < 1 || m.RetentionDays > 3650 {
		return errors.New("采集器维护配置无效")
	}
	for _, directory := range []string{m.Root, filepath.Join(m.Root, "operations"), filepath.Join(m.Root, "releases")} {
		if err := os.MkdirAll(directory, 0755); err != nil {
			return err
		}
		info, err := os.Lstat(directory)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
			return errors.New("维护目录不能为链接或允许其他用户写入")
		}
		if stat, ok := info.Sys().(*syscall.Stat_t); !ok || stat.Uid != uint32(os.Geteuid()) {
			return errors.New("维护目录不属于当前部署管理员")
		}
	}
	return nil
}

func (m *Manager) lock() (*os.File, error) {
	if err := m.initialize(); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(m.Root, "maintenance.lock"), os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW, 0644)
	if err != nil {
		return nil, err
	}
	if err = f.Chmod(0644); err != nil {
		f.Close()
		return nil, err
	}
	if err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		return nil, ErrConflict
	}
	return f, nil
}

func (m *Manager) readState() (State, error) {
	s := State{SchemaVersion: 1, Instance: m.Instance, Mode: m.Mode, BindingSHA256: m.BindingSHA256}
	err := readJSON(filepath.Join(m.Root, "state.json"), &s)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return State{}, err
	}
	if s.SchemaVersion != 1 || s.Instance != m.Instance || s.Mode != m.Mode || s.BindingSHA256 != m.BindingSHA256 || s.Revision < 0 || s.MaxGeneration < 0 {
		return State{}, errors.New("采集器维护状态不属于当前部署")
	}
	for _, release := range []*Release{s.Current, s.Previous} {
		if release != nil && (release.validate() != nil || release.Proof.Generation > s.MaxGeneration) {
			return State{}, errors.New("采集器维护状态的制品绑定无效")
		}
	}
	if s.Operation != nil && (!contract.ValidID(s.Operation.ID) || s.Operation.Kind != "apply" && s.Operation.Kind != "rollback" || s.Operation.Target.validate() != nil || s.Operation.StartedAt.IsZero() || !s.Operation.RetainUntil.After(s.Operation.StartedAt) || s.Operation.Original != nil && s.Operation.Original.validate() != nil) {
		return State{}, errors.New("采集器维护 journal 无效")
	}
	if s.Operation != nil {
		switch s.Operation.Phase {
		case "prepared", "switching", "starting", "restoring", "unknown":
			if s.Operation.FinishedAt != nil {
				return State{}, errors.New("维护中间状态不能标记完成")
			}
		case "committed", "restored":
			if s.Operation.FinishedAt == nil {
				return State{}, errors.New("维护完成状态缺少时间")
			}
		default:
			return State{}, errors.New("维护阶段无效")
		}
	}
	return s, nil
}

func (m *Manager) Status() (State, error) {
	if err := m.initialize(); err != nil {
		return State{}, err
	}
	// 原子文件替换保证读到完整快照；只读状态不与维护写锁竞争。
	return m.readState()
}

func (m *Manager) save(s State) error {
	return atomicJSONMode(filepath.Join(m.Root, "state.json"), s, 0644)
}

func (m *Manager) Apply(ctx context.Context, archive string, envelope Envelope, id string, revision int64) (State, error) {
	f, err := m.lock()
	if err != nil {
		return State{}, err
	}
	defer f.Close()
	s, err := m.readState()
	if err != nil {
		return s, err
	}
	if existing, ok, err := m.previousRequest(s, id, "apply", envelope.Proof); ok || err != nil {
		return existing, err
	}
	if s.Operation != nil && s.Operation.FinishedAt == nil {
		return s, ErrRecoveryRequired
	}
	if !contract.ValidID(id) || revision != s.Revision || envelope.Proof.Generation <= s.MaxGeneration {
		return s, ErrConflict
	}
	if err := m.Runtime.Prepare(ctx, s.Current); err != nil {
		return s, err
	}
	target, err := stage(ctx, m.Root, archive, envelope, m.Key, m.now(), m.RetentionDays)
	if err != nil {
		return s, err
	}
	return m.switchTo(ctx, s, target, id, "apply")
}

func (m *Manager) Rollback(ctx context.Context, id string, revision int64) (State, error) {
	f, err := m.lock()
	if err != nil {
		return State{}, err
	}
	defer f.Close()
	s, err := m.readState()
	if err != nil {
		return s, err
	}
	if s.Operation != nil && s.Operation.ID == id {
		if s.Operation.Kind != "rollback" {
			return s, ErrConflict
		}
		return m.confirm(s)
	}
	if !contract.ValidID(id) || revision != s.Revision {
		return s, ErrConflict
	}
	if s.Operation != nil && s.Operation.FinishedAt == nil {
		return s, ErrRecoveryRequired
	}
	if s.Previous == nil {
		return s, errors.New("没有已经运行核验的前版本")
	}
	if _, err := os.Lstat(m.receiptPath(id)); !errors.Is(err, os.ErrNotExist) {
		return s, ErrConflict
	}
	if err := m.Runtime.Prepare(ctx, s.Current); err != nil {
		return s, err
	}
	// 已安装的前版本按保存的摘要验证；签发期限不阻止恢复已经信任的本机程序。
	if err := verifyBinary(s.Previous.binary(m.Root), *s.Previous); err != nil {
		return s, err
	}
	return m.switchTo(ctx, s, *s.Previous, id, "rollback")
}

func (m *Manager) switchTo(ctx context.Context, s State, target Release, id, kind string) (State, error) {
	if err := ctx.Err(); err != nil {
		return s, err
	}
	original := s.Current
	now := m.now()
	s.Operation = &Operation{ID: id, Kind: kind, Phase: "prepared", Target: target, Original: original, StartedAt: now, RetainUntil: now.AddDate(0, 0, m.RetentionDays)}
	s.MaxGeneration = max(s.MaxGeneration, target.Proof.Generation)
	if err := m.save(s); err != nil {
		return s, err
	}
	// journal 在停止进程前落盘，任何中断都会阻止另一项升级覆盖恢复依据。
	if err := m.Runtime.Stop(ctx); err != nil {
		return m.unknown(s, "stop_unconfirmed", err)
	}
	if err := m.Guard(ctx); err != nil {
		return m.restore(s, "data_precondition_failed", err)
	}
	s.Operation.Phase = "switching"
	if err := m.save(s); err != nil {
		return s, err
	}
	if err := m.selectRelease(&target); err != nil {
		return m.restore(s, "selection_failed", err)
	}
	s.Operation.Phase = "starting"
	if err := m.save(s); err != nil {
		return s, err
	}
	if err := m.Runtime.Start(ctx, target); err != nil {
		return m.restore(s, "start_failed", err)
	}
	if err := m.Runtime.Verify(ctx, target); err != nil {
		return m.restore(s, "health_verification_failed", err)
	}
	// 只有实际程序与本机就绪同时通过，目标才能成为当前版本。
	s.Current, s.Previous = &target, original
	s.Revision++
	s.Operation.Phase = "committed"
	finished := m.now()
	s.Operation.FinishedAt = &finished
	if err := m.finish(s); err != nil {
		return m.unknown(s, "commit_record_unconfirmed", err)
	}
	return s, nil
}

func (m *Manager) Recover(ctx context.Context) (State, error) {
	f, err := m.lock()
	if err != nil {
		return State{}, err
	}
	defer f.Close()
	s, err := m.readState()
	if err != nil || s.Operation == nil || s.Operation.FinishedAt != nil {
		return s, err
	}
	if err := ctx.Err(); err != nil {
		return s, err
	}
	return m.restore(s, "execution_interrupted", nil)
}

func (m *Manager) restore(s State, code string, cause error) (State, error) {
	// 浏览器、原命令或 SSH 取消后仍有独立恢复期限，不依赖失败调用的上下文。
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	s.Operation.Phase, s.Operation.Code = "restoring", code
	if err := m.save(s); err != nil {
		return s, errors.Join(cause, err)
	}
	if err := m.Runtime.Stop(ctx); err != nil {
		return m.unknown(s, "rollback_stop_unconfirmed", errors.Join(cause, err))
	}
	if err := m.selectRelease(s.Operation.Original); err != nil {
		return m.unknown(s, "rollback_selection_failed", errors.Join(cause, err))
	}
	if s.Operation.Original != nil {
		original := *s.Operation.Original
		if err := verifyBinary(original.binary(m.Root), original); err != nil {
			return m.unknown(s, "rollback_program_invalid", errors.Join(cause, err))
		}
		if err := m.Runtime.Start(ctx, original); err != nil {
			return m.unknown(s, "rollback_start_failed", errors.Join(cause, err))
		}
		if err := m.Runtime.Verify(ctx, original); err != nil {
			return m.unknown(s, "rollback_health_unconfirmed", errors.Join(cause, err))
		}
	}
	s.Current = s.Operation.Original
	s.Revision++
	s.Operation.Phase = "restored"
	finished := m.now()
	s.Operation.FinishedAt = &finished
	if err := m.finish(s); err != nil {
		return m.unknown(s, "rollback_record_unconfirmed", errors.Join(cause, err))
	}
	return s, cause
}

func (m *Manager) unknown(s State, code string, cause error) (State, error) {
	s.Operation.Phase, s.Operation.Code = "unknown", code
	s.Operation.FinishedAt = nil
	return s, errors.Join(cause, ErrRecoveryRequired, m.save(s))
}

func (m *Manager) finish(s State) error {
	// 保存回执先于状态提交；崩溃后的确认不能把中间记录视为已完成。
	if err := atomicJSON(m.receiptPath(s.Operation.ID), s); err != nil {
		return err
	}
	return m.save(s)
}

func (m *Manager) receiptPath(id string) string {
	return filepath.Join(m.Root, "operations", id+".json")
}

func (m *Manager) previousRequest(s State, id, kind string, proof Proof) (State, bool, error) {
	if !contract.ValidID(id) {
		return s, false, ErrConflict
	}
	var previous State
	err := readJSON(m.receiptPath(id), &previous)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return s, true, err
	}
	if s.Operation != nil && s.Operation.ID == id {
		previous = s
	} else if errors.Is(err, os.ErrNotExist) {
		return s, false, nil
	}
	if previous.Instance != m.Instance || previous.Mode != m.Mode || previous.BindingSHA256 != m.BindingSHA256 || previous.Operation == nil || previous.Operation.ID != id || previous.Operation.Kind != kind || !bytes.Equal(proofBytes(previous.Operation.Target.Proof), proofBytes(proof)) || previous.Operation.Target.validate() != nil {
		return s, true, ErrConflict
	}
	confirmed, err := m.confirm(previous)
	return confirmed, true, err
}

func (m *Manager) confirm(s State) (State, error) {
	if s.Operation.FinishedAt == nil {
		return s, ErrRecoveryRequired
	}
	if s.Operation.Phase != "committed" {
		return s, errors.New("原维护操作未提交目标版本，请核对原回执")
	}
	return s, nil
}

func (m *Manager) selectRelease(release *Release) error {
	current := filepath.Join(m.Root, "current")
	if release == nil {
		err := os.Remove(current)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return syncDirectory(m.Root)
	}
	if err := release.validate(); err != nil {
		return err
	}
	name := filepath.Join(m.Root, ".current-next")
	if err := os.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Symlink(filepath.Join("releases", release.Directory), name); err != nil {
		return err
	}
	if err := os.Rename(name, current); err != nil {
		return err
	}
	return syncDirectory(m.Root)
}

func syncDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func readJSON(path string, value any) error {
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 2<<20 {
		return errors.New("维护记录类型或体积无效")
	}
	d := json.NewDecoder(io.LimitReader(f, (2<<20)+1))
	d.DisallowUnknownFields()
	if err := d.Decode(value); err != nil {
		return err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return errors.New("维护记录不能包含多个 JSON 值")
	}
	return nil
}

func atomicJSON(path string, value any) error {
	return atomicJSONMode(path, value, 0600)
}

func atomicJSONMode(path string, value any, mode os.FileMode) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".journal-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	_, writeErr := f.Write(append(raw, '\n'))
	syncErr := f.Sync()
	closeErr := f.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		return err
	}
	if err := os.Rename(f.Name(), path); err != nil {
		return fmt.Errorf("维护状态写入失败：%w", err)
	}
	return syncDirectory(filepath.Dir(path))
}
