package collectorupdate

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// BootGuard 防止重启策略在断电或维护进程被强制终止后直接启动未确认目标。
// 显式恢复由部署管理员执行；只读服务账号不能替换 journal 或清除恢复依据。
func BootGuard(root string) error {
	if !absolutePath.MatchString(root) || filepath.Clean(root) != root || root == "/" {
		return errors.New("维护启动目录无效")
	}
	var s State
	if err := readJSON(filepath.Join(root, "state.json"), &s); err != nil {
		return err
	}
	if s.SchemaVersion != 1 || s.Operation == nil || s.Instance == "" || s.Operation.Target.validate() != nil || s.Operation.FinishedAt != nil && s.Operation.Phase != "committed" && s.Operation.Phase != "restored" {
		return errors.New("维护启动状态缺失")
	}
	selected := s.Current
	if s.Operation.FinishedAt == nil {
		lock, err := os.OpenFile(filepath.Join(root, "maintenance.lock"), os.O_RDONLY|unix.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		defer lock.Close()
		err = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return ErrRecoveryRequired
		}
		if !errors.Is(err, unix.EWOULDBLOCK) {
			return err
		}
		switch s.Operation.Phase {
		case "starting":
			selected = &s.Operation.Target
		case "restoring":
			selected = s.Operation.Original
		default:
			return ErrRecoveryRequired
		}
	}
	if selected == nil || selected.validate() != nil {
		return errors.New("没有可信的采集器启动目标")
	}
	current, err := os.Readlink(filepath.Join(root, "current"))
	if err != nil || current != filepath.Join("releases", selected.Directory) {
		return errors.New("采集器启动目标与维护状态不一致")
	}
	return verifyBinary(selected.binary(root), *selected)
}

func ExecManaged(root, binary string, uid, gid int) error {
	if binary != "/starbeacon/starbeacon-agent" {
		return errors.New("受管容器只接受固定采集器程序")
	}
	if err := BootGuard(root); err != nil {
		return err
	}
	if err := dropCapturePrivileges(uid, gid); err != nil {
		return err
	}
	return syscall.Exec(binary, []string{binary}, os.Environ())
}

func bootstrap(root string) error {
	if err := os.MkdirAll(filepath.Join(root, "maintenance"), 0755); err != nil {
		return err
	}
	target := filepath.Join(root, "maintenance/starbeacon-agent")
	if info, err := os.Lstat(target); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
			return errors.New("维护启动程序的类型或权限无效")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	input, err := os.Open(self)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0755)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(output, input)
	syncErr := output.Sync()
	closeErr := output.Close()
	if err := errors.Join(copyErr, syncErr, closeErr); err != nil {
		os.Remove(target)
		return err
	}
	return syncDirectory(filepath.Dir(target))
}
