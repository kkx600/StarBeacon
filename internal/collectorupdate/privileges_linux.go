//go:build linux

package collectorupdate

import (
	"errors"
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

// 容器先由受信启动程序转交已明确授予的 NET_RAW，再不可逆地放弃服务管理能力。
// 所有阶段固定在执行线程；exec 后旧运行时线程消失，新程序仅继承 NET_RAW。
func dropCapturePrivileges(uid, gid int) error {
	if os.Geteuid() != 0 || uid < 1 || gid < 1 || int64(uid) > 2147483647 || int64(gid) > 2147483647 {
		return errors.New("容器权限转换需要受信入口及有效的非 root 服务账号")
	}
	runtime.LockOSThread()
	if err := unix.Prctl(unix.PR_SET_KEEPCAPS, 1, 0, 0, 0); err != nil {
		return err
	}
	if err := unix.Setgroups([]int{}); err != nil {
		return err
	}
	if err := unix.Setresgid(gid, gid, gid); err != nil {
		return err
	}
	if err := unix.Setresuid(uid, uid, uid); err != nil {
		return err
	}
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	raw := uint32(1 << unix.CAP_NET_RAW)
	admin := uint32(1 << unix.CAP_SETPCAP)
	data := [2]unix.CapUserData{{Effective: raw | admin, Permitted: raw | admin, Inheritable: raw}, {}}
	if err := unix.Capset(&header, &data[0]); err != nil {
		return err
	}
	// 内核能力目录连续；EINVAL 表示已经超过此内核支持的最高能力编号。
	for capability := 0; capability < 64; capability++ {
		if capability == unix.CAP_NET_RAW {
			continue
		}
		if err := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(capability), 0, 0, 0); errors.Is(err, unix.EINVAL) {
			break
		} else if err != nil {
			return err
		}
	}
	data[0] = unix.CapUserData{Effective: raw, Permitted: raw, Inheritable: raw}
	if err := unix.Capset(&header, &data[0]); err != nil {
		return err
	}
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_RAISE, unix.CAP_NET_RAW, 0, 0); err != nil {
		return err
	}
	if err := unix.Prctl(unix.PR_SET_KEEPCAPS, 0, 0, 0, 0); err != nil {
		return err
	}
	return unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
}
