//go:build linux

package collectorupdate

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestNativeCollectorCapturePrivilegeTransfer(t *testing.T) {
	if os.Getenv("SB_TEST_PRIVILEGE_CHILD") == "1" {
		if err := dropCapturePrivileges(65532, 65532); err != nil {
			t.Fatal(err)
		}
		if os.Geteuid() != 65532 || os.Getegid() != 65532 {
			t.Fatal("服务没有转换为非 root 账号")
		}
		header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
		var caps [2]unix.CapUserData
		if err := unix.Capget(&header, &caps[0]); err != nil {
			t.Fatal(err)
		}
		if caps[0].Effective != 1<<unix.CAP_NET_RAW || caps[0].Permitted != 1<<unix.CAP_NET_RAW || caps[0].Inheritable != 1<<unix.CAP_NET_RAW || caps[1] != (unix.CapUserData{}) {
			t.Fatal("服务仍持有其他能力", caps)
		}
		fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int((unix.ETH_P_ALL<<8)&0xff00|(unix.ETH_P_ALL>>8)))
		if err != nil {
			t.Fatal("非 root 服务无法打开 AF_PACKET", err)
		}
		unix.Close(fd)
		if err := unix.Setresuid(0, 0, 0); !errors.Is(err, unix.EPERM) {
			t.Fatal("服务仍能恢复 root", err)
		}
		for _, capability := range []int{unix.CAP_SETUID, unix.CAP_SETGID, unix.CAP_SETPCAP, unix.CAP_NET_ADMIN, unix.CAP_SYS_ADMIN} {
			value, err := unix.PrctlRetInt(unix.PR_CAPBSET_READ, uintptr(capability), 0, 0, 0)
			if err != nil || value != 0 {
				t.Fatal("服务仍可重新取得管理能力", capability, value, err)
			}
		}
		return
	}
	if os.Geteuid() != 0 {
		if err := dropCapturePrivileges(65532, 65532); err == nil {
			t.Fatal("非受信入口提升了抓包权限")
		}
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"-test.run=^TestNativeCollectorCapturePrivilegeTransfer$", "-test.v"}
	if dir := os.Getenv("SB_PRIVILEGE_COVER_DIR"); dir != "" {
		args = append(args, "-test.coverprofile="+filepath.Join(dir, "privilege-child.cover"))
	}
	command := exec.CommandContext(ctx, self, args...)
	command.Env = append(os.Environ(), "SB_TEST_PRIVILEGE_CHILD=1")
	var output bytes.Buffer
	command.Stdout, command.Stderr = &output, &output
	if err := command.Run(); err != nil {
		t.Fatalf("独立权限转换进程未通过：%v\n%s", err, output.Bytes())
	}
}
