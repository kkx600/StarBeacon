//go:build linux

package collectorupdate

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestCollectorCleanupRejectsTopLevelForeignFilesystem(t *testing.T) {
	root := t.TempDir()
	info, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	device := uint64(info.Sys().(*syscall.Stat_t).Dev)
	foreign, err := os.MkdirTemp("/dev/shm", "starbeacon-maintenance-")
	if err != nil {
		t.Fatal("Linux 验收需要独立的 /dev/shm 临时文件系统", err)
	}
	t.Cleanup(func() { os.RemoveAll(foreign) })
	outside := filepath.Join(foreign, "retained")
	if err := os.WriteFile(outside, []byte("retained outside the program filesystem"), 0600); err != nil {
		t.Fatal(err)
	}
	other, err := os.Stat(foreign)
	if err != nil || uint64(other.Sys().(*syscall.Stat_t).Dev) == device {
		t.Fatal("两个实际文件系统未独立，不能授予跨挂载回收资格", err)
	}
	if _, err := cleanupTree(context.Background(), foreign, device); err == nil {
		t.Fatal("回收允许候选目录位于程序根之外的文件系统")
	}
	if raw, err := os.ReadFile(outside); err != nil || string(raw) != "retained outside the program filesystem" {
		t.Fatal("外部文件系统材料发生变化", err)
	}
}
