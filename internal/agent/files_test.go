package agent

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/control"
	"golang.org/x/sys/unix"
)

func TestBoundedCopyRejectsFIFOWithoutOpeningAnOutput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.pipe")
	target := filepath.Join(dir, "output.yaml")
	if err := unix.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := copyBounded(path, target, 1024); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO 被接受为配置")
		}
	case <-time.After(time.Second):
		t.Fatal("配置路径阻塞了重放任务")
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatal("拒绝配置后仍创建了输出")
	}
}

func TestBoundedCopyPreservesDigestAndRejectsOversize(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "suricata.yaml")
	target := filepath.Join(dir, "copied.yaml")
	data := []byte("%YAML 1.1\n---\n")
	if err := os.WriteFile(source, data, 0600); err != nil {
		t.Fatal(err)
	}
	value, err := copyBounded(source, target, int64(len(data)))
	if err != nil || value != control.Digest(data) {
		t.Fatal("配置复制或摘要失败", err)
	}
	if _, err := copyBounded(source, filepath.Join(dir, "too-large"), int64(len(data)-1)); err == nil {
		t.Fatal("超限配置被复制")
	}
	if _, err := copyBounded(dir, filepath.Join(dir, "directory"), 1024); err == nil {
		t.Fatal("目录被接受为配置")
	}
	if _, err := copyBounded(source, filepath.Join(dir, "missing", "copied.yaml"), 1024); err == nil {
		t.Fatal("缺失输出目录未返回错误")
	}
}
