//go:build linux

package agent

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/control"
)

func TestCaptureChildDiesWhenParentIsKilled(t *testing.T) {
	if os.Getenv("SB_CAPTURE_PARENT_DEATH_HELPER") == "1" {
		command := exec.Command("/usr/bin/sleep", "60")
		command.SysProcAttr = captureProcessAttributes()
		done := make(chan struct{})
		if err := startCaptureProcess(command, done); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(os.Getenv("SB_CAPTURE_CHILD_PID"), []byte(strconv.Itoa(command.Process.Pid)), 0600); err != nil {
			t.Fatal(err)
		}
		<-done
		return
	}
	path := filepath.Join(t.TempDir(), "child.pid")
	parent := exec.Command(os.Args[0], "-test.run=^TestCaptureChildDiesWhenParentIsKilled$")
	parent.Env = []string{"PATH=/usr/bin:/bin", "SB_CAPTURE_PARENT_DEATH_HELPER=1", "SB_CAPTURE_CHILD_PID=" + path}
	if err := parent.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = parent.Process.Kill(); _ = parent.Wait() }()
	var pid int
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if raw, err := os.ReadFile(path); err == nil {
			pid, err = strconv.Atoi(string(raw))
			if err != nil || pid < 2 {
				t.Fatal("子进程身份无效")
			}
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if pid == 0 {
		t.Fatal("受管子进程没有启动")
	}
	child, err := os.FindProcess(pid)
	if err != nil {
		t.Fatal(err)
	}
	defer child.Release()
	defer child.Kill()
	if err = parent.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		// 僵尸状态已经不能执行或占用捕获套接字，稍后由容器内收养者回收。
		raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
		if os.IsNotExist(err) {
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		_, rest, ok := strings.Cut(string(raw), ") ")
		if ok && strings.HasPrefix(rest, "Z ") {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("采集器意外退出后子进程仍在运行")
}

func TestCaptureSourceCannotSwitchWhileWriterOwnsOldInode(t *testing.T) {
	s, r := rotationFixture(t)
	e := s.Engine
	e.Config.SuricataPIDFile = filepath.Join(s.root, "engine.pid")
	if err := durableFile(e.Config.SuricataPIDFile, []byte(strconv.Itoa(os.Getpid()))); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(e.Config.SuricataConfig)
	if err != nil {
		t.Fatal(err)
	}
	process := &captureProcess{command: &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}, done: make(chan struct{}), sha: control.Digest(raw), aux: map[string]string{}}
	s.active = process
	rotation, err := s.readRotation()
	if err != nil {
		t.Fatal(err)
	}
	sealed := filepath.Join(s.root, rotation.Name)
	if err = os.Rename(r.Path, sealed); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(r.Path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	writer, err := os.OpenFile(sealed, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if ready, err := s.captureWriterSealed(context.Background(), rotation.Source.FileID); ready || err != nil {
		t.Fatal("活跃写端被判为封存", ready, err)
	}
	if err = r.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if source, _ := s.WAL.Source(); source.FileID != rotation.Source.FileID {
		t.Fatal("活跃写端的来源被跳过")
	}
	_, err = writer.WriteString(eveSample + "\n")
	if err != nil {
		t.Fatal(err)
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	// 读取器的旧只读句柄不属于检测进程，核对前暂时关闭它再检查实际写端。
	if err = r.Close(); err != nil {
		t.Fatal(err)
	}
	r.file = nil
	if ready, err := s.captureWriterSealed(context.Background(), rotation.Source.FileID); !ready || err != nil {
		t.Fatal("写端关闭后不能封存", ready, err)
	}
	// 同进程边界用例不继续让读取器充当检测进程；排空和重启由独立用例验收。
	close(process.done)
	if ready, err := s.captureWriterSealed(context.Background(), rotation.Source.FileID); ready || err == nil {
		t.Fatal("退出进程被接受")
	}
	if attrs := captureProcessAttributes(); attrs.Pdeathsig != syscall.SIGTERM || !attrs.Setpgid {
		t.Fatal("进程生命周期约束不完整")
	}
}
