//go:build linux

package agent

import (
	"bufio"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func sandboxZombieCount(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc")
	if err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, entry := range entries {
		if entry.Name() == "" || entry.Name()[0] < '0' || entry.Name()[0] > '9' {
			continue
		}
		raw, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "stat"))
		// /proc 枚举与读取之间进程可能已退出；ENOENT 和 ESRCH 都不表示残留。
		if os.IsNotExist(err) || errors.Is(err, unix.ESRCH) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "(bwrap) Z ") {
			total++
		}
	}
	return total
}

func requireSandboxReaped(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if sandboxZombieCount(t) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("原生隔离器退出后仍有未回收子进程；容器必须启用 init")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestNativeSandboxRepeatedExitDoesNotExhaustProcesses(t *testing.T) {
	if os.Getenv("SB_TEST_SURICATA_BINARY") == "" {
		t.Skip("原生进程生命周期验证需独立 Linux 隔离环境")
	}
	job := t.TempDir()
	input, output := filepath.Join(job, "input"), filepath.Join(job, "output")
	for _, path := range []string{input, output} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// 次数高于专属进程测试容器的 PID 预算；正常完成不能依靠不断提高配额。
	for i := 0; i < 128; i++ {
		command, err := sandboxCommand(ctx, "/usr/bin/true", job, input, output, nil)
		if err != nil {
			t.Fatal(err)
		}
		if raw, err := command.CombinedOutput(); err != nil {
			t.Fatalf("第 %d 次隔离退出失败：%v，输出 %s", i+1, err, raw)
		}
	}
	requireSandboxReaped(t)
	t.Log("128 次实际隔离执行完成，退出后 bwrap 僵尸进程为 0")
}

func TestNativeSandboxCancellationReapsNamespaceChildren(t *testing.T) {
	if os.Getenv("SB_TEST_SURICATA_BINARY") == "" {
		t.Skip("原生进程取消验证需独立 Linux 隔离环境")
	}
	job := t.TempDir()
	input, output := filepath.Join(job, "input"), filepath.Join(job, "output")
	for _, path := range []string{input, output} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 8; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		command, err := sandboxCommand(ctx, "/usr/bin/sh", job, input, output, []string{"-c", "printf 'ready\\n'; exec /usr/bin/sleep 30"})
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		pipe, err := command.StdoutPipe()
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		if err = command.Start(); err != nil {
			cancel()
			t.Fatal(err)
		}
		// 只在命令已进入独立命名空间后取消，避免把启动前取消计为后代回收验证。
		line, readErr := bufio.NewReader(pipe).ReadString('\n')
		cancel()
		runErr := command.Wait()
		if readErr != nil || line != "ready\n" {
			t.Fatal("隔离命令尚未就绪", readErr)
		}
		if runErr == nil || ctx.Err() == nil {
			t.Fatal("超时未终止隔离命令")
		}
	}
	requireSandboxReaped(t)
	t.Log("8 次实际隔离取消完成，退出后 bwrap 僵尸进程为 0")
}
