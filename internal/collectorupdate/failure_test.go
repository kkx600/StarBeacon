package collectorupdate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"

	"golang.org/x/sys/unix"
)

func TestCollectorBundleSnapshotKeepsVerifiedBytesAfterSourceMutation(t *testing.T) {
	_, key := testKeys(t)
	archive, envelope := writeZIP(t, key, 1, items(1))
	original, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	input, err := os.Open(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	snapshot, err := snapshotArchive(context.Background(), t.TempDir(), input, envelope.Proof)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	if err := os.WriteFile(archive, bytes.Repeat([]byte("x"), len(original)), 0600); err != nil {
		t.Fatal(err)
	}
	retained := make([]byte, len(original))
	if _, err := snapshot.ReadAt(retained, 0); err != nil || !bytes.Equal(retained, original) {
		t.Fatal("外部源文件改写影响了已核验字节", err)
	}
	info, err := snapshot.Stat()
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("制品快照没有限制读取权限", err)
	}
}

func TestCollectorBundleSnapshotRejectsIncompleteChangedAndCancelledInputs(t *testing.T) {
	_, key := testKeys(t)
	archive, envelope := writeZIP(t, key, 1, items(1))
	raw, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for name, input := range map[string]io.Reader{
		"short": bytes.NewReader(raw[:len(raw)-1]), "growing": bytes.NewReader(append(raw, 'x')),
		"modified":   bytes.NewReader(bytes.Repeat([]byte("x"), len(raw))),
		"read_error": iotest.ErrReader(io.ErrUnexpectedEOF),
		"cancelled":  archiveInput{ctx, bytes.NewReader(raw)},
	} {
		t.Run(name, func(t *testing.T) {
			directory := t.TempDir()
			if _, err := snapshotArchive(context.Background(), directory, input, envelope.Proof); err == nil {
				t.Fatal("接受未完整核验的制品输入")
			}
			entries, err := os.ReadDir(directory)
			if err != nil || len(entries) != 0 {
				t.Fatal("失败后保留了未核验快照", err)
			}
		})
	}
	if _, err := snapshotArchive(context.Background(), filepath.Join(t.TempDir(), "missing"), bytes.NewReader(raw), envelope.Proof); err == nil {
		t.Fatal("忽略快照写入失败")
	}
}

type failingOutput struct{}

func (failingOutput) Write([]byte) (int, error) { return 0, errors.New("输出连接中断") }

func TestCollectorMaintenanceCLIExecutionAndImmutableBootstrap(t *testing.T) {
	m, _, key := managerFixture(t)
	archive, proof := writeZIP(t, key, 1, items(1))
	proofPath := filepath.Join(t.TempDir(), "proof.json")
	if err := atomicJSON(proofPath, proof); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := executeMaintenance(context.Background(), m, "apply", archive, proofPath, "install_cli", 0, &out); err != nil {
		t.Fatal(err)
	}
	var s State
	if err := json.Unmarshal(out.Bytes(), &s); err != nil || s.Operation.Phase != "committed" {
		t.Fatal(err, s)
	}
	helper := filepath.Join(m.Root, "maintenance/starbeacon-agent")
	first, err := fileDigest(helper)
	if err != nil {
		t.Fatal(err)
	}
	if err := bootstrap(m.Root); err != nil {
		t.Fatal(err)
	}
	second, _ := fileDigest(helper)
	if first != second {
		t.Fatal("升级隐式替换了独立维护启动程序")
	}
	for _, operation := range []string{"status", "recover"} {
		out.Reset()
		if err := executeMaintenance(context.Background(), m, operation, "", "", "", 0, &out); err != nil {
			t.Fatal(operation, err)
		}
	}
	if executeMaintenance(context.Background(), m, "status", "", "", "", 0, failingOutput{}) == nil {
		t.Fatal("输出失败没有返回错误")
	}
	if executeMaintenance(context.Background(), m, "unknown", "", "", "", 0, &out) == nil {
		t.Fatal("接受未知维护动作")
	}
	if executeMaintenance(context.Background(), m, "rollback", "", "", "rollback_cli", 1, &out) == nil {
		t.Fatal("没有前版本仍回退")
	}
	if executeMaintenance(context.Background(), m, "apply", "", "/not/found", "invalid_cli", 1, &out) == nil {
		t.Fatal("缺少签名仍安装")
	}
	if err := os.Chmod(helper, 0777); err != nil {
		t.Fatal(err)
	}
	if bootstrap(m.Root) == nil {
		t.Fatal("继续信任可被其他用户修改的维护程序")
	}
	if ExecManaged(m.Root, "/bin/sh", 1, 1) == nil || ExecManaged("/not/found", "/starbeacon/starbeacon-agent", 1, 1) == nil || dropCapturePrivileges(0, 0) == nil {
		t.Fatal("容器维护入口接受非法启动请求")
	}
}

func TestCollectorMaintenanceFilesystemFailuresPreserveRecoveryEvidence(t *testing.T) {
	for _, target := range []string{"lock", "state", "operation", "selection", "release", "root"} {
		t.Run(target, func(t *testing.T) {
			m, _, key := managerFixture(t)
			state := applyFixture(t, m, key, 1, 0)
			switch target {
			case "lock":
				os.Remove(filepath.Join(m.Root, "maintenance.lock"))
				os.Symlink("state.json", filepath.Join(m.Root, "maintenance.lock"))
				if _, err := m.lock(); err == nil {
					t.Fatal("维护锁跟随了符号链接")
				}
			case "state":
				os.WriteFile(filepath.Join(m.Root, "state.json"), []byte("{}\n{}"), 0644)
				if _, err := m.Status(); err == nil {
					t.Fatal("接受多条 JSON")
				}
			case "operation":
				os.WriteFile(m.receiptPath("bad_receipt"), []byte("{"), 0600)
				name, proof := writeZIP(t, key, 2, items(2))
				if _, err := m.Apply(context.Background(), name, proof, "bad_receipt", 1); err == nil {
					t.Fatal("覆盖损坏的原请求")
				}
			case "selection":
				os.Remove(filepath.Join(m.Root, "current"))
				os.Mkdir(filepath.Join(m.Root, "current"), 0755)
				os.WriteFile(filepath.Join(m.Root, "current/occupied"), []byte("preserve"), 0644)
				name, proof := writeZIP(t, key, 2, items(2))
				result, err := m.Apply(context.Background(), name, proof, "selection_conflict", 1)
				if err == nil || result.Operation.Phase != "unknown" {
					t.Fatal("选择目录故障丢失恢复依据", result, err)
				}
			case "release":
				applyFixture(t, m, key, 2, 1)
				os.WriteFile(state.Current.binary(m.Root), []byte("broken"), 0755)
				if _, err := m.Rollback(context.Background(), "bad_previous", 2); err == nil {
					t.Fatal("恢复被更改的前版本")
				}
			case "root":
				os.Chmod(m.Root, 0777)
				if _, err := m.Status(); err == nil {
					t.Fatal("信任其他用户可写的维护根目录")
				}
			}
		})
	}
	if atomicJSON(filepath.Join(t.TempDir(), "bad.json"), make(chan int)) == nil {
		t.Fatal("不能序列化的状态被提交")
	}
	if atomicJSON("/path/does/not/exist/state.json", State{}) == nil || syncDirectory("/path/does/not/exist") == nil {
		t.Fatal("忽略 journal 落盘失败")
	}
	root := t.TempDir()
	os.Mkdir(filepath.Join(root, "record.json"), 0700)
	if readJSON(filepath.Join(root, "record.json"), new(State)) == nil {
		t.Fatal("把目录当成状态")
	}
	if atomicJSON(filepath.Join(root, "record.json"), State{}) == nil {
		t.Fatal("覆盖既有目录")
	}
}

func TestCollectorBootGuardRejectsUnconfirmedSelectionAndCorruptRecords(t *testing.T) {
	if BootGuard("/") == nil || BootGuard("relative") == nil || BootGuard("/no/such/deployment") == nil {
		t.Fatal("非法启动目录被接受")
	}
	m, _, key := managerFixture(t)
	s := applyFixture(t, m, key, 1, 0)
	for _, phase := range []string{"prepared", "switching", "starting", "restoring", "unknown"} {
		changed := s
		op := *s.Operation
		changed.Operation = &op
		op.FinishedAt, op.Phase = nil, phase
		if err := m.save(changed); err != nil {
			t.Fatal(err)
		}
		if err := BootGuard(m.Root); !errors.Is(err, ErrRecoveryRequired) {
			t.Fatal("进程中断后自行启动未经核验版本", phase, err)
		}
		lock, err := m.lock()
		if err != nil {
			t.Fatal(err)
		}
		if phase != "starting" && BootGuard(m.Root) == nil {
			t.Fatal("错误的维护阶段允许启动")
		}
		lock.Close()
	}
	if err := m.save(s); err != nil {
		t.Fatal(err)
	}
	os.Remove(filepath.Join(m.Root, "current"))
	os.Symlink(filepath.Join("releases", "other"), filepath.Join(m.Root, "current"))
	if BootGuard(m.Root) == nil {
		t.Fatal("启动与状态不符的程序")
	}
	if err := m.selectRelease(nil); err != nil {
		t.Fatal(err)
	}
	if err := m.selectRelease(nil); err != nil {
		t.Fatal(err)
	}
	if err := m.selectRelease(&Release{Directory: "../bad"}); err == nil {
		t.Fatal("选择无效的版本目录")
	}
	if err := os.WriteFile(filepath.Join(m.Root, "state.json"), []byte(`{"schema_version":1,"unknown":true}`), 0644); err != nil {
		t.Fatal(err)
	}
	if readJSON(filepath.Join(m.Root, "state.json"), new(State)) == nil {
		t.Fatal("接受未知状态字段")
	}
	if err := os.WriteFile(filepath.Join(m.Root, "state.json"), []byte(strings.Repeat(" ", (2<<20)+1)), 0644); err != nil {
		t.Fatal(err)
	}
	if readJSON(filepath.Join(m.Root, "state.json"), new(State)) == nil {
		t.Fatal("无状态读取预算")
	}
}

func TestCollectorMaintenanceRejectsSpecialInputsWithoutBlocking(t *testing.T) {
	pub, key := testKeys(t)
	_, proof := writeZIP(t, key, 1, items(1))
	fifo := filepath.Join(t.TempDir(), "input")
	if err := unix.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Stage(context.Background(), t.TempDir(), fifo, proof, pub, fixedTime); err == nil {
		t.Fatal("维护制品接受 FIFO")
	}
	if readJSON(fifo, new(State)) == nil {
		t.Fatal("维护记录接受 FIFO")
	}
	if _, err := fileDigest(fifo); err == nil {
		t.Fatal("摘要输入接受 FIFO")
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(fifo, link); err != nil {
		t.Fatal(err)
	}
	if readJSON(link, new(State)) == nil {
		t.Fatal("维护记录跟随不可信链接")
	}
}

func TestCollectorMaintenanceBindsEnvironmentAndKeepsRetentionIndependent(t *testing.T) {
	c := testConfig(t)
	if _, err := c.binding(); err == nil {
		t.Fatal("缺少环境文件仍绑定配置")
	}
	os.MkdirAll(c.ConfigDir, 0755)
	environment := filepath.Join(c.ConfigDir, "agent.env")
	os.WriteFile(environment, []byte("SB_MODE=production\n"), 0600)
	first, err := c.binding()
	if err != nil {
		t.Fatal(err)
	}
	c.RetentionDays = 365
	second, err := c.binding()
	if err != nil || second != first {
		t.Fatal("未来保留期影响已有部署身份", err)
	}
	os.WriteFile(environment, []byte("SB_MODE=production\n# external change\n"), 0600)
	third, err := c.binding()
	if err != nil || third == first {
		t.Fatal("部署环境漂移没有改变绑定", err)
	}
}
