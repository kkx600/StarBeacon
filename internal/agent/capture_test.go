package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/config"
	"github.com/kkx600/StarBeacon/internal/control"
	"go.yaml.in/yaml/v3"
)

func captureFixture(t *testing.T) *Engine {
	t.Helper()
	dir := t.TempDir()
	w, err := OpenWAL(filepath.Join(dir, "agent.db"), "tenant", "sensor", "registration", 4<<20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	base := filepath.Join(dir, "base.yaml")
	if err = os.WriteFile(base, []byte("%YAML 1.1\n---\nvars:\n  address-groups:\n    HOME_NET: any\n    EXTERNAL_NET: any\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return &Engine{WAL: w, Config: config.Config{StatePath: filepath.Join(dir, "agent.db"), SuricataConfig: base, CaptureSpoolBytes: 100 << 20}}
}

func TestCaptureSettingsRejectsUnavailableAndExcessiveTargets(t *testing.T) {
	for _, settings := range []CaptureSettings{{}, {Interfaces: []string{"lo"}}, {Interfaces: []string{"missing-interface"}}, {Interfaces: []string{}, Threads: -1}, {Interfaces: []string{}, Threads: 65}, {Interfaces: make([]string, 17)}, {Interfaces: []string{}, BPFFilter: strings.Repeat("x", 2049)}, {Interfaces: []string{}, BPFFilter: "tcp\nport 80"}} {
		if err := settings.normalize(); err == nil {
			t.Fatal("无效采集目标被接受", settings)
		}
	}
	settings := CaptureSettings{Interfaces: []string{}, BPFFilter: "  tcp port 80  "}
	if err := settings.normalize(); err != nil || settings.Threads != 1 || settings.Promiscuous == nil || !*settings.Promiscuous || settings.BPFFilter != "tcp port 80" {
		t.Fatal("默认采集参数无效", settings, err)
	}
	interfaces, err := Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range interfaces {
		if item.Up && !item.Loopback && item.MAC != "" {
			if err = (&CaptureSettings{Interfaces: []string{item.Name, item.Name}}).normalize(); err == nil {
				t.Fatal("重复网卡被接受")
			}
			return
		}
	}
}

func TestCaptureTemplateAcceptsExplicitlyDisabledPlugins(t *testing.T) {
	if runtime.GOOS != "linux" {
		return
	}
	e := captureFixture(t)
	f, err := os.OpenFile(e.Config.SuricataConfig, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.WriteString("plugins: []\n")
	_ = f.Close()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = NewCaptureSupervisor(e); err != nil {
		t.Fatal("显式禁用插件的采集模板被拒绝", err)
	}
}

func TestCaptureRestartDoesNotRestoreRuntimeObservations(t *testing.T) {
	if runtime.GOOS != "linux" {
		return
	}
	e := captureFixture(t)
	settings := CaptureSettings{Interfaces: []string{}, Threads: 2}
	observed := time.Now().UTC().Add(-time.Hour)
	old := CaptureState{CaptureSettings: settings, Revision: 4, AppliedRevision: 4, AppliedSettings: &settings, Status: "running", ConfigSHA256: strings.Repeat("a", 64), PID: 1234, Counters: map[string]string{"kernelPackets": "999"}, CountersObservedAt: &observed, SpoolBytes: "9988", SpoolBudget: "104857600", Rotations: "19", RotationPending: true}
	raw, err := json.Marshal(old)
	if err != nil {
		t.Fatal(err)
	}
	if err = e.WAL.SaveLocalConfig(raw, "admin", "configure_before_restart"); err != nil {
		t.Fatal(err)
	}
	s, err := NewCaptureSupervisor(e)
	if err != nil {
		t.Fatal(err)
	}
	state := s.Snapshot()
	if state.Revision != 4 || state.Threads != 2 || state.Status != "stopped" || state.PID != 0 || state.AppliedRevision != 0 || state.AppliedSettings != nil || state.ConfigSHA256 != "" || state.CountersObservedAt != nil || len(state.Counters) != 0 || state.SpoolBytes != "" || state.SpoolBudget != "" || state.Rotations != "" || state.RotationPending {
		t.Fatal("重启保留了旧进程或磁盘观测，或丢失了期望配置", state)
	}
}

func TestCaptureRenderOwnsProcessOutputsAndPassivelyCaptures(t *testing.T) {
	e := captureFixture(t)
	e.Config.SuricataRulesPath, e.Config.SuricataSocket = filepath.Join(t.TempDir(), "rules.rules"), filepath.Join(t.TempDir(), "engine.sock")
	s := &CaptureSupervisor{Engine: e, WAL: e.WAL, root: filepath.Dir(e.Config.StatePath), base: map[string]any{"run-as": map[string]any{"user": "unknown"}, "pid-file": "/external/pid", "outputs": []any{"external-log"}}}
	promiscuous := false
	raw, err := s.render(CaptureSettings{Interfaces: []string{"capture0", "capture1"}, Threads: 2, BPFFilter: "tcp port 80", Promiscuous: &promiscuous})
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err = yaml.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	if value["run-as"] != nil || value["pid-file"] != nil || value["default-log-dir"] != s.root || strings.Contains(string(raw), "external-log") || strings.Contains(string(raw), "copy-mode") {
		t.Fatal("配置没有约束到专属的旁路采集进程")
	}
	interfaces := value["af-packet"].([]any)
	a, b := interfaces[0].(map[string]any), interfaces[1].(map[string]any)
	if len(interfaces) != 2 || a["cluster-id"] == b["cluster-id"] || a["bpf-filter"] != "tcp port 80" || a["disable-promisc"] != true || a["threads"] != 2 || a["checksum-checks"] != "kernel" {
		t.Fatal("采集目标或线程配置不一致")
	}
	capture := value["capture"].(map[string]any)
	if capture["checksum-validation"] != "all" || capture["disable-offloading"] != false {
		t.Fatal("旁路采集不能停用校验和验证或修改网卡卸载设置")
	}
	outputs := value["outputs"].([]any)
	eve := outputs[0].(map[string]any)["eve-log"].(map[string]any)
	protocols := map[string]map[string]any{}
	for _, entry := range eve["types"].([]any) {
		if options, ok := entry.(map[string]any); ok {
			for name, fields := range options {
				protocols[name] = fields.(map[string]any)
			}
		}
	}
	for _, name := range []string{"http", "tls"} {
		if protocols[name]["extended"] != true || protocols[name]["custom"] != nil || protocols[name]["dump-all-headers"] != nil {
			t.Fatal("协议元数据缺少扩展字段或启用了未要求的全量头信息", name)
		}
	}
	if s.base["run-as"] == nil || s.base["pid-file"] == nil {
		t.Fatal("生成配置污染了原模板")
	}
}

func TestCaptureReadinessRequiresRunningPacketPolls(t *testing.T) {
	for _, raw := range []string{`{}`, `{"capture":{"kernel_packets":0}}`, `{"capture":{"afpacket":{"polls":0}}}`, `{"capture":{"afpacket":{"polls":-1}}}`, `{"capture":{"afpacket":{"polls":"1"}}}`, `{"capture":{"afpacket":{"polls":1.5}}}`, `null`, `{"capture":`} {
		if captureHasStarted(json.RawMessage(raw)) {
			t.Fatal("未运行或不可核对的捕获线程被声明就绪", raw)
		}
	}
	if !captureHasStarted(json.RawMessage(`{"capture":{"kernel_packets":0,"afpacket":{"polls":1}}}`)) {
		t.Fatal("无流量但实际轮询的旁路采集器未就绪")
	}
}

func TestCaptureStartupRequiresOwnedConfiguration(t *testing.T) {
	if runtime.GOOS != "linux" {
		if _, err := NewCaptureSupervisor(captureFixture(t)); err == nil {
			t.Fatal("非 Linux 环境接受了托管捕获")
		}
		return
	}
	for _, name := range []string{"重复键", "多个文档", "非映射", "外部配置", "外部插件", "无模板", "辅助链接", "开放目录", "目录链接", "坏持久配置"} {
		t.Run(name, func(t *testing.T) {
			e := captureFixture(t)
			switch name {
			case "重复键":
				_ = os.WriteFile(e.Config.SuricataConfig, []byte("a: 1\na: 2\n"), 0600)
			case "多个文档":
				_ = os.WriteFile(e.Config.SuricataConfig, []byte("a: 1\n---\nb: 2\n"), 0600)
			case "非映射":
				_ = os.WriteFile(e.Config.SuricataConfig, []byte("[1,2,3]\n"), 0600)
			case "外部配置", "外部插件":
				key := "include"
				if name == "外部插件" {
					key = "plugins"
				}
				_ = os.WriteFile(e.Config.SuricataConfig, []byte(key+": [external]\n"), 0600)
			case "无模板":
				_ = os.Remove(e.Config.SuricataConfig)
			case "辅助链接":
				if err := os.Symlink(e.Config.SuricataConfig, filepath.Join(filepath.Dir(e.Config.StatePath), "classification.config")); err != nil {
					t.Fatal(err)
				}
			case "开放目录", "目录链接":
				root := filepath.Join(filepath.Dir(e.Config.StatePath), "capture")
				if name == "目录链接" {
					if err := os.Symlink(t.TempDir(), root); err != nil {
						t.Fatal(err)
					}
				} else {
					if err := os.Mkdir(root, 0755); err != nil {
						t.Fatal(err)
					}
				}
			case "坏持久配置":
				if err := e.WAL.SaveLocalConfig([]byte(`{`), "admin", "request"); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := NewCaptureSupervisor(e); err == nil {
				t.Fatal("不可信采集配置被接受")
			}
		})
	}
	e := captureFixture(t)
	s, err := NewCaptureSupervisor(e)
	if err != nil {
		t.Fatal(err)
	}
	if state := s.Snapshot(); state.Status != "stopped" || !state.Managed || state.AppliedSettings != nil || s.Ready() {
		t.Fatal("未启动引擎被声明为运行")
	}
	state, err := s.Configure(context.Background(), CaptureSettings{Interfaces: []string{}}, "admin", "stop_capture")
	if err != nil || state.Status != "stopped" || state.Revision != 1 || state.AppliedRevision != 1 {
		t.Fatal("停止配置没有实际应用", state, err)
	}
	_, err = s.Configure(context.Background(), CaptureSettings{Interfaces: []string{}}, "admin", "same_settings")
	if err != nil || s.Snapshot().Revision != 1 {
		t.Fatal("相同配置重复产生修订", err)
	}
	s.op.Lock()
	_, err = s.Configure(context.Background(), CaptureSettings{Interfaces: []string{}}, "admin", "busy")
	s.op.Unlock()
	if !errors.Is(err, ErrCaptureBusy) {
		t.Fatal("并发配置未拒绝", err)
	}
}

// 这里只核对启动记录与磁盘变更的拒绝边界，实际捕获由 Linux Docker 端到端用例验收。
func TestCaptureManifestRejectsChangedFilesAndExitedProcess(t *testing.T) {
	e := captureFixture(t)
	root := filepath.Dir(e.Config.StatePath)
	e.Config.SuricataPIDFile = filepath.Join(root, "engine.pid")
	raw, _ := os.ReadFile(e.Config.SuricataConfig)
	pid := strconv.Itoa(os.Getpid())
	if err := durableFile(e.Config.SuricataPIDFile, []byte(pid)); err != nil {
		t.Fatal(err)
	}
	process := &captureProcess{command: &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}, done: make(chan struct{}), sha: control.Digest(raw), aux: map[string]string{}}
	s := &CaptureSupervisor{Engine: e, WAL: e.WAL, root: root, active: process}
	if err := s.Check(context.Background()); err != nil {
		t.Fatal("记录检查边界不成立", err)
	}
	if err := durableFile(e.Config.SuricataConfig, []byte("changed: true\n")); err != nil {
		t.Fatal(err)
	}
	if err := s.Check(context.Background()); err == nil {
		t.Fatal("检测配置被改写后仍被信任")
	}
	if err := durableFile(e.Config.SuricataConfig, raw); err != nil {
		t.Fatal(err)
	}
	aux := filepath.Join(root, "classification.config")
	if err := durableFile(aux, []byte("classification")); err != nil {
		t.Fatal(err)
	}
	process.aux["classification.config"] = control.Digest([]byte("classification"))
	if err := durableFile(aux, []byte("other")); err != nil {
		t.Fatal(err)
	}
	if err := s.Check(context.Background()); err == nil {
		t.Fatal("辅助文件变更未失效")
	}
	delete(process.aux, "classification.config")
	if err := durableFile(e.Config.SuricataPIDFile, []byte("other")); err != nil {
		t.Fatal(err)
	}
	if err := s.Check(context.Background()); err == nil {
		t.Fatal("PID 变更未失效")
	}
	if err := durableFile(e.Config.SuricataPIDFile, []byte(pid)); err != nil {
		t.Fatal(err)
	}
	close(process.done)
	if err := s.Check(context.Background()); err == nil {
		t.Fatal("已退出的进程仍被信任")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.Check(ctx); err == nil {
		t.Fatal("取消后仍核实启动记录")
	}
	s.active = nil
	if err := s.Check(context.Background()); err == nil {
		t.Fatal("不存在的进程被信任")
	}
}

func TestCaptureSnapshotsDoNotExposeMutableSettingsAndSpoolIsBounded(t *testing.T) {
	e := captureFixture(t)
	e.Config.EVEPath = filepath.Join(filepath.Dir(e.Config.StatePath), "eve.json")
	value := true
	s := &CaptureSupervisor{Engine: e, WAL: e.WAL, state: CaptureState{CaptureSettings: CaptureSettings{Interfaces: []string{"capture0"}, Promiscuous: &value}, AppliedSettings: &CaptureSettings{Interfaces: []string{"capture1"}, Promiscuous: &value}, Counters: map[string]string{"decoder.bytes": "18446744073709551615"}}}
	state := s.Snapshot()
	state.Interfaces[0], state.AppliedSettings.Interfaces[0], *state.Promiscuous, *state.AppliedSettings.Promiscuous = "foreign", "foreign", false, false
	state.Counters["decoder.bytes"] = "0"
	if state = s.Snapshot(); state.Interfaces[0] != "capture0" || state.AppliedSettings.Interfaces[0] != "capture1" || !*state.Promiscuous || !*state.AppliedSettings.Promiscuous || state.Counters["decoder.bytes"] != "18446744073709551615" {
		t.Fatal("外部修改污染了实际采集快照")
	}
	if !s.withinSpoolBudget() {
		t.Fatal("空采集缓冲未允许启动")
	}
	file, err := os.Create(e.Config.EVEPath)
	if err != nil {
		t.Fatal(err)
	}
	if err = file.Truncate(e.Config.CaptureSpoolBytes); err != nil {
		t.Fatal(err)
	}
	_ = file.Close()
	if s.withinSpoolBudget() {
		t.Fatal("超出缓冲额度仍允许采集")
	}
	s.failure("capture_spool_full")
	if s.Snapshot().Status != "failed" || s.Snapshot().ErrorCode != "capture_spool_full" || s.retry.Before(time.Now()) {
		t.Fatal("额度耗尽未形成可核对的失败状态")
	}
	if _, err := json.Marshal(s.Snapshot()); err != nil {
		t.Fatal(err)
	}
}

func TestNativeCaptureBPFCompilerRejectsFilterBeforeProcessRestart(t *testing.T) {
	binary := os.Getenv("SB_TEST_SURICATA_BINARY")
	if binary == "" {
		t.Skip("需要真实 Suricata 8.0.7 与隔离执行环境")
	}
	e := captureFixture(t)
	e.Config.SuricataBinary = binary
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := validateCaptureFilter(ctx, e.Config, ""); err != nil {
		t.Fatal("无过滤器被拒绝", err)
	}
	if err := validateCaptureFilter(ctx, e.Config, "tcp port 8088"); err != nil {
		t.Fatal("实际 libpcap 拒绝合法过滤器", err)
	}
	if err := validateCaptureFilter(ctx, e.Config, "tcp port ???"); err == nil {
		t.Fatal("非法捕获过滤器未在实际编译器中拒绝")
	}
}

func TestBPFInstructionsRejectsTruncatedAndOversizedCompilation(t *testing.T) {
	for _, raw := range []string{"", "0", "4097", "1 6 0 0", "2 6 0 0 65535", "1 65536 0 0 0", "1 6 256 0 0", "1 6 0 256 0", "1 6 0 0 4294967296", "1 6 0 0 -1", "1 6 0 0 x"} {
		if validateBPFInstructions(raw) == nil {
			t.Fatal("不完整或越界的原生编译结果被接受", raw)
		}
	}
	if err := validateBPFInstructions("2\n6 0 0 65535\n6 0 0 0\n"); err != nil {
		t.Fatal("合法 BPF 指令被拒绝", err)
	}
}

func TestCaptureCountersPreservesPrecisionAndMissingFields(t *testing.T) {
	raw := json.RawMessage(`{"uptime":1,"capture":{"kernel_packets":18446744073709551615,"kernel_drops":0},"decoder":{"pkts":9007199254740993,"bytes":42},"flow":{"active":3},"tcp":{"reassembly_gap":4,"segment_memcap_drop":5},"threads":{"worker":{"capture":{"kernel_packets":123}}}}`)
	values, valid := captureCounters(raw)
	if !valid || len(values) != 7 || values["capture.kernel_packets"] != "18446744073709551615" || values["decoder.pkts"] != "9007199254740993" || values["capture.kernel_drops"] != "0" {
		t.Fatal("实际计数精度或总计范围不正确", values)
	}
	values, valid = captureCounters(json.RawMessage(`{"capture":{"kernel_packets":-1,"kernel_drops":18446744073709551616},"decoder":{"pkts":1.5,"bytes":"42"},"flow":{"active":true},"tcp":{"reassembly_gap":null}}`))
	if !valid || len(values) != 0 {
		t.Fatal("畸形或缺测计数被伪造为有效值", values)
	}
	for _, raw := range []string{"null", "[]", "true", "{"} {
		if _, valid := captureCounters(json.RawMessage(raw)); valid {
			t.Fatal("无效统计协议被接受", raw)
		}
	}
}
