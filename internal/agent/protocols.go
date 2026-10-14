package agent

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/protocolcap"
)

// ProtocolInspector 的缓存只减少原生命令开销；配置或运行状态变化后不复用旧能力结论。
type ProtocolInspector struct {
	Engine *Engine
	mu     sync.Mutex
	last   *protocolcap.Report
	key    string
	until  time.Time
	record atomic.Pointer[protocolcap.Report]
}

func protocolFailure(code string) *protocolcap.Report {
	state := "unavailable"
	if code == "inspection_pending" {
		state = "pending"
	}
	return &protocolcap.Report{SchemaVersion: protocolcap.SchemaVersion, State: state, Source: "unavailable", ObservedAt: time.Now().UTC(), ErrorCode: code, Protocols: []protocolcap.Entry{}, Limits: []protocolcap.Limit{}}
}

// Snapshot 不运行原生命令，避免阻塞心跳、任务回执或本地健康读取。
func (p *ProtocolInspector) Snapshot(ctx context.Context) *protocolcap.Report {
	if ctx.Err() != nil {
		return protocolFailure("protocol_inspection_cancelled")
	}
	r := p.record.Load()
	if r == nil {
		return protocolFailure("inspection_pending")
	}
	if r.State == "observed" && p.Engine != nil && p.Engine.Capture != nil {
		s := p.Engine.Capture.Snapshot()
		if s.ConfigSHA256 != r.ConfigSHA256 || (s.Status == "running") != r.CaptureActive {
			return protocolFailure("inspection_pending")
		}
	}
	return r
}

func (p *ProtocolInspector) Run(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for ctx.Err() == nil {
		p.Observe(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (p *ProtocolInspector) Observe(ctx context.Context) (result *protocolcap.Report) {
	if !p.mu.TryLock() {
		return protocolFailure("inspection_pending")
	}
	defer p.mu.Unlock()
	defer func() { p.record.Store(result) }()
	e := p.Engine
	if e == nil || e.Config.SuricataBinary == "" || e.Config.SuricataConfig == "" {
		return protocolFailure("engine_not_configured")
	}
	if ctx.Err() != nil {
		return protocolFailure("protocol_inspection_cancelled")
	}
	raw, err := readRegularBounded(e.Config.SuricataConfig, 1024*1024, false)
	if err != nil {
		return protocolFailure("protocol_configuration_unavailable")
	}
	configSHA := control.Digest(raw)
	active, source := p.captureSource(configSHA)
	// 缓存身份包含实际文件摘要；检测进程从运行到停止也会使先前观测失效。
	binary, err := exec.LookPath(e.Config.SuricataBinary)
	if err != nil {
		return protocolFailure("native_protocol_inventory_unavailable")
	}
	binary, err = filepath.EvalSymlinks(binary)
	if err != nil {
		return protocolFailure("native_protocol_inventory_unavailable")
	}
	binarySHA, err := ruleFileDigest(binary, 256*1024*1024)
	if err != nil {
		return protocolFailure("native_protocol_inventory_unavailable")
	}
	key := source + "/" + configSHA + "/" + binarySHA
	if active {
		key += "/active"
	}
	if p.last != nil && p.key == key && time.Now().Before(p.until) {
		return p.last
	}
	report := p.inspect(ctx, binary, binarySHA, raw, configSHA, source, active)
	p.last, p.key, p.until = report, key, time.Now().Add(30*time.Second)
	if report.State != "observed" {
		p.until = time.Now().Add(5 * time.Second)
	}
	return report
}

func (p *ProtocolInspector) captureSource(configSHA string) (bool, string) {
	if p.Engine.Capture == nil {
		return false, "offline_template"
	}
	s := p.Engine.Capture.Snapshot()
	return s.ConfigSHA256 == configSHA && s.Status == "running" && p.Engine.Capture.Ready(), "managed_configuration"
}

func (p *ProtocolInspector) inspect(ctx context.Context, binary, binarySHA string, raw []byte, configSHA, source string, active bool) *protocolcap.Report {
	e := p.Engine
	configuration, err := protocolcap.Configuration(raw)
	if err != nil {
		return protocolFailure("protocol_configuration_unsupported")
	}
	if !e.ReplayAvailable() {
		return protocolFailure("engine_isolation_unavailable")
	}
	job, err := os.MkdirTemp("", "sb-protocols-")
	if err != nil {
		return protocolFailure("native_protocol_inventory_unavailable")
	}
	defer os.RemoveAll(job)
	input, output := filepath.Join(job, "input"), filepath.Join(job, "output")
	for _, path := range []string{input, output} {
		if err = os.Mkdir(path, 0700); err != nil {
			return protocolFailure("native_protocol_inventory_unavailable")
		}
	}
	snapshot := filepath.Join(input, "suricata.yaml")
	if err = durableFile(snapshot, raw); err != nil {
		return protocolFailure("native_protocol_inventory_unavailable")
	}
	// 固定执行字节，不让本机包更新与两次原生命令交错形成混合版本的观测。
	frozenBinary := filepath.Join(input, "suricata")
	if actual, copyErr := copyBounded(binary, frozenBinary, 256*1024*1024); copyErr != nil || actual != binarySHA || os.Chmod(frozenBinary, 0500) != nil {
		return protocolFailure("protocol_observation_changed")
	}
	call, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	version, _, _, err := executeBounded(call, frozenBinary, job, input, output, []string{"-V"})
	if err != nil || version.truncated || !engineVersion.Match(version.data) {
		if call.Err() != nil {
			return protocolFailure("protocol_inspection_cancelled")
		}
		return protocolFailure("engine_version_mismatch")
	}
	list, _, _, err := executeBounded(call, frozenBinary, job, input, output, []string{"-c", snapshot, "-l", output, "--list-app-layer-protos"})
	if err != nil || list.truncated {
		if call.Err() != nil {
			return protocolFailure("protocol_inspection_cancelled")
		}
		return protocolFailure("native_protocol_inventory_unavailable")
	}
	names, err := protocolcap.ListProtocols(list.data)
	if err != nil {
		return protocolFailure("native_protocol_inventory_unavailable")
	}
	current, err := readRegularBounded(e.Config.SuricataConfig, 1024*1024, false)
	currentBinarySHA, binaryErr := ruleFileDigest(binary, 256*1024*1024)
	currentActive, currentSource := p.captureSource(configSHA)
	if err != nil || binaryErr != nil || currentBinarySHA != binarySHA || control.Digest(current) != configSHA || active != currentActive || source != currentSource {
		return protocolFailure("protocol_observation_changed")
	}
	// 文件、取证与规则效果分别标记；列出解析器绝不授予文件外送、设备动作或效果资格。
	base := protocolcap.Report{ObservedAt: time.Now().UTC(), Source: source, CaptureActive: active, EngineVersion: "8.0.7", EngineSHA256: binarySHA, ConfigSHA256: configSHA}
	report := protocolcap.Build(base, names, configuration, e.WAL != nil && e.WAL.packetArchives != nil)
	if err = report.Validate(); err != nil {
		return protocolFailure("native_protocol_inventory_unavailable")
	}
	return &report
}
