package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"hash/fnv"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/detectionquality"
	"github.com/kkx600/StarBeacon/internal/store"
	"go.yaml.in/yaml/v3"
)

var ErrCaptureBusy = errors.New("采集配置或规则事务正在执行")

type CaptureSettings control.CaptureSettings

type CaptureState struct {
	CaptureSettings
	Managed            bool                     `json:"managed"`
	Status             string                   `json:"status"`
	Revision           uint64                   `json:"revision"`
	AppliedRevision    uint64                   `json:"applied_revision"`
	AppliedSettings    *CaptureSettings         `json:"applied_settings,omitempty"`
	UpdatedAt          time.Time                `json:"updated_at"`
	ObservedAt         time.Time                `json:"observed_at"`
	ConfigSHA256       string                   `json:"config_sha256,omitempty"`
	SettingsSHA256     string                   `json:"settings_sha256"`
	CountersObservedAt *time.Time               `json:"counters_observed_at,omitempty"`
	SpoolBytes         string                   `json:"spool_bytes,omitempty"`
	SpoolBudget        string                   `json:"spool_budget,omitempty"`
	Rotations          string                   `json:"rotations,omitempty"`
	RotationPending    bool                     `json:"rotation_pending"`
	ErrorCode          string                   `json:"error_code,omitempty"`
	PID                int                      `json:"pid,omitempty"`
	Counters           map[string]string        `json:"counters,omitempty"`
	Quality            *detectionquality.Report `json:"quality,omitempty"`
}

func (s *CaptureSettings) normalize() error {
	if s.Interfaces == nil || len(s.Interfaces) > 16 || s.Threads < 0 || s.Threads > 64 || len(s.Interfaces)*s.Threads > 128 || len(s.BPFFilter) > 2048 || strings.ContainsAny(s.BPFFilter, "\x00\r\n") {
		return errors.New("采集参数格式无效")
	}
	if s.Threads == 0 {
		s.Threads = 1
	}
	if s.Promiscuous == nil {
		value := true
		s.Promiscuous = &value
	}
	s.BPFFilter = strings.TrimSpace(s.BPFFilter)
	if err := control.CaptureSettings(*s).Validate(); err != nil {
		return err
	}
	return validateCaptureInterfaces(s.Interfaces)
}

func validateCaptureInterfaces(names []string) error {
	available, err := Interfaces()
	if err != nil {
		return err
	}
	valid := map[string]bool{}
	for _, i := range available {
		mac, err := net.ParseMAC(i.MAC)
		valid[i.Name] = i.Up && !i.Loopback && err == nil && len(mac) == 6
	}
	seen := map[string]bool{}
	for _, name := range names {
		if !valid[name] || seen[name] {
			return errors.New("请选择不重复且已启用的非回环 Ethernet 网卡")
		}
		seen[name] = true
	}
	return nil
}

type captureProcess struct {
	command *exec.Cmd
	done    chan struct{}
	sha     string
	aux     map[string]string
}

// 只管理本设备专属目录和子进程，不配置管理地址、路由、防火墙或内核全局参数。
type CaptureSupervisor struct {
	Engine    *Engine
	WAL       *WAL
	root      string
	base      map[string]any
	op        sync.Mutex
	mu        sync.RWMutex
	state     CaptureState
	active    *captureProcess
	retry     time.Time
	rotations uint64
	quality   detectionquality.Tracker
}

func NewCaptureSupervisor(engine *Engine) (*CaptureSupervisor, error) {
	if runtime.GOOS != "linux" || engine.WAL == nil {
		return nil, errors.New("托管采集要求 Linux 和持久队列")
	}
	source := engine.Config.SuricataConfig
	raw, err := readRegularBounded(source, 1024*1024, false)
	if err != nil {
		return nil, err
	}
	var base map[string]any
	d := yaml.NewDecoder(bytes.NewReader(raw))
	if d.Decode(&base) != nil || len(base) == 0 || d.Decode(new(any)) != io.EOF || base["include"] != nil {
		return nil, errors.New("采集模板必须为单文档 YAML，不能引用外部配置或插件")
	}
	if plugins, exists := base["plugins"]; exists && plugins != nil {
		list, valid := plugins.([]any)
		if !valid || len(list) != 0 {
			return nil, errors.New("采集模板不能引用外部插件")
		}
	}
	root := filepath.Join(filepath.Dir(engine.Config.StatePath), "capture")
	if err = os.MkdirAll(root, 0700); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(root); err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("采集工作目录必须为设备专属的私有目录")
	}
	for name, setting := range map[string]string{"classification.config": "classification-file", "reference.config": "reference-config-file", "threshold.config": "threshold-file"} {
		path := filepath.Join(filepath.Dir(source), name)
		if configured, ok := base[setting].(string); ok && configured != "" {
			path = configured
			if !filepath.IsAbs(path) {
				path = filepath.Join(filepath.Dir(source), path)
			}
		}
		data, err := readRegularBounded(path, 1024*1024, false)
		if errors.Is(err, os.ErrNotExist) && base[setting] == nil {
			delete(base, setting)
			continue
		}
		if err != nil {
			return nil, errors.New("采集模板辅助文件不可读取")
		}
		if err = durableFile(filepath.Join(root, name), data); err != nil {
			return nil, err
		}
		base[setting] = filepath.Join(root, name)
	}
	engine.Config.SuricataConfig = filepath.Join(root, "engine.yaml")
	engine.Config.SuricataSocket = filepath.Join(root, "engine.sock")
	engine.Config.SuricataPIDFile = filepath.Join(root, "engine.pid")
	engine.Config.EVEPath = filepath.Join(root, "eve.json")
	if engine.Config.SuricataRulesPath == "" {
		engine.Config.SuricataRulesPath = filepath.Join(root, "active.rules")
	}
	if _, err = os.Lstat(engine.Config.SuricataRulesPath); errors.Is(err, os.ErrNotExist) {
		// 初始规则检测公开 Git 配置泄露；正式规则仍通过带验证证据的发布任务管理。
		const initial = `alert http any any -> any any (msg:"StarBeacon HTTP repository configuration access"; flow:established,to_server; http.uri; content:"/.git/config"; nocase; sid:1000001; rev:1;)`
		err = durableFile(engine.Config.SuricataRulesPath, []byte(initial))
	}
	if err != nil {
		return nil, err
	}
	s := &CaptureSupervisor{Engine: engine, WAL: engine.WAL, root: root, base: base}
	s.state = CaptureState{CaptureSettings: CaptureSettings{Interfaces: []string{}, Threads: 1}, Managed: true, Status: "stopped"}
	saved, err := s.WAL.LocalConfig()
	if err != nil || json.Unmarshal(saved, &s.state) != nil {
		return nil, errors.New("持久采集配置不可读取")
	}
	s.state.Managed, s.state.AppliedRevision, s.state.PID = true, 0, 0
	s.state.AppliedSettings = nil
	s.state.Status, s.state.ConfigSHA256, s.state.ErrorCode = "stopped", "", ""
	s.state.ObservedAt, s.state.Counters, s.state.CountersObservedAt = time.Now().UTC(), nil, nil
	s.state.Quality = nil
	// 暂存与轮转状态须从本次磁盘和原生进程重新观测，不能沿用持久配置中的旧快照。
	s.state.SpoolBytes, s.state.SpoolBudget, s.state.Rotations, s.state.RotationPending = "", "", "", false
	engine.Capture = s
	return s, nil
}

func (s *CaptureSupervisor) Snapshot() CaptureState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v := s.state
	v.Interfaces = append([]string{}, v.Interfaces...)
	if v.Promiscuous != nil {
		value := *v.Promiscuous
		v.Promiscuous = &value
	}
	if v.AppliedSettings != nil {
		settings := *v.AppliedSettings
		settings.Interfaces = append([]string{}, settings.Interfaces...)
		if settings.Promiscuous != nil {
			value := *settings.Promiscuous
			settings.Promiscuous = &value
		}
		v.AppliedSettings = &settings
	}
	v.Counters = make(map[string]string, len(s.state.Counters))
	if v.CountersObservedAt != nil {
		observed := *v.CountersObservedAt
		v.CountersObservedAt = &observed
	}
	for key, value := range s.state.Counters {
		v.Counters[key] = value
	}
	v.SettingsSHA256 = control.CaptureSettingsDigest(control.CaptureSettings(v.CaptureSettings))
	quality := s.quality.Snapshot(time.Now().UTC(), s.active != nil && s.state.Status == "running")
	v.Quality = &quality
	return v
}

// 质量观测仅来自托管读取器已持久提交的原生 EVE；不采用控制接口中没有采样时间的缓存计数。
func (s *CaptureSupervisor) ObserveStats(payload []byte, observed time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active != nil && s.state.Status == "running" {
		s.quality.Observe(payload, observed)
	}
}

func (s *CaptureSupervisor) Ready() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active != nil && s.state.Status == "running" && s.state.AppliedRevision == s.state.Revision
}

func (s *CaptureSupervisor) Configure(ctx context.Context, settings CaptureSettings, username, requestID string) (CaptureState, error) {
	if err := settings.normalize(); err != nil {
		return CaptureState{}, err
	}
	if !s.op.TryLock() {
		return CaptureState{}, ErrCaptureBusy
	}
	defer s.op.Unlock()
	return s.configureLocked(ctx, settings, username, requestID)
}

func (s *CaptureSupervisor) configureLocked(ctx context.Context, settings CaptureSettings, username, requestID string) (CaptureState, error) {
	current := s.Snapshot()
	if current.Revision >= 9007199254740991 {
		return CaptureState{}, errors.New("采集配置修订已达到上限")
	}
	wanted, _ := json.Marshal(settings)
	previous, _ := json.Marshal(current.CaptureSettings)
	if bytes.Equal(wanted, previous) && current.Revision == current.AppliedRevision && (current.Status == "running" || current.Status == "stopped") {
		return current, nil
	}
	current.CaptureSettings, current.Revision = settings, current.Revision+1
	current.SettingsSHA256 = control.CaptureSettingsDigest(control.CaptureSettings(settings))
	current.Status, current.ErrorCode, current.UpdatedAt = "pending", "", time.Now().UTC()
	raw, err := json.Marshal(current)
	if err != nil {
		return CaptureState{}, err
	}
	if err = s.WAL.SaveLocalConfigWithContext(ctx, raw, username, requestID); err != nil {
		return CaptureState{}, err
	}
	s.mu.Lock()
	s.state = current
	s.mu.Unlock()
	// 期望配置已经持久化；实际启动失败通过状态返回，不能伪装为未保存或已生效。
	s.apply(ctx)
	return s.Snapshot(), nil
}

func (s *CaptureSupervisor) ConfigureRemote(ctx context.Context, p control.CaptureConfiguration, requestID string) (CaptureState, string, error) {
	if err := ctx.Err(); err != nil {
		return CaptureState{}, "command_cancelled", err
	}
	if p.Validate() != nil || validateCaptureInterfaces(p.Settings.Interfaces) != nil {
		return CaptureState{}, "invalid_capture_configuration", errors.New("采集配置或本机网卡不可用")
	}
	if !s.op.TryLock() {
		return CaptureState{}, "capture_operation_in_progress", ErrCaptureBusy
	}
	defer s.op.Unlock()
	current := s.Snapshot()
	if current.Revision != *p.ExpectedRevision || current.ConfigSHA256 != p.ExpectedConfigSHA256 || control.CaptureSettingsDigest(control.CaptureSettings(current.CaptureSettings)) != p.ExpectedSettingsSHA256 {
		return current, "capture_configuration_changed", errors.New("采集配置已变更，请重新观测后提交")
	}
	if current.PID > 0 && s.Check(ctx) != nil {
		return current, "capture_process_or_configuration_changed", errors.New("检测进程与配置的启动记录无法核对")
	}
	state, err := s.configureLocked(ctx, CaptureSettings(p.Settings), "platform", requestID)
	if err != nil {
		return state, "local_storage_unavailable", err
	}
	raw, _ := json.Marshal(state)
	if control.ValidateCaptureResult(p, raw) != nil {
		code := state.ErrorCode
		if code == "" {
			code = "capture_application_unconfirmed"
		}
		return state, code, errors.New("期望配置已保存，实际采集状态尚未确认")
	}
	return state, "", nil
}

func (s *CaptureSupervisor) Start(ctx context.Context) {
	s.op.Lock()
	defer s.op.Unlock()
	s.apply(ctx)
}

func (s *CaptureSupervisor) apply(ctx context.Context) {
	if !s.Engine.ruleApplyMu.TryLock() {
		s.failure("rule_operation_in_progress")
		return
	}
	defer s.Engine.ruleApplyMu.Unlock()
	settings := s.Snapshot()
	if err := settings.CaptureSettings.normalize(); err != nil {
		s.failure("capture_interface_unavailable")
		return
	}
	if _, err := os.Lstat(s.Engine.ruleJournalPath()); err == nil {
		// 启动恢复可以先装载当前规则；已有进程不能被配置变更覆盖恢复现场。
		if s.active != nil {
			s.failure("rule_recovery_required")
			return
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		s.failure("local_storage_unavailable")
		return
	}
	if len(settings.Interfaces) == 0 {
		s.stop(ctx)
		s.mu.Lock()
		s.state.Status, s.state.ErrorCode, s.state.PID = "stopped", "", 0
		s.state.AppliedRevision, s.state.ObservedAt = settings.Revision, time.Now().UTC()
		s.state.AppliedSettings = &settings.CaptureSettings
		s.mu.Unlock()
		return
	}
	if !s.withinSpoolBudget() {
		s.failure("capture_spool_full")
		return
	}
	raw, err := s.render(settings.CaptureSettings)
	if err != nil {
		s.failure("capture_template_invalid")
		return
	}
	candidate := filepath.Join(s.root, "candidate.yaml")
	if err = durableFile(candidate, raw); err != nil {
		s.failure("local_storage_unavailable")
		return
	}
	defer os.Remove(candidate)
	rules, err := readRegularBounded(s.Engine.Config.SuricataRulesPath, 900*1024, false)
	if err != nil || store.ValidateRules(string(rules)) != nil {
		s.failure("registered_rules_unavailable")
		return
	}
	cfg := s.Engine.Config
	cfg.SuricataConfig = candidate
	validation := &Engine{Config: cfg, WAL: s.WAL}
	payload, _ := control.RulePayload(control.RulePackage{PackageID: "capture", Revision: 1, EngineVersion: "8.0.7", Text: string(rules), SHA256: control.Digest(rules)})
	call, cancel := context.WithTimeout(ctx, 15*time.Second)
	_, code, err := validation.Execute(call, control.Command{Kind: "rules.validate", Payload: payload})
	cancel()
	if err != nil {
		s.failure(code)
		return
	}
	filterCheck, cancel := context.WithTimeout(ctx, 10*time.Second)
	err = validateCaptureFilter(filterCheck, cfg, settings.BPFFilter)
	cancel()
	if err != nil {
		code := "capture_filter_invalid"
		if errors.Is(err, ErrCaptureFilterCompilerUnavailable) {
			code = "capture_filter_compiler_unavailable"
		} else if errors.Is(err, ErrCaptureFilterBudget) {
			code = "capture_filter_resource_limit"
		}
		s.failure(code)
		return
	}
	old := s.Snapshot()
	previous, _ := readRegularBounded(s.Engine.Config.SuricataConfig, 1024*1024, false)
	hadProcess := s.active != nil
	s.stop(ctx)
	if ctx.Err() == nil {
		err = durableFile(s.Engine.Config.SuricataConfig, raw)
		if err == nil {
			err = s.launch(ctx, raw, settings.Revision, settings.CaptureSettings)
		}
	} else {
		err = ctx.Err()
	}
	if err == nil {
		return
	}
	s.stop(context.Background())
	// 仅恢复本管理器刚刚运行过的配置，不启动未知的磁盘文件。
	if hadProcess && old.AppliedSettings != nil && len(previous) > 0 && durableFile(s.Engine.Config.SuricataConfig, previous) == nil {
		restore, stop := context.WithTimeout(context.Background(), 10*time.Second)
		_ = s.launch(restore, previous, old.AppliedRevision, *old.AppliedSettings)
		stop()
	}
	s.failure("capture_start_failed")
}

func (s *CaptureSupervisor) render(settings CaptureSettings) ([]byte, error) {
	base := make(map[string]any, len(s.base))
	for key, value := range s.base {
		base[key] = value
	}
	delete(base, "run-as")
	delete(base, "pid-file")
	base["default-log-dir"] = s.root
	base["default-rule-path"] = filepath.Dir(s.Engine.Config.SuricataRulesPath)
	base["rule-files"] = []string{filepath.Base(s.Engine.Config.SuricataRulesPath)}
	base["unix-command"] = map[string]any{"enabled": true, "filename": s.Engine.Config.SuricataSocket}
	base["stats"] = map[string]any{"enabled": true, "interval": 5}
	base["logging"] = map[string]any{"default-log-level": "notice", "outputs": []any{}}
	// AF_PACKET 使用内核的校验和卸载标记；旁路管理器不修改网卡的卸载设置。
	base["capture"] = map[string]any{"checksum-validation": "all", "disable-offloading": false}
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(s.WAL.SensorID))
	var interfaces []any
	for i, name := range settings.Interfaces {
		value := map[string]any{"interface": name, "threads": settings.Threads, "cluster-id": int((hash.Sum32()+uint32(i))%65000) + 1, "cluster-type": "cluster_flow", "defrag": true, "use-mmap": true, "tpacket-v3": true, "disable-promisc": !*settings.Promiscuous, "checksum-checks": "kernel"}
		if settings.BPFFilter != "" {
			value["bpf-filter"] = settings.BPFFilter
		}
		interfaces = append(interfaces, value)
	}
	base["af-packet"] = interfaces
	// HTTP 请求方法和 TLS 协商版本依赖扩展日志；不启用全量请求头或证书链。
	base["outputs"] = []any{map[string]any{"eve-log": map[string]any{"enabled": true, "filetype": "regular", "filename": "eve.json", "append": true, "threaded": false, "ethernet": true, "community-id": true, "types": []any{map[string]any{"alert": map[string]any{"payload": true, "payload-buffer-size": "4kb", "packet": true}}, "flow", map[string]any{"http": map[string]any{"extended": true}}, "dns", map[string]any{"tls": map[string]any{"extended": true}}, "ssh", "smtp", "ftp", "smb", "nfs", "dhcp", map[string]any{"stats": map[string]any{"totals": true, "threads": false}}}}}}
	raw, err := yaml.Marshal(base)
	return append([]byte("%YAML 1.1\n---\n"), raw...), err
}

func (s *CaptureSupervisor) launch(ctx context.Context, raw []byte, revision uint64, settings CaptureSettings) error {
	_ = os.Remove(s.Engine.Config.SuricataSocket)
	aux := map[string]string{}
	for _, name := range []string{"classification.config", "reference.config", "threshold.config"} {
		hash, err := ruleFileDigest(filepath.Join(s.root, name), 1024*1024)
		if err == nil {
			aux[name] = hash
		} else if !errors.Is(err, os.ErrNotExist) {
			// 摘要函数返回通用错误；不存在的可选辅助文件单独判断。
			if _, missing := os.Lstat(filepath.Join(s.root, name)); !errors.Is(missing, os.ErrNotExist) {
				return errors.New("采集辅助文件不可信")
			}
		}
	}
	c := s.Engine.Config
	command := exec.Command(c.SuricataBinary, "-c", c.SuricataConfig, "--af-packet", "--runmode=workers", "--init-errors-fatal", "--strict-rule-keywords=all", "-l", s.root)
	command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
	command.Stdout, command.Stderr, command.WaitDelay = io.Discard, io.Discard, 2*time.Second
	command.SysProcAttr = captureProcessAttributes()
	done := make(chan struct{})
	started := time.Now().UTC()
	if err := startCaptureProcess(command, done); err != nil {
		return err
	}
	process := &captureProcess{command: command, done: done, sha: control.Digest(raw), aux: aux}
	s.mu.Lock()
	s.active = process
	s.state.Status, s.state.PID, s.state.ConfigSHA256 = "starting", command.Process.Pid, process.sha
	s.state.Counters, s.state.CountersObservedAt = nil, nil
	s.quality.Start(store.RandomID("engine_"), process.sha, started)
	s.mu.Unlock()
	if err := durableFile(c.SuricataPIDFile, []byte(strconv.Itoa(command.Process.Pid))); err != nil {
		return err
	}
	ready, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	for ready.Err() == nil {
		select {
		case <-process.done:
			return errors.New("检测引擎在采集就绪前退出")
		default:
		}
		if err := s.Engine.ensureManagedPath(ready); err == nil {
			stats, err := socketCommand(ready, c.SuricataSocket, "ruleset-stats", nil)
			var values []struct {
				Loaded int `json:"rules_loaded"`
				Failed int `json:"rules_failed"`
			}
			if err == nil && json.Unmarshal(stats, &values) == nil && len(values) == 1 && values[0].Loaded > 0 && values[0].Failed == 0 {
				// Unix 控制服务先于捕获线程启动；已装载规则不能证明网卡正在收包。
				actual, err := socketCommand(ready, c.SuricataSocket, "dump-counters", nil)
				if err != nil || !captureHasStarted(actual) {
					if !pause(ready, 100*time.Millisecond) {
						break
					}
					continue
				}
				s.mu.Lock()
				s.state.Status, s.state.ErrorCode, s.state.AppliedRevision = "running", "", revision
				s.state.AppliedSettings = &settings
				s.state.ObservedAt = time.Now().UTC()
				s.state.Counters, _ = captureCounters(actual)
				observed := s.state.ObservedAt
				s.state.CountersObservedAt = &observed
				s.mu.Unlock()
				return nil
			}
		}
		if !pause(ready, 100*time.Millisecond) {
			break
		}
	}
	return errors.New("检测引擎采集启动超时")
}

// Linux 的父线程退出信号绑定到执行 fork 的线程；该线程保持到子进程回收。
func startCaptureProcess(command *exec.Cmd, done chan struct{}) error {
	started := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		err := command.Start()
		started <- err
		if err == nil {
			_ = command.Wait()
		}
		close(done)
	}()
	return <-started
}

func captureHasStarted(raw json.RawMessage) bool {
	var counters struct {
		Capture struct {
			AFPacket struct {
				Polls uint64 `json:"polls"`
			} `json:"afpacket"`
		} `json:"capture"`
	}
	return json.Unmarshal(raw, &counters) == nil && counters.Capture.AFPacket.Polls > 0
}

func (s *CaptureSupervisor) Check(ctx context.Context) error {
	s.mu.RLock()
	process := s.active
	s.mu.RUnlock()
	if process == nil || ctx.Err() != nil {
		return errors.New("托管检测引擎未运行")
	}
	select {
	case <-process.done:
		return errors.New("托管检测引擎已退出")
	default:
	}
	pid, err := readRegularBounded(s.Engine.Config.SuricataPIDFile, 32, true)
	if err != nil || strings.TrimSpace(string(pid)) != strconv.Itoa(process.command.Process.Pid) {
		return errors.New("托管检测引擎 PID 与启动记录不一致")
	}
	sha, err := ruleFileDigest(s.Engine.Config.SuricataConfig, 1024*1024)
	if err != nil || sha != process.sha {
		return errors.New("检测配置与实际进程的启动记录不一致")
	}
	for name, expected := range process.aux {
		actual, err := ruleFileDigest(filepath.Join(s.root, name), 1024*1024)
		if err != nil || actual != expected {
			return errors.New("检测辅助文件与进程启动记录不一致")
		}
	}
	return nil
}

func (s *CaptureSupervisor) stop(ctx context.Context) {
	s.mu.Lock()
	process := s.active
	s.active = nil
	s.state.PID, s.state.AppliedSettings = 0, nil
	s.mu.Unlock()
	if process == nil {
		return
	}
	_ = process.command.Process.Signal(syscall.SIGTERM)
	call, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	select {
	case <-process.done:
	case <-call.Done():
		_ = process.command.Process.Kill()
		<-process.done
	}
	_ = os.Remove(s.Engine.Config.SuricataPIDFile)
	_ = os.Remove(s.Engine.Config.SuricataSocket)
}

func (s *CaptureSupervisor) failure(code string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Status = "failed"
	if s.active != nil {
		s.state.Status = "degraded"
	}
	s.state.ErrorCode, s.state.ObservedAt = code, time.Now().UTC()
	s.retry = time.Now().Add(30 * time.Second)
}

func (s *CaptureSupervisor) Run(ctx context.Context) error {
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
			if !s.op.TryLock() {
				continue
			}
			if err := s.rotate(ctx); err != nil {
				slog.Error("EVE 轮转无法确认，检测引擎已停止", "error", err)
				s.stop(ctx)
				s.failure("capture_rotation_unavailable")
			}
			if s.active != nil && !s.withinSpoolBudget() {
				s.stop(ctx)
				s.failure("capture_spool_full")
			} else if s.active != nil && s.Check(ctx) != nil {
				select {
				case <-s.active.done:
					s.stop(ctx)
				default:
				}
				s.failure("capture_process_or_configuration_changed")
				// 不能自动覆盖运维修改的配置或 PID，保留现场直到明确应用配置。
			} else if s.Snapshot().Status == "pending" || (s.Snapshot().Status == "failed" && time.Now().After(s.retry)) {
				s.apply(ctx)
			}
			if s.Ready() {
				call, cancel := context.WithTimeout(ctx, time.Second)
				raw, err := socketCommand(call, s.Engine.Config.SuricataSocket, "dump-counters", nil)
				cancel()
				counters, valid := captureCounters(raw)
				if err == nil && valid {
					s.mu.Lock()
					s.state.Counters, s.state.ObservedAt = counters, time.Now().UTC()
					observed := s.state.ObservedAt
					s.state.CountersObservedAt = &observed
					s.mu.Unlock()
				}
			}
			s.op.Unlock()
		}
	}
}

// Suricata 8 的总计数使用嵌套对象。只保留实际出现的 uint64，不把线程计数或缺测补成零。
func captureCounters(raw json.RawMessage) (map[string]string, bool) {
	return detectionquality.Extract(raw)
}

func (s *CaptureSupervisor) Close(ctx context.Context) {
	s.op.Lock()
	defer s.op.Unlock()
	s.stop(ctx)
}

func (s *CaptureSupervisor) withinSpoolBudget() bool {
	budget := s.Engine.Config.CaptureSpoolBytes
	if budget == 0 {
		budget = 1024 * 1024 * 1024
	}
	used, err := s.spoolUsage()
	s.mu.Lock()
	s.state.SpoolBudget = strconv.FormatInt(budget, 10)
	if err == nil {
		s.state.SpoolBytes = strconv.FormatInt(used, 10)
	} else {
		s.state.SpoolBytes = ""
	}
	s.mu.Unlock()
	return err == nil && used < budget
}
