package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	sensorv1 "github.com/kkx600/StarBeacon/api/sensor/v1"
	"github.com/kkx600/StarBeacon/internal/config"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/shirou/gopsutil/v4/process"
	"golang.org/x/sys/unix"
)

type Engine struct {
	Config             config.Config
	Capture            *CaptureSupervisor
	WAL                *WAL
	Response           *ResponseService
	LocalReplay        *ReplayService
	ReplayClient       sensorv1.SensorServiceClient
	isolationOnce      sync.Once
	isolationAvailable bool
	ruleApplyMu        sync.Mutex
}
type boundedLog struct {
	data      []byte
	truncated bool
}

func (b *boundedLog) Write(p []byte) (int, error) {
	n := len(p)
	remaining := 32*1024 - len(b.data)
	if remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
		}
		b.data = append(b.data, p...)
	}
	if n > remaining {
		b.truncated = true
	}
	return n, nil
}
func (e *Engine) Capabilities() []string {
	out := []string{"diagnostics"}
	if e.Response != nil {
		out = append(out, "response.block", "response.read", "response.revoke")
	}
	if e.Capture != nil {
		out = append(out, "capture.configure")
	}
	if e.ReplayAvailable() {
		out = append(out, "rules.validate")
		if e.ReplayAvailable() {
			out = append(out, "rules.replay")
		}
		if e.Config.AllowRuleApply && e.Config.SuricataSocket != "" && e.Config.SuricataRulesPath != "" && e.Config.SuricataPIDFile != "" && (e.Capture == nil || e.Capture.Ready()) {
			out = append(out, "rules.apply", "rules.reconcile")
		}
	}
	return out
}
func (e *Engine) Execute(ctx context.Context, c control.Command) (json.RawMessage, string, error) {
	if strings.HasPrefix(c.Kind, "response.") {
		if e.Response == nil {
			return nil, "response_device_unavailable", errors.New("采集器未配置联动设备")
		}
		return e.Response.Execute(ctx, c)
	}
	if c.Kind == "capture.configure" {
		if e.Capture == nil {
			return nil, "capture_not_managed", errors.New("设备未启用托管采集")
		}
		if !contract.ValidID(c.ID) {
			return nil, "invalid_task", errors.New("采集任务身份无效")
		}
		p, err := control.ReadCaptureConfiguration(c.Payload)
		if err != nil {
			return nil, "invalid_capture_configuration", err
		}
		state, code, err := e.Capture.ConfigureRemote(ctx, p, c.ID)
		if err != nil && state.Managed == false {
			return nil, code, err
		}
		raw, marshalErr := json.Marshal(state)
		if marshalErr != nil {
			return nil, "invalid_execution_result", marshalErr
		}
		return raw, code, err
	}
	if c.Kind == "rules.reconcile" {
		return e.reconcile(ctx, c)
	}
	if c.Kind == "rules.replay" {
		return e.Replay(ctx, c)
	}
	if c.Kind == "diagnostics" {
		v, err := json.Marshal(e.WAL.Health(ctx, e.Config.StatePath))
		return v, "", err
	}
	if c.Kind != "rules.validate" && c.Kind != "rules.apply" {
		return nil, "unsupported_task", errors.New("设备不接受该任务类型")
	}
	if c.Kind == "rules.apply" {
		if !contract.ValidID(c.ID) {
			return nil, "invalid_task", errors.New("规则安装任务身份无效")
		}
		if !e.Config.AllowRuleApply || e.Config.SuricataSocket == "" || e.Config.SuricataRulesPath == "" || e.Config.SuricataPIDFile == "" {
			return nil, "rule_apply_not_authorized", errors.New("设备未授权规则安装")
		}
		if !e.ruleApplyMu.TryLock() {
			return nil, "rule_operation_in_progress", errors.New("规则安装或恢复正在执行")
		}
		defer e.ruleApplyMu.Unlock()
		if _, err := os.Lstat(e.ruleJournalPath()); err == nil {
			return nil, "result_unknown", errors.New("规则恢复记录尚未核对，禁止覆盖恢复依据")
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, "local_storage_unavailable", errors.New("无法核对规则恢复记录")
		}
	}
	if e.Config.SuricataBinary == "" || e.Config.SuricataConfig == "" {
		return nil, "engine_not_configured", errors.New("检测引擎未配置")
	}
	var p control.RulePackage
	decoder := json.NewDecoder(bytes.NewReader(c.Payload))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&p) != nil || decoder.Decode(new(any)) != io.EOF || !contract.ValidID(p.PackageID) || p.Revision < 1 || p.EngineVersion != "8.0.7" || p.SHA256 != control.Digest([]byte(p.Text)) {
		return nil, "invalid_package", errors.New("规则包身份、版本或摘要无效")
	}
	if err := store.ValidateRules(p.Text); err != nil {
		return nil, "invalid_package", err
	}
	if c.Kind == "rules.apply" {
		if err := p.Authorization.Validate(); err != nil {
			return nil, "release_validation_required", err
		}
	} else if p.Authorization != nil {
		return nil, "invalid_package", errors.New("装载检查不接受发布授权")
	}
	if !e.ReplayAvailable() {
		return nil, "engine_isolation_unavailable", errors.New("检测引擎隔离环境不可用")
	}
	build, err := exec.CommandContext(ctx, e.Config.SuricataBinary, "-V").Output()
	if err != nil || !engineVersion.Match(build) {
		return nil, "engine_version_mismatch", errors.New("检测引擎版本与规则包不匹配")
	}
	dir, err := os.MkdirTemp(filepath.Dir(e.Config.StatePath), "rule-test-")
	if err != nil {
		return nil, "local_storage_unavailable", err
	}
	defer os.RemoveAll(dir)
	dir, err = filepath.EvalSymlinks(dir)
	if err != nil {
		return nil, "local_storage_unavailable", err
	}
	input, output := filepath.Join(dir, "input"), filepath.Join(dir, "output")
	for _, path := range []string{input, output} {
		if err = os.Mkdir(path, 0700); err != nil {
			return nil, "local_storage_unavailable", err
		}
	}
	candidate := filepath.Join(input, "candidate.rules")
	if err = durableFile(candidate, []byte(p.Text)); err != nil {
		return nil, "local_storage_unavailable", err
	}
	configSHA, profile, err := offlineConfig(e.Config.SuricataConfig, input)
	if err != nil {
		return nil, "engine_not_configured", err
	}
	args := []string{"-T", "-c", filepath.Join(input, "suricata.yaml"), "--include", filepath.Join(input, "replay.yaml"), "-S", candidate, "--init-errors-fatal", "--strict-rule-keywords=all", "-l", output}
	log, duration, limit, err := executeBounded(ctx, e.Config.SuricataBinary, dir, input, output, args)
	if err != nil {
		raw, _ := json.Marshal(map[string]any{"log": string(log.data), "log_truncated": log.truncated, "resource_limit": limit, "duration_ms": duration})
		code := "engine_validation_failed"
		if limit != "" {
			code = "engine_resource_limit"
		}
		if limit == "isolation" {
			code = "engine_isolation_unavailable"
		}
		return raw, code, err
	}
	validation := map[string]any{"engine_version": "8.0.7", "package_id": p.PackageID, "revision": p.Revision, "sha256": p.SHA256, "syntax": "passed", "replay": "not_run", "config_sha256": configSHA, "profile_sha256": control.Digest([]byte(profile)), "duration_ms": duration, "log": string(log.data), "log_truncated": log.truncated}
	if c.Kind == "rules.validate" {
		raw, _ := json.Marshal(validation)
		return raw, "", nil
	}
	if p.Authorization.ConfigSHA256 != configSHA || p.Authorization.ProfileSHA256 != control.Digest([]byte(profile)) {
		return nil, "release_configuration_changed", errors.New("检测配置与已核对的发布证据不一致，请重新检查和重放")
	}
	if err = e.ensureManagedPath(ctx); err != nil {
		return nil, "managed_rules_mismatch", err
	}
	previous, err := readRegularBounded(e.Config.SuricataRulesPath, 900*1024, false)
	if err != nil || store.ValidateRules(string(previous)) != nil {
		return nil, "managed_rules_unavailable", errors.New("现有规则包超出回滚边界")
	}
	if control.Digest(previous) != p.Authorization.ExpectedRulesSHA256 {
		return nil, "active_rules_changed", errors.New("当前规则与发布预期不一致，禁止覆盖其他发布或运维写入")
	}
	journal := e.ruleJournalPath()
	raw, _ := json.Marshal(ruleTransaction{TaskID: c.ID, Path: e.Config.SuricataRulesPath, Previous: previous, TargetSHA256: p.SHA256})
	if err = durableFile(journal, raw); err != nil {
		return nil, "local_storage_unavailable", err
	}
	if err = durableFile(e.Config.SuricataRulesPath, []byte(p.Text)); err != nil {
		return nil, "rule_install_failed", err
	}
	stats, err := e.reloadAndRead(ctx, ruleCount(p.Text))
	if err != nil {
		// 恢复独立于调用期限，失败时保留恢复 journal，不能报告已回滚。
		rollback, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		if durableFile(e.Config.SuricataRulesPath, previous) != nil {
			return nil, "result_unknown", err
		}
		if _, restoreErr := e.reloadAndRead(rollback, ruleCount(string(previous))); restoreErr != nil {
			return nil, "result_unknown", restoreErr
		}
		if removeErr := removeDurable(journal); removeErr != nil {
			return nil, "result_unknown", removeErr
		}
		return nil, "rule_reload_failed_rolled_back", err
	}
	installed, err := readRegularBounded(e.Config.SuricataRulesPath, 900*1024, false)
	if err != nil || control.Digest(installed) != p.SHA256 {
		return nil, "result_unknown", errors.New("规则安装回读不一致")
	}
	validation["active_sha256"] = p.SHA256
	validation["previous_sha256"] = p.Authorization.ExpectedRulesSHA256
	validation["authorization"] = p.Authorization
	validation["engine_ruleset"] = json.RawMessage(stats)
	validation["applied_at"] = time.Now().UTC()
	if err = removeDurable(journal); err != nil {
		return nil, "result_unknown", err
	}
	result, _ := json.Marshal(validation)
	return result, "", nil
}
func durableFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, e := os.CreateTemp(dir, ".starbeacon-")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(data)
	}
	if e == nil {
		e = f.Sync()
	}
	closed := f.Close()
	if e != nil {
		return e
	}
	if closed != nil {
		return closed
	}
	if e = os.Rename(name, path); e != nil {
		return e
	}
	d, e := os.Open(dir)
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
func removeDurable(path string) error {
	if e := os.Remove(path); e != nil {
		return e
	}
	d, e := os.Open(filepath.Dir(path))
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
func socketCommand(ctx context.Context, path, command string, args map[string]any) (json.RawMessage, error) {
	conn, e := (&net.Dialer{}).DialContext(ctx, "unix", path)
	if e != nil {
		return nil, e
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	deadline := time.Now().Add(30 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if e = conn.SetDeadline(deadline); e != nil {
		return nil, e
	}
	enc := json.NewEncoder(conn)
	dec := json.NewDecoder(io.LimitReader(conn, 256*1024))
	if e = enc.Encode(map[string]string{"version": "0.2"}); e != nil {
		return nil, e
	}
	var response struct {
		Return  string          `json:"return"`
		Message json.RawMessage `json:"message"`
	}
	if e = dec.Decode(&response); e != nil || response.Return != "OK" {
		return nil, errors.New("检测引擎控制协议不匹配")
	}
	if e = enc.Encode(map[string]any{"command": command, "arguments": args}); e != nil {
		return nil, e
	}
	response.Return = ""
	response.Message = nil
	if e = dec.Decode(&response); e != nil {
		return nil, e
	}
	if response.Return != "OK" {
		return nil, &socketRejection{Command: command, Message: response.Message}
	}
	return response.Message, nil
}
func (e *Engine) ensureManagedPath(ctx context.Context) error {
	if err := e.ensureManagedProcess(ctx); err != nil {
		return err
	}
	raw, err := socketCommand(ctx, e.Config.SuricataSocket, "conf-get", map[string]any{"variable": "default-rule-path"})
	if err != nil {
		return err
	}
	var root string
	if err = json.Unmarshal(raw, &root); err != nil {
		return err
	}
	raw, err = socketCommand(ctx, e.Config.SuricataSocket, "conf-get", map[string]any{"variable": "rule-files.0"})
	if err != nil {
		return err
	}
	var name string
	if err = json.Unmarshal(raw, &name); err != nil {
		return err
	}
	actual := name
	if !filepath.IsAbs(actual) {
		actual = filepath.Join(root, name)
	}
	if filepath.Clean(actual) != filepath.Clean(e.Config.SuricataRulesPath) {
		return errors.New("运行引擎不使用登记的规则文件")
	}
	// 一个发布写入者只管理这一份完整规则包，禁止覆盖未知来源的合并结果。
	if _, err = socketCommand(ctx, e.Config.SuricataSocket, "conf-get", map[string]any{"variable": "rule-files.1"}); err == nil {
		return errors.New("检测引擎仍引用其他规则包")
	} else {
		var rejected *socketRejection
		var message string
		if !errors.As(err, &rejected) || json.Unmarshal(rejected.Message, &message) != nil || message != "Unable to get value" {
			return errors.New("无法核实检测引擎完整规则来源")
		}
	}

	return nil
}

func (e *Engine) ensureManagedProcess(ctx context.Context) error {
	if e.Capture != nil {
		if err := e.Capture.Check(ctx); err != nil {
			return err
		}
	}
	info, err := os.Lstat(e.Config.SuricataPIDFile)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 32 || info.Mode().Perm()&0022 != 0 {
		return errors.New("检测引擎 PID 文件不可信")
	}
	raw, err := os.ReadFile(e.Config.SuricataPIDFile)
	if err != nil {
		return err
	}
	pid, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 32)
	if err != nil || pid < 1 {
		return errors.New("检测引擎 PID 无效")
	}
	p, err := process.NewProcessWithContext(ctx, int32(pid))
	if err != nil {
		return err
	}
	path, err := p.ExeWithContext(ctx)
	if err != nil {
		return err
	}
	expected, err := filepath.EvalSymlinks(e.Config.SuricataBinary)
	if err != nil {
		return err
	}
	path, err = filepath.EvalSymlinks(path)
	if err != nil || path != expected {
		return errors.New("运行进程不属于登记的检测引擎")
	}
	argv, err := p.CmdlineSliceWithContext(ctx)
	if err != nil {
		return err
	}
	configured := false
	for i, arg := range argv {
		if i == 0 {
			continue
		}
		if strings.HasPrefix(arg, "-S") || strings.HasPrefix(arg, "-s") || strings.HasPrefix(arg, "--include") || strings.HasPrefix(arg, "--set") {
			return errors.New("运行引擎存在规则来源或配置覆盖参数")
		}
		if arg == "-c" && i+1 < len(argv) {
			actual, err := filepath.EvalSymlinks(argv[i+1])
			if err != nil {
				return err
			}
			configPath, err := filepath.EvalSymlinks(e.Config.SuricataConfig)
			if err != nil || actual != configPath {
				return errors.New("运行引擎配置路径不匹配")
			}
			configured = true
		}
	}
	if !configured {
		return errors.New("运行引擎未使用明确登记的配置")
	}
	return nil
}
func (e *Engine) reloadAndRead(ctx context.Context, expected ...int) (json.RawMessage, error) {
	if _, err := socketCommand(ctx, e.Config.SuricataSocket, "ruleset-reload-rules", nil); err != nil {
		return nil, err
	}
	stats, err := socketCommand(ctx, e.Config.SuricataSocket, "ruleset-stats", nil)
	if err != nil {
		return nil, err
	}
	var values []struct {
		Loaded int `json:"rules_loaded"`
		Failed int `json:"rules_failed"`
	}
	if err = json.Unmarshal(stats, &values); err != nil || len(values) == 0 {
		return nil, errors.New("检测引擎规则回读格式不符")
	}
	for _, v := range values {
		if v.Failed != 0 || v.Loaded < 1 {
			return nil, errors.New("检测引擎规则装载不完整")
		}
	}
	if len(expected) > 0 && (len(values) != 1 || values[0].Loaded != expected[0]) {
		return nil, errors.New("运行引擎装载数量与完整规则包不一致")
	}
	return stats, nil
}

func ruleCount(text string) int {
	count := 0
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			count++
		}
	}
	return count
}
func (e *Engine) Recover(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !e.ruleApplyMu.TryLock() {
		return errors.New("规则安装或恢复正在执行")
	}
	defer e.ruleApplyMu.Unlock()
	path := e.ruleJournalPath()
	// 恢复材料不能是链接、无限输入或其他本地账号可写的文件。
	raw, err := readRegularBounded(path, 900*1024*4/3+8192, true)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var v ruleTransaction
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&v) != nil || decoder.Decode(new(any)) != io.EOF || !contract.ValidID(v.TaskID) || !ruleDigest.MatchString(v.TargetSHA256) || store.ValidateRules(string(v.Previous)) != nil {
		return errors.New("规则恢复记录损坏，需要人工核对")
	}
	if v.Path != e.Config.SuricataRulesPath || !e.Config.AllowRuleApply || e.Config.SuricataRulesPath == "" || e.Config.SuricataSocket == "" || e.Config.SuricataPIDFile == "" {
		return errors.New("恢复规则任务需要原设备授权与路径")
	}
	current, err := readRegularBounded(v.Path, 900*1024, false)
	if err != nil {
		return err
	}
	currentSHA, previousSHA := control.Digest(current), control.Digest(v.Previous)
	if currentSHA != v.TargetSHA256 && currentSHA != previousSHA {
		return errors.New("规则文件不属于恢复事务，禁止覆盖其他写入者的内容")
	}
	// 必须先确认实际进程、配置和完整规则来源，再进行任何规则写入。
	if err = e.ensureManagedPath(ctx); err != nil {
		return err
	}
	previous := control.RulePackage{PackageID: "recovery", Revision: 1, EngineVersion: "8.0.7", Text: string(v.Previous), SHA256: previousSHA}
	payload, err := json.Marshal(previous)
	if err != nil {
		return err
	}
	if _, _, err = e.Execute(ctx, control.Command{Kind: "rules.validate", Payload: payload}); err != nil {
		return errors.New("历史规则未通过隔离装载检查，恢复记录仍保留")
	}
	// 原生校验期间文件可能被外部运维改写，恢复不能覆盖这一变化。
	checked, err := readRegularBounded(v.Path, 900*1024, false)
	if err != nil || control.Digest(checked) != currentSHA {
		return errors.New("恢复期间规则文件发生变化，需要人工核对")
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = e.ensureManagedPath(ctx); err != nil {
		return err
	}
	if currentSHA != previousSHA {
		if err = durableFile(v.Path, v.Previous); err != nil {
			return err
		}
	}
	if _, err = e.reloadAndRead(ctx, ruleCount(string(v.Previous))); err != nil {
		return err
	}
	installed, err := readRegularBounded(v.Path, 900*1024, false)
	if err != nil || control.Digest(installed) != previousSHA {
		return errors.New("规则恢复回读不一致，恢复记录仍保留")
	}
	return removeDurable(path)
}

type ruleTransaction struct {
	TaskID       string `json:"task_id"`
	Path         string `json:"path"`
	Previous     []byte `json:"previous"`
	TargetSHA256 string `json:"target_sha256"`
}

func (e *Engine) ruleJournalPath() string {
	return filepath.Join(filepath.Dir(e.Config.StatePath), "rule-transaction.json")
}

// 心跳采用有界流式摘要，避免每次分配整份规则包；文件摘要不等同运行引擎已生效的回执。
func ruleFileDigest(path string, limit int64) (string, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() > limit {
		return "", errors.New("登记规则文件不可读取")
	}
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return "", err
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) || after.Size() > limit {
		return "", errors.New("登记规则文件身份发生变化")
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(f, limit+1))
	if err != nil || n > limit {
		return "", errors.New("登记规则文件读取失败或超过额度")
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// 同时核对路径和已打开文件的身份，避免读到链接替换、特殊文件或超出预算的数据。
func readRegularBounded(path string, limit int64, private bool) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Size() > limit || (private && before.Mode().Perm()&0077 != 0) {
		return nil, errors.New("规则文件类型、权限或大小不可信")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || !after.Mode().IsRegular() || (private && after.Mode().Perm()&0077 != 0) {
		return nil, errors.New("规则文件读取期间身份发生变化")
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, errors.New("规则文件超过读取预算")
	}
	return raw, nil
}

var engineVersion = regexp.MustCompile(`(?:^|[ \t])8\.0\.7(?:[ \t\r\n]|$)`)
var ruleDigest = regexp.MustCompile(`^[a-f0-9]{64}$`)

type socketRejection struct {
	Command string
	Message json.RawMessage
}

func (e *socketRejection) Error() string {
	return fmt.Sprintf("检测引擎拒绝命令 %s", e.Command)
}
