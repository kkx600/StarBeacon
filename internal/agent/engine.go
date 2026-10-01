package agent

import (
	"context"
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
	"time"

	sensorv1 "github.com/kkx600/StarBeacon/api/sensor/v1"
	"github.com/kkx600/StarBeacon/internal/config"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/shirou/gopsutil/v4/process"
)

type Engine struct {
	Config       config.Config
	WAL          *WAL
	LocalReplay  *ReplayService
	ReplayClient sensorv1.SensorServiceClient
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
	if e.Config.SuricataBinary != "" && e.Config.SuricataConfig != "" {
		out = append(out, "rules.validate")
		if e.ReplayAvailable() {
			out = append(out, "rules.replay")
		}
		if e.Config.AllowRuleApply && e.Config.SuricataSocket != "" && e.Config.SuricataRulesPath != "" && e.Config.SuricataPIDFile != "" {
			out = append(out, "rules.apply")
		}
	}
	return out
}
func (e *Engine) Execute(ctx context.Context, c control.Command) (json.RawMessage, string, error) {
	if c.Kind == "rules.replay" {
		return e.Replay(ctx, c)
	}
	if c.Kind == "diagnostics" {
		v, err := json.Marshal(e.WAL.Health(ctx, e.Config.StatePath))
		return v, "", err
	}
	if e.Config.SuricataBinary == "" || e.Config.SuricataConfig == "" {
		return nil, "engine_not_configured", errors.New("检测引擎未配置")
	}
	var p control.RulePackage
	if err := json.Unmarshal(c.Payload, &p); err != nil {
		return nil, "invalid_package", err
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
	candidate := filepath.Join(dir, "candidate.rules")
	if err = durableFile(candidate, []byte(p.Text)); err != nil {
		return nil, "local_storage_unavailable", err
	}
	var log boundedLog
	cmd := exec.CommandContext(ctx, e.Config.SuricataBinary, "-T", "-c", e.Config.SuricataConfig, "-S", candidate, "--init-errors-fatal", "--strict-rule-keywords=all", "-l", dir)
	cmd.Stdout = &log
	cmd.Stderr = &log
	if err = cmd.Run(); err != nil {
		raw, _ := json.Marshal(map[string]any{"log": string(log.data), "log_truncated": log.truncated})
		return raw, "engine_validation_failed", err
	}
	validation := map[string]any{"engine_version": "8.0.7", "package_id": p.PackageID, "revision": p.Revision, "sha256": p.SHA256, "syntax": "passed", "replay": "not_run", "log": string(log.data), "log_truncated": log.truncated}
	if c.Kind == "rules.validate" {
		raw, _ := json.Marshal(validation)
		return raw, "", nil
	}
	if !e.Config.AllowRuleApply || e.Config.SuricataSocket == "" || e.Config.SuricataRulesPath == "" {
		return nil, "rule_apply_not_authorized", errors.New("设备未授权规则安装")
	}
	if err = e.ensureManagedPath(ctx); err != nil {
		return nil, "managed_rules_mismatch", err
	}
	info, err := os.Lstat(e.Config.SuricataRulesPath)
	if err != nil || !info.Mode().IsRegular() {
		return nil, "managed_rules_unavailable", errors.New("规则文件必须是现有普通文件")
	}
	previous, err := os.ReadFile(e.Config.SuricataRulesPath)
	if err != nil || len(previous) > 900*1024 {
		return nil, "managed_rules_unavailable", errors.New("现有规则包超出回滚边界")
	}
	journal := filepath.Join(filepath.Dir(e.Config.StatePath), "rule-transaction.json")
	raw, _ := json.Marshal(map[string]any{"task_id": c.ID, "path": e.Config.SuricataRulesPath, "previous": previous, "target_sha256": p.SHA256})
	if err = durableFile(journal, raw); err != nil {
		return nil, "local_storage_unavailable", err
	}
	if err = durableFile(e.Config.SuricataRulesPath, []byte(p.Text)); err != nil {
		return nil, "rule_install_failed", err
	}
	stats, err := e.reloadAndRead(ctx)
	if err != nil {
		// 恢复独立于调用期限，失败时保留恢复 journal，不能报告已回滚。
		rollback, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		if durableFile(e.Config.SuricataRulesPath, previous) != nil {
			return nil, "result_unknown", err
		}
		if _, restoreErr := e.reloadAndRead(rollback); restoreErr != nil {
			return nil, "result_unknown", restoreErr
		}
		if removeErr := removeDurable(journal); removeErr != nil {
			return nil, "result_unknown", removeErr
		}
		return nil, "rule_reload_failed_rolled_back", err
	}
	installed, err := os.ReadFile(e.Config.SuricataRulesPath)
	if err != nil || control.Digest(installed) != p.SHA256 {
		return nil, "result_unknown", errors.New("规则安装回读不一致")
	}
	validation["active_sha256"] = p.SHA256
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
		if strings.HasPrefix(arg, "-S") || arg == "-s" || strings.HasPrefix(arg, "-s=") || strings.HasPrefix(arg, "--include") || strings.HasPrefix(arg, "--set") {
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
func (e *Engine) reloadAndRead(ctx context.Context) (json.RawMessage, error) {
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
	return stats, nil
}
func (e *Engine) Recover(ctx context.Context) error {
	path := filepath.Join(filepath.Dir(e.Config.StatePath), "rule-transaction.json")
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var v struct {
		Path     string `json:"path"`
		Previous []byte `json:"previous"`
	}
	if err = json.Unmarshal(raw, &v); err != nil {
		return err
	}
	if v.Path != e.Config.SuricataRulesPath || !e.Config.AllowRuleApply {
		return errors.New("恢复规则任务需要原设备授权与路径")
	}
	if err = durableFile(v.Path, v.Previous); err != nil {
		return err
	}
	if _, err = e.reloadAndRead(ctx); err != nil {
		return err
	}
	return removeDurable(path)
}

var engineVersion = regexp.MustCompile(`(?:^|[ \t])8\.0\.7(?:[ \t\r\n]|$)`)

type socketRejection struct {
	Command string
	Message json.RawMessage
}

func (e *socketRejection) Error() string {
	return fmt.Sprintf("检测引擎拒绝命令 %s", e.Command)
}
