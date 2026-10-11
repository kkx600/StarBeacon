package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/config"
	"github.com/kkx600/StarBeacon/internal/control"
)

const recoveryPrevious = `alert tcp any any -> any any (msg:"StarBeacon recovery previous"; sid:1000001; rev:1;)`
const recoveryTarget = `alert tcp any any -> any any (msg:"StarBeacon recovery target"; sid:1000002; rev:1;)`

func recoveryFixture(t *testing.T) (*Engine, ruleTransaction) {
	t.Helper()
	dir := t.TempDir()
	e := &Engine{Config: config.Config{
		Mode: "development", StatePath: filepath.Join(dir, "state.db"),
		AllowRuleApply: true, SuricataRulesPath: filepath.Join(dir, "active.rules"),
		SuricataSocket: filepath.Join(dir, "suricata.sock"), SuricataPIDFile: filepath.Join(dir, "suricata.pid"),
	}}
	if err := os.WriteFile(e.Config.SuricataRulesPath, []byte(recoveryTarget), 0600); err != nil {
		t.Fatal(err)
	}
	v := ruleTransaction{TaskID: "task_recovery", Path: e.Config.SuricataRulesPath, Previous: []byte(recoveryPrevious), TargetSHA256: control.Digest([]byte(recoveryTarget))}
	return e, v
}

func saveRecoveryFixture(t *testing.T, e *Engine, v ruleTransaction) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(e.ruleJournalPath(), raw, 0600); err != nil {
		t.Fatal(err)
	}
	return raw
}

// 任何恢复资格错误都必须在规则写入之前失败，并保留原始材料供运维核对。
func TestRuleRecoveryRejectsDamagedMaterialAndForeignState(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*testing.T, *Engine, *ruleTransaction, *[]byte)
	}{
		{"损坏JSON", func(t *testing.T, e *Engine, v *ruleTransaction, raw *[]byte) { *raw = []byte(`{"path":`) }},
		{"未知字段", func(t *testing.T, e *Engine, v *ruleTransaction, raw *[]byte) {
			*raw = append((*raw)[:len(*raw)-1], []byte(`,"unexpected":true}`)...)
		}},
		{"尾随对象", func(t *testing.T, e *Engine, v *ruleTransaction, raw *[]byte) { *raw = append(*raw, []byte(` {}`)...) }},
		{"任务身份缺失", func(t *testing.T, e *Engine, v *ruleTransaction, raw *[]byte) {
			v.TaskID = ""
			*raw, _ = json.Marshal(v)
		}},
		{"目标摘要损坏", func(t *testing.T, e *Engine, v *ruleTransaction, raw *[]byte) {
			v.TargetSHA256 = "not-a-digest"
			*raw, _ = json.Marshal(v)
		}},
		{"空历史内容", func(t *testing.T, e *Engine, v *ruleTransaction, raw *[]byte) {
			v.Previous = nil
			*raw, _ = json.Marshal(v)
		}},
		{"越权规则动作", func(t *testing.T, e *Engine, v *ruleTransaction, raw *[]byte) {
			v.Previous = []byte(strings.Replace(recoveryPrevious, "alert ", "drop ", 1))
			*raw, _ = json.Marshal(v)
		}},
		{"特殊执行关键词", func(t *testing.T, e *Engine, v *ruleTransaction, raw *[]byte) {
			v.Previous = []byte(strings.Replace(recoveryPrevious, "sid:", "lua:script; sid:", 1))
			*raw, _ = json.Marshal(v)
		}},
		{"历史内容超限", func(t *testing.T, e *Engine, v *ruleTransaction, raw *[]byte) {
			v.Previous = []byte(strings.Repeat("#", 900*1024+1))
			*raw, _ = json.Marshal(v)
		}},
		{"恢复输入超限", func(t *testing.T, e *Engine, v *ruleTransaction, raw *[]byte) {
			*raw = []byte(strings.Repeat(" ", 900*1024*4/3+8193))
		}},
		{"取消授权", func(t *testing.T, e *Engine, v *ruleTransaction, raw *[]byte) { e.Config.AllowRuleApply = false }},
		{"路径不匹配", func(t *testing.T, e *Engine, v *ruleTransaction, raw *[]byte) {
			v.Path = filepath.Join(t.TempDir(), "another.rules")
			*raw, _ = json.Marshal(v)
		}},
		{"套接字未登记", func(t *testing.T, e *Engine, v *ruleTransaction, raw *[]byte) { e.Config.SuricataSocket = "" }},
		{"进程文件未登记", func(t *testing.T, e *Engine, v *ruleTransaction, raw *[]byte) { e.Config.SuricataPIDFile = "" }},
		{"规则文件未登记", func(t *testing.T, e *Engine, v *ruleTransaction, raw *[]byte) { e.Config.SuricataRulesPath = "" }},
		{"其他写入者内容", func(t *testing.T, e *Engine, v *ruleTransaction, raw *[]byte) {
			if err := os.WriteFile(e.Config.SuricataRulesPath, []byte("其他运维写入的规则"), 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{"PID文件缺失", func(t *testing.T, e *Engine, v *ruleTransaction, raw *[]byte) {}},
		{"PID文件可被其他账号写入", func(t *testing.T, e *Engine, v *ruleTransaction, raw *[]byte) {
			if err := os.WriteFile(e.Config.SuricataPIDFile, []byte("1"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(e.Config.SuricataPIDFile, 0666); err != nil {
				t.Fatal(err)
			}
		}},
		{"PID内容不是数字", func(t *testing.T, e *Engine, v *ruleTransaction, raw *[]byte) {
			if err := os.WriteFile(e.Config.SuricataPIDFile, []byte("invalid"), 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{"恢复文件可被其他账号读取", func(t *testing.T, e *Engine, v *ruleTransaction, raw *[]byte) {
			if err := os.Chmod(e.ruleJournalPath(), 0644); err != nil {
				t.Fatal(err)
			}
		}},
		{"进程不属于检测引擎", func(t *testing.T, e *Engine, v *ruleTransaction, raw *[]byte) {
			e.Config.SuricataBinary = filepath.Join(t.TempDir(), "missing-suricata")
			if err := os.WriteFile(e.Config.SuricataPIDFile, []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, v := recoveryFixture(t)
			raw := saveRecoveryFixture(t, e, v)
			tc.mutate(t, e, &v, &raw)
			if err := os.WriteFile(e.ruleJournalPath(), raw, 0); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(v.Path)
			// 路径损坏时核对实际登记目标，而不是不可信记录中的路径。
			if tc.name == "路径不匹配" || tc.name == "规则文件未登记" {
				before, err = os.ReadFile(filepath.Join(filepath.Dir(e.Config.StatePath), "active.rules"))
			}
			if err != nil {
				t.Fatal(err)
			}
			ctx, stop := context.WithTimeout(context.Background(), 3*time.Second)
			defer stop()
			if err := e.Recover(ctx); err == nil {
				t.Fatal("不可信恢复材料没有被拒绝")
			}
			after, err := os.ReadFile(filepath.Join(filepath.Dir(e.Config.StatePath), "active.rules"))
			if err != nil || string(after) != string(before) {
				t.Fatal("资格核对失败之前改写了规则", err)
			}
			retained, err := os.ReadFile(e.ruleJournalPath())
			if err != nil || string(retained) != string(raw) {
				t.Fatal("拒绝后没有保留原始恢复依据", err)
			}
		})
	}
}

func TestRuleRecoveryDoesNotFollowSpecialFilesOrOverwritePendingJournal(t *testing.T) {
	for _, object := range []string{"journal_symlink", "journal_directory", "rules_symlink", "rules_directory", "rules_oversized"} {
		t.Run(object, func(t *testing.T) {
			e, v := recoveryFixture(t)
			raw := saveRecoveryFixture(t, e, v)
			target := e.ruleJournalPath()
			if strings.HasPrefix(object, "rules_") {
				target = e.Config.SuricataRulesPath
			}
			if err := os.Remove(target); err != nil {
				t.Fatal(err)
			}
			if strings.HasSuffix(object, "symlink") {
				private := filepath.Join(t.TempDir(), "private")
				if err := os.WriteFile(private, raw, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(private, target); err != nil {
					t.Fatal(err)
				}
			} else if strings.HasSuffix(object, "directory") {
				if err := os.Mkdir(target, 0700); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(target, []byte(strings.Repeat("#", 900*1024+1)), 0600); err != nil {
				t.Fatal(err)
			}
			if err := e.Recover(context.Background()); err == nil {
				t.Fatal("恢复接受了特殊文件或超限输入")
			}
			if _, err := os.Lstat(target); err != nil {
				t.Fatal("恢复删除或替换了不可信对象", err)
			}
		})
	}
	e, v := recoveryFixture(t)
	raw := saveRecoveryFixture(t, e, v)
	if _, code, err := e.Execute(context.Background(), control.Command{ID: "task_apply", Kind: "rules.apply"}); err == nil || code != "result_unknown" {
		t.Fatal("安装覆盖了在途恢复依据", code, err)
	}
	retained, err := os.ReadFile(e.ruleJournalPath())
	if err != nil || string(retained) != string(raw) {
		t.Fatal("安装改写了恢复依据", err)
	}
	e.ruleApplyMu.Lock()
	if err := e.Recover(context.Background()); err == nil {
		t.Fatal("恢复没有拒绝并发操作")
	}
	if _, code, err := e.Execute(context.Background(), control.Command{ID: "task_apply", Kind: "rules.apply"}); err == nil || code != "rule_operation_in_progress" {
		t.Fatal("安装没有拒绝并发操作", code, err)
	}
	e.ruleApplyMu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := e.Recover(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("恢复未遵守取消", err)
	}
	if err := os.Remove(e.ruleJournalPath()); err != nil {
		t.Fatal(err)
	}
	if err := e.Recover(context.Background()); err != nil {
		t.Fatal("没有事务时恢复失败", err)
	}
}

func TestEngineRefusesUnknownTaskAndUntrustedPackageBeforeNativeExecution(t *testing.T) {
	e := &Engine{Config: config.Config{SuricataBinary: "/missing-suricata", SuricataConfig: "/missing-config"}}
	if _, code, err := e.Execute(context.Background(), control.Command{Kind: "unsupported"}); err == nil || code != "unsupported_task" {
		t.Fatal("未知任务未被拒绝", code, err)
	}
	if _, code, err := e.Execute(context.Background(), control.Command{Kind: "rules.apply"}); err == nil || code != "invalid_task" {
		t.Fatal("安装没有拒绝无效身份", code, err)
	}
	if _, code, err := e.Execute(context.Background(), control.Command{ID: "task_apply", Kind: "rules.apply"}); err == nil || code != "rule_apply_not_authorized" {
		t.Fatal("未授权安装未被拒绝", code, err)
	}
	p := control.RulePackage{PackageID: "rules", Revision: 1, EngineVersion: "8.0.7", Text: recoveryPrevious, SHA256: control.Digest([]byte(recoveryPrevious))}
	for _, mutate := range []func(*control.RulePackage){
		func(p *control.RulePackage) { p.PackageID = "../rules" }, func(p *control.RulePackage) { p.Revision = 0 },
		func(p *control.RulePackage) { p.EngineVersion = "8.0.70" }, func(p *control.RulePackage) { p.SHA256 = strings.Repeat("0", 64) },
		func(p *control.RulePackage) {
			p.Text = strings.Replace(p.Text, "alert", "drop", 1)
			p.SHA256 = control.Digest([]byte(p.Text))
		},
	} {
		value := p
		mutate(&value)
		raw, _ := json.Marshal(value)
		if _, code, err := e.Execute(context.Background(), control.Command{Kind: "rules.validate", Payload: raw}); err == nil || code != "invalid_package" {
			t.Fatal("非法规则材料进入了原生执行", code, err)
		}
	}
	raw, _ := json.Marshal(p)
	for _, invalid := range [][]byte{[]byte("{"), append(append([]byte(nil), raw...), []byte(" {}")...), append(append([]byte(nil), raw[:len(raw)-1]...), []byte(`,"unknown":1}`)...)} {
		if _, code, err := e.Execute(context.Background(), control.Command{Kind: "rules.validate", Payload: invalid}); err == nil || code != "invalid_package" {
			t.Fatal("不完整或歧义载荷进入了原生执行", code, err)
		}
	}
}

type nativeRuleControlOptions struct {
	ruleFiles    []string
	arguments    []string
	joinedConfig bool
}

func nativeRuleControl(t *testing.T, ctx context.Context, options nativeRuleControlOptions) (*Engine, ruleTransaction) {
	t.Helper()
	binary := os.Getenv("SB_TEST_SURICATA_BINARY")
	if binary == "" {
		t.Skip("需要实际 Suricata 8.0.7 二进制和隔离运行环境")
	}
	e, v := recoveryFixture(t)
	dir := filepath.Dir(e.Config.StatePath)
	e.Config.SuricataBinary = binary
	e.Config.SuricataConfig = filepath.Join(dir, "suricata.yaml")
	if len(options.ruleFiles) == 0 {
		options.ruleFiles = []string{"active.rules"}
	}
	if len(options.ruleFiles) > 1 {
		if err := os.WriteFile(filepath.Join(dir, "other.rules"), []byte(recoveryPrevious), 0600); err != nil {
			t.Fatal(err)
		}
	}
	// JSON 是 YAML 的受限子集，整个配置由测试目录中的确定常量组成。
	settings := map[string]any{
		"vars":              map[string]any{"address-groups": map[string]string{"HOME_NET": "any", "EXTERNAL_NET": "any"}, "port-groups": map[string]string{"HTTP_PORTS": "80"}},
		"default-rule-path": dir, "rule-files": options.ruleFiles, "run-as": map[string]any{},
		"unix-command": map[string]any{"enabled": true, "filename": e.Config.SuricataSocket},
		"outputs":      []any{}, "logging": map[string]any{"default-log-level": "notice", "outputs": []any{map[string]any{"console": map[string]any{"enabled": true}}}},
		"flow":   map[string]any{"memcap": "16mb", "hash-size": 1024, "prealloc": 1024},
		"stream": map[string]any{"memcap": "32mb", "reassembly": map[string]any{"memcap": "64mb"}},
	}
	configuration, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(e.Config.SuricataConfig, append([]byte("%YAML 1.1\n---\n"), configuration...), 0600); err != nil {
		t.Fatal(err)
	}
	processContext, stop := context.WithCancel(ctx)
	arguments := []string{"-c", e.Config.SuricataConfig}
	if options.joinedConfig {
		arguments = []string{"-c" + e.Config.SuricataConfig}
	}
	arguments = append(arguments, "--unix-socket="+e.Config.SuricataSocket, "-l", dir)
	arguments = append(arguments, options.arguments...)
	cmd := exec.CommandContext(processContext, binary, arguments...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
	cmd.WaitDelay = 2 * time.Second
	var log boundedLog
	cmd.Stdout, cmd.Stderr = &log, &log
	if err = cmd.Start(); err != nil {
		stop()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() { stop(); <-done })
	if err = os.WriteFile(e.Config.SuricataPIDFile, []byte(strconv.Itoa(cmd.Process.Pid)), 0600); err != nil {
		t.Fatal(err)
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	ready := false
	for !ready {
		select {
		case err := <-done:
			done <- err
			t.Fatal("独立离线控制进程未就绪", err, string(log.data))
		case <-ctx.Done():
			t.Fatal("独立离线控制进程就绪超时")
		case <-ticker.C:
			request, end := context.WithTimeout(ctx, time.Second)
			_, err := socketCommand(request, e.Config.SuricataSocket, "conf-get", map[string]any{"variable": "default-rule-path"})
			end()
			ready = err == nil
		}
	}
	return e, v
}

// 实际离线引擎拒绝损坏的历史规则时，运行规则和恢复依据必须保持不变。
func TestNativeSuricataRecoveryChecksHistoricalRulesBeforeWrite(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	e, v := nativeRuleControl(t, ctx, nativeRuleControlOptions{})
	if err := e.ensureManagedPath(ctx); err != nil {
		t.Fatal("实际检测引擎身份或规则来源核对失败", err)
	}
	v.Previous = []byte(`alert tcp any any -> any any (msg:"Damaged historical rule"; no_such_keyword; sid:1000001; rev:1;)`)
	raw := saveRecoveryFixture(t, e, v)
	if err := e.Recover(ctx); err == nil || !strings.Contains(err.Error(), "历史规则未通过隔离装载检查") {
		t.Fatal("实际隔离引擎没有阻止损坏历史内容恢复", err)
	}
	current, err := os.ReadFile(e.Config.SuricataRulesPath)
	if err != nil || string(current) != recoveryTarget {
		t.Fatal("原生拒绝之后规则内容改变", err)
	}
	retained, err := os.ReadFile(e.ruleJournalPath())
	if err != nil || string(retained) != string(raw) {
		t.Fatal("原生拒绝之后恢复依据丢失", err)
	}
	// 有效历史内容必须经过同一真实进程的重载和摘要回读，再删除恢复依据。
	v.Previous = []byte(recoveryPrevious)
	saveRecoveryFixture(t, e, v)
	if err := e.Recover(ctx); err != nil {
		t.Fatal("实际检测引擎恢复失败", err)
	}
	current, err = os.ReadFile(e.Config.SuricataRulesPath)
	if err != nil || string(current) != recoveryPrevious {
		t.Fatal("实际恢复内容不一致", err)
	}
	if _, err = os.Lstat(e.ruleJournalPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("确认恢复之后没有回收事务记录", err)
	}
	// 直接测试设备执行基础，不把该设备入口当作平台正式发布资格。
	packageValue := control.RulePackage{PackageID: "rules_native_recovery", Revision: 2, EngineVersion: "8.0.7", Text: recoveryTarget, SHA256: control.Digest([]byte(recoveryTarget))}
	input := t.TempDir()
	configSHA, profile, err := offlineConfig(e.Config.SuricataConfig, input)
	if err != nil {
		t.Fatal(err)
	}
	packageValue.Authorization = &control.RuleAuthorization{ValidationTaskID: "task_validation", PositiveReplayTaskID: "task_positive", NegativeReplayTaskID: "task_negative", ExpectedRulesSHA256: control.Digest([]byte(recoveryPrevious)), ConfigSHA256: configSHA, ProfileSHA256: control.Digest([]byte(profile)), ValidationReceiptSHA256: control.Digest([]byte("validation")), PositiveReceiptSHA256: control.Digest([]byte("positive")), NegativeReceiptSHA256: control.Digest([]byte("negative"))}
	payload, _ := json.Marshal(packageValue)
	result, code, err := e.Execute(ctx, control.Command{ID: "task_native_apply", Kind: "rules.apply", Payload: payload})
	if err != nil {
		t.Fatal("实际规则安装和重载失败", code, err)
	}
	var receipt struct {
		SHA256, ActiveSHA256 string
	}
	var response map[string]json.RawMessage
	if json.Unmarshal(result, &response) != nil || json.Unmarshal(response["sha256"], &receipt.SHA256) != nil || json.Unmarshal(response["active_sha256"], &receipt.ActiveSHA256) != nil || receipt.SHA256 != packageValue.SHA256 || receipt.ActiveSHA256 != packageValue.SHA256 {
		t.Fatal("实际规则安装回执没有绑定候选摘要")
	}
	current, err = os.ReadFile(e.Config.SuricataRulesPath)
	if err != nil || string(current) != recoveryTarget {
		t.Fatal("实际安装没有写入对应规则", err)
	}
	if _, err = os.Lstat(e.ruleJournalPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("确认安装之后没有回收事务记录", err)
	}
	for _, tc := range []struct {
		name, code string
		change     func(*control.RuleAuthorization)
	}{
		{"changed rules", "active_rules_changed", func(a *control.RuleAuthorization) { a.ExpectedRulesSHA256 = control.Digest([]byte("another writer")) }},
		{"changed config", "release_configuration_changed", func(a *control.RuleAuthorization) { a.ConfigSHA256 = control.Digest([]byte("another config")) }},
		{"changed profile", "release_configuration_changed", func(a *control.RuleAuthorization) { a.ProfileSHA256 = control.Digest([]byte("another profile")) }},
		{"missing evidence", "release_validation_required", func(a *control.RuleAuthorization) { a.PositiveReceiptSHA256 = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value := packageValue
			grant := *value.Authorization
			value.Authorization = &grant
			tc.change(&grant)
			payload, _ := json.Marshal(value)
			if _, code, err := e.Execute(ctx, control.Command{ID: "task_stale", Kind: "rules.apply", Payload: payload}); err == nil || code != tc.code {
				t.Fatal("设备没有拒绝失效授权", code, err)
			}
			actual, err := os.ReadFile(e.Config.SuricataRulesPath)
			if err != nil || string(actual) != recoveryTarget {
				t.Fatal("失效授权改变了规则", err)
			}
			if _, err = os.Lstat(e.ruleJournalPath()); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("失效授权创建了写入事务", err)
			}
		})
	}
	packageValue.Text = strings.Replace(recoveryTarget, "sid:", "no_such_keyword; sid:", 1)
	packageValue.SHA256 = control.Digest([]byte(packageValue.Text))
	payload, _ = json.Marshal(packageValue)
	if _, code, err := e.Execute(ctx, control.Command{ID: "task_invalid_apply", Kind: "rules.apply", Payload: payload}); err == nil || code != "engine_validation_failed" {
		t.Fatal("实际安装没有拒绝非法候选", code, err)
	}
	current, err = os.ReadFile(e.Config.SuricataRulesPath)
	if err != nil || string(current) != recoveryTarget {
		t.Fatal("非法候选改变了实际规则文件", err)
	}
	// 文件已经恢复而记录尚未清除的崩溃窗口不能重复改写内容。
	v.Previous = []byte(recoveryTarget)
	v.TargetSHA256 = control.Digest([]byte(recoveryPrevious))
	saveRecoveryFixture(t, e, v)
	beforeInfo, err := os.Stat(e.Config.SuricataRulesPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Recover(ctx); err != nil {
		t.Fatal("已恢复文件的幂等核对失败", err)
	}
	afterInfo, err := os.Stat(e.Config.SuricataRulesPath)
	if err != nil || !afterInfo.ModTime().Equal(beforeInfo.ModTime()) {
		t.Fatal("恢复重复改写了已经恢复的规则文件", err)
	}
	if _, err = os.Lstat(e.ruleJournalPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("幂等恢复没有清除确认后的事务记录", err)
	}
}
