package agent

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// 实际控制进程就绪之后，登记身份和完整规则来源仍须独立核验。
func TestNativeSuricataManagedRuleSourceGuards(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	e, transaction := nativeRuleControl(t, ctx, nativeRuleControlOptions{})
	if err := e.ensureManagedPath(ctx); err != nil {
		t.Fatal("登记进程和完整规则来源未通过核对", err)
	}
	original := e.Config
	for _, tc := range []struct {
		name, reason string
		change       func(*testing.T)
	}{
		{"登记其他可执行文件", "运行进程不属于登记的检测引擎", func(t *testing.T) {
			path, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			e.Config.SuricataBinary = path
		}},
		{"登记其他配置文件", "运行引擎配置路径不匹配", func(t *testing.T) {
			e.Config.SuricataConfig = filepath.Join(t.TempDir(), "another.yaml")
			if err := os.WriteFile(e.Config.SuricataConfig, []byte("{}"), 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{"登记配置丢失", "运行引擎配置路径不匹配", func(t *testing.T) {
			e.Config.SuricataConfig = filepath.Join(t.TempDir(), "missing.yaml")
		}},
		{"运行配置路径被移走", "", func(t *testing.T) {
			moved := original.SuricataConfig + ".moved"
			if err := os.Rename(original.SuricataConfig, moved); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := os.Rename(moved, original.SuricataConfig); err != nil {
					t.Fatal(err)
				}
			})
		}},
		{"控制套接字丢失", "", func(t *testing.T) {
			e.Config.SuricataSocket = filepath.Join(t.TempDir(), "missing.sock")
		}},
		{"登记进程已经退出", "", func(t *testing.T) {
			process := exec.CommandContext(ctx, "/usr/bin/true")
			if err := process.Run(); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(e.Config.SuricataPIDFile, []byte(strconv.Itoa(process.Process.Pid)), 0600); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pid, err := os.ReadFile(original.SuricataPIDFile)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				e.Config = original
				if err := os.WriteFile(original.SuricataPIDFile, pid, 0600); err != nil {
					t.Fatal(err)
				}
			})
			tc.change(t)
			assertNativeRuleSourceRejected(t, ctx, e, transaction, tc.reason)
		})
	}
	t.Run("登记其他规则文件", func(t *testing.T) {
		e.Config.SuricataRulesPath = filepath.Join(t.TempDir(), "another.rules")
		t.Cleanup(func() { e.Config = original })
		if err := os.WriteFile(e.Config.SuricataRulesPath, []byte(recoveryTarget), 0600); err != nil {
			t.Fatal(err)
		}
		pending := transaction
		pending.Path = e.Config.SuricataRulesPath
		assertNativeRuleSourceRejected(t, ctx, e, pending, "运行引擎不使用登记的规则文件")
		actual, err := os.ReadFile(original.SuricataRulesPath)
		if err != nil || string(actual) != recoveryTarget {
			t.Fatal("来源拒绝改写了实际运行规则", err)
		}
	})
	for _, tc := range []struct {
		name, reason string
		options      nativeRuleControlOptions
	}{
		{"命令行覆盖配置", "运行引擎存在规则来源或配置覆盖参数", nativeRuleControlOptions{arguments: []string{"--set", "flow.hash-size=1024"}}},
		{"未使用独立配置参数", "运行引擎未使用明确登记的配置", nativeRuleControlOptions{joinedConfig: true}},
		{"同时加载其他规则包", "检测引擎仍引用其他规则包", nativeRuleControlOptions{ruleFiles: []string{"active.rules", "other.rules"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			engine, pending := nativeRuleControl(t, ctx, tc.options)
			assertNativeRuleSourceRejected(t, ctx, engine, pending, tc.reason)
		})
	}
	if _, err := e.reloadAndRead(ctx, 2); err == nil || !strings.Contains(err.Error(), "运行引擎装载数量与完整规则包不一致") {
		t.Fatal("原生回读接受了与完整包不同的规则数量", err)
	}
	if _, err := e.reloadAndRead(ctx, 1); err != nil {
		t.Fatal("原生回读未恢复为实际装载数量", err)
	}
}

func assertNativeRuleSourceRejected(t *testing.T, ctx context.Context, engine *Engine, transaction ruleTransaction, reason string) {
	t.Helper()
	before, err := os.ReadFile(transaction.Path)
	if err != nil {
		t.Fatal(err)
	}
	raw := saveRecoveryFixture(t, engine, transaction)
	if err := engine.ensureManagedPath(ctx); err == nil || (reason != "" && !strings.Contains(err.Error(), reason)) {
		t.Fatal("不可信运行来源未被拒绝", err)
	}
	if err := engine.Recover(ctx); err == nil || (reason != "" && !strings.Contains(err.Error(), reason)) {
		t.Fatal("恢复未核对实际运行来源", err)
	}
	after, err := os.ReadFile(transaction.Path)
	if err != nil || string(after) != string(before) {
		t.Fatal("运行资格拒绝之后规则文件被改写", err)
	}
	retained, err := os.ReadFile(engine.ruleJournalPath())
	if err != nil || string(retained) != string(raw) {
		t.Fatal("运行资格拒绝之后恢复依据丢失", err)
	}
	if err := os.Remove(engine.ruleJournalPath()); err != nil {
		t.Fatal(err)
	}
}

// 文件存在不代表可读取；权限失败必须保留原始规则和事务材料。
func TestNativeSuricataUnreadableRecoveryMaterial(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("需要非 root 运行身份验证文件读取权限")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	e, transaction := nativeRuleControl(t, ctx, nativeRuleControlOptions{})
	for _, target := range []string{e.Config.SuricataPIDFile, e.Config.SuricataRulesPath, e.ruleJournalPath()} {
		t.Run(filepath.Base(target), func(t *testing.T) {
			raw := saveRecoveryFixture(t, e, transaction)
			before, err := os.ReadFile(e.Config.SuricataRulesPath)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(target, 0000); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(target, 0600) })
			if err := e.Recover(ctx); err == nil || !errors.Is(err, os.ErrPermission) {
				t.Fatal("恢复接受了不可读取的来源文件", err)
			}
			if target == e.Config.SuricataRulesPath {
				if _, err := ruleFileDigest(target, 900*1024); err == nil || !errors.Is(err, os.ErrPermission) {
					t.Fatal("心跳摘要接受了不可读取的规则", err)
				}
			}
			if err := os.Chmod(target, 0600); err != nil {
				t.Fatal(err)
			}
			after, err := os.ReadFile(e.Config.SuricataRulesPath)
			if err != nil || string(after) != string(before) {
				t.Fatal("权限拒绝后规则文件被改写", err)
			}
			retained, err := os.ReadFile(e.ruleJournalPath())
			if err != nil || string(retained) != string(raw) {
				t.Fatal("权限拒绝后事务材料丢失", err)
			}
		})
	}
}
