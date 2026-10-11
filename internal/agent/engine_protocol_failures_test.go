package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/config"
	"github.com/kkx600/StarBeacon/internal/control"
)

// 受控本地套接字只验证错误契约；原生装载与恢复另由真实引擎用例验收。
func failureSocket(t *testing.T, replies []string, handshake string) (string, <-chan struct{}) {
	t.Helper()
	dir, err := os.MkdirTemp("", "sb-fault-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "engine.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	done := make(chan struct{})
	go func() {
		defer close(done)
		for _, reply := range replies {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.SetDeadline(time.Now().Add(time.Second))
			decoder := json.NewDecoder(conn)
			var request map[string]any
			if decoder.Decode(&request) != nil {
				_ = conn.Close()
				return
			}
			if handshake != "" {
				_, _ = io.WriteString(conn, handshake)
				_ = conn.Close()
				continue
			}
			_, _ = io.WriteString(conn, `{"return":"OK"}`+"\n")
			if decoder.Decode(&request) == nil {
				_, _ = io.WriteString(conn, reply)
			}
			_ = conn.Close()
		}
	}()
	return path, done
}

func TestEngineSocketFailuresAndRuleReadbackNeverReportSuccess(t *testing.T) {
	for _, mode := range []string{"handshake_rejected", "handshake_invalid", "reply_empty", "reply_invalid", "reply_limit", "rejected"} {
		t.Run(mode, func(t *testing.T) {
			handshake, reply := "", `{"return":"NOK","message":"owned sensitive detail"}`
			switch mode {
			case "handshake_rejected":
				handshake = `{"return":"NOK"}`
			case "handshake_invalid":
				handshake = `{`
			case "reply_empty":
				reply = ""
			case "reply_invalid":
				reply = `{`
			case "reply_limit":
				reply = `{"return":"OK","message":"` + strings.Repeat("a", 256*1024) + `"}`
			}
			path, done := failureSocket(t, []string{reply}, handshake)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			raw, err := socketCommand(ctx, path, "ruleset-stats", nil)
			if err == nil || raw != nil {
				t.Fatal("套接字错误被当作有效规则结果")
			}
			if mode == "rejected" {
				var rejected *socketRejection
				if !errors.As(err, &rejected) || !strings.Contains(err.Error(), "ruleset-stats") || strings.Contains(err.Error(), "sensitive") {
					t.Fatal("控制错误没有保留类型或泄露正文", err)
				}
			}
			<-done
		})
	}
	for _, mode := range []string{"reload_rejected", "stats_rejected", "stats_invalid", "empty", "failed", "unloaded"} {
		t.Run(mode, func(t *testing.T) {
			replies := []string{`{"return":"OK","message":"done"}`, `{"return":"OK","message":[]}`}
			switch mode {
			case "reload_rejected":
				replies = []string{`{"return":"NOK","message":"denied"}`}
			case "stats_rejected":
				replies[1] = `{"return":"NOK","message":"denied"}`
			case "stats_invalid":
				replies[1] = `{"return":"OK","message":{}}`
			case "failed":
				replies[1] = `{"return":"OK","message":[{"rules_loaded":1,"rules_failed":1}]}`
			case "unloaded":
				replies[1] = `{"return":"OK","message":[{"rules_loaded":0,"rules_failed":0}]}`
			}
			path, done := failureSocket(t, replies, "")
			e := &Engine{Config: config.Config{SuricataSocket: path}}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if raw, err := e.reloadAndRead(ctx); err == nil || raw != nil {
				t.Fatal("不完整装载被当作规则发布成功")
			}
			<-done
		})
	}
	var log boundedLog
	input := bytes.Repeat([]byte("x"), 40*1024)
	n, err := log.Write(input)
	if n != len(input) || err != nil || len(log.data) != 32*1024 || !log.truncated {
		t.Fatal("引擎日志未受预算限制")
	}
	if n, err = log.Write([]byte("continued")); n != 9 || err != nil || len(log.data) != 32*1024 {
		t.Fatal("追加日志突破预算")
	}
}

func TestNativeRulePreflightFailureKeepsInstalledRules(t *testing.T) {
	binary, cfg := os.Getenv("SB_TEST_SURICATA_BINARY"), os.Getenv("SB_TEST_SURICATA_CONFIG")
	if binary == "" || cfg == "" {
		t.Skip("需要原生 Suricata 与隔离工具")
	}
	for _, mode := range []string{"wrong_version", "state_directory", "missing_config", "diagnostics", "managed_mismatch", "capabilities"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			wal, err := OpenWAL(filepath.Join(dir, "state.db"), "tenant_rule_fault", "sensor_rule_fault", "registration_rule_fault", 4<<20)
			if err != nil {
				t.Fatal(err)
			}
			defer wal.Close()
			engine := &Engine{WAL: wal, Config: config.Config{Mode: "development", StatePath: wal.DB.Path(), SuricataBinary: binary, SuricataConfig: cfg, SuricataRulesPath: filepath.Join(dir, "active.rules"), SuricataSocket: filepath.Join(dir, "missing.sock"), SuricataPIDFile: filepath.Join(dir, "missing.pid"), AllowRuleApply: true}}
			if err := os.WriteFile(engine.Config.SuricataRulesPath, []byte(recoveryPrevious), 0600); err != nil {
				t.Fatal(err)
			}
			pkg := control.RulePackage{PackageID: "rules_preflight", Revision: 1, EngineVersion: "8.0.7", Text: recoveryTarget, SHA256: control.Digest([]byte(recoveryTarget))}
			payload, _ := json.Marshal(pkg)
			command := control.Command{ID: "task_preflight", Kind: "rules.validate", Payload: payload}
			want := ""
			switch mode {
			case "wrong_version":
				engine.Config.SuricataBinary = "/usr/bin/false"
				want = "engine_version_mismatch"
			case "state_directory":
				engine.Config.StatePath = filepath.Join(dir, "missing", "state.db")
				want = "local_storage_unavailable"
			case "missing_config":
				engine.Config.SuricataConfig = filepath.Join(dir, "missing.yaml")
				want = "engine_not_configured"
			case "managed_mismatch":
				command.Kind = "rules.apply"
				configSHA, profile, err := offlineConfig(engine.Config.SuricataConfig, t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				digest := control.Digest([]byte("preflight rejection fixture"))
				pkg.Authorization = &control.RuleAuthorization{ValidationTaskID: "validation", PositiveReplayTaskID: "positive", NegativeReplayTaskID: "negative", ExpectedRulesSHA256: control.Digest([]byte(recoveryPrevious)), ConfigSHA256: configSHA, ProfileSHA256: control.Digest([]byte(profile)), ValidationReceiptSHA256: digest, PositiveReceiptSHA256: digest, NegativeReceiptSHA256: digest}
				command.Payload, err = control.RulePayload(pkg)
				if err != nil {
					t.Fatal(err)
				}
				want = "managed_rules_mismatch"
			case "diagnostics":
				command.Kind = "diagnostics"
			case "capabilities":
				found := false
				for _, c := range engine.Capabilities() {
					if c == "rules.apply" {
						found = true
					}
				}
				if !found {
					t.Fatal("已授权且隔离可用的规则能力未上报")
				}
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			raw, code, err := engine.Execute(ctx, command)
			if mode == "diagnostics" {
				if err != nil || !json.Valid(raw) {
					t.Fatal("诊断结果无效", err)
				}
			} else if err == nil || code != want {
				t.Fatal("预检失败状态不正确", code, want, err)
			}
			installed, err := os.ReadFile(engine.Config.SuricataRulesPath)
			if err != nil || string(installed) != recoveryPrevious {
				t.Fatal("失败预检改写了在用规则")
			}
		})
	}
}
