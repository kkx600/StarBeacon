//go:build linux

package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCapturePrivateFilesAndClosedQueuePreventConfiguration(t *testing.T) {
	for _, name := range []string{"missing_queue", "parent_file", "aux_relative", "aux_destination", "rule_destination", "revision_limit", "closed_queue", "invalid_settings"} {
		t.Run(name, func(t *testing.T) {
			e := captureFixture(t)
			if name == "missing_queue" {
				e.WAL = nil
				if _, err := NewCaptureSupervisor(e); err == nil {
					t.Fatal("无持久队列允许托管")
				}
				return
			}
			root := filepath.Join(filepath.Dir(e.Config.StatePath), "capture")
			if name == "parent_file" {
				if err := os.WriteFile(root, []byte("foreign"), 0600); err != nil {
					t.Fatal(err)
				}
				if _, err := NewCaptureSupervisor(e); err == nil {
					t.Fatal("工作目录被普通文件占用仍启动")
				}
				return
			}
			if name == "aux_relative" {
				if err := os.WriteFile(filepath.Join(filepath.Dir(e.Config.SuricataConfig), "owned-classification"), []byte("config classification: owned,Owned,1\n"), 0600); err != nil {
					t.Fatal(err)
				}
				f, err := os.OpenFile(e.Config.SuricataConfig, os.O_APPEND|os.O_WRONLY, 0600)
				if err != nil {
					t.Fatal(err)
				}
				_, err = f.WriteString("classification-file: owned-classification\n")
				_ = f.Close()
				if err != nil {
					t.Fatal(err)
				}
				if _, err = NewCaptureSupervisor(e); err != nil {
					t.Fatal("专属相对辅助文件不能加载", err)
				}
				copy, err := os.ReadFile(filepath.Join(root, "classification.config"))
				if err != nil || !strings.Contains(string(copy), "Owned") {
					t.Fatal("辅助文件未冻结到专属目录", err)
				}
				return
			}
			if name == "aux_destination" {
				if err := os.MkdirAll(filepath.Join(root, "classification.config"), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(filepath.Dir(e.Config.SuricataConfig), "classification.config"), []byte("owned"), 0600); err != nil {
					t.Fatal(err)
				}
				if _, err := NewCaptureSupervisor(e); err == nil {
					t.Fatal("辅助目的路径冲突仍启动")
				}
				return
			}
			if name == "rule_destination" {
				e.Config.SuricataRulesPath = filepath.Join(filepath.Dir(e.Config.StatePath), "absent", "active.rules")
				if _, err := NewCaptureSupervisor(e); err == nil {
					t.Fatal("初始规则写入失败仍启动")
				}
				return
			}
			s, err := NewCaptureSupervisor(e)
			if err != nil {
				t.Fatal(err)
			}
			settings := CaptureSettings{Interfaces: []string{}, Threads: 2}
			switch name {
			case "revision_limit":
				s.state.Revision = 9007199254740991
			case "closed_queue":
				if err = e.WAL.Close(); err != nil {
					t.Fatal(err)
				}
			case "invalid_settings":
				settings.Interfaces = []string{"missing-interface"}
			}
			before := s.Snapshot()
			if _, err = s.Configure(context.Background(), settings, "admin", "configuration_fault"); err == nil {
				t.Fatal("不可提交配置仍返回成功")
			}
			if after := s.Snapshot(); after.Revision != before.Revision || after.Status != before.Status {
				t.Fatal("失败写入改变期望修订")
			}
		})
	}
}

func TestCaptureApplicationFailureKeepsRegisteredState(t *testing.T) {
	interfaces, err := Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	name := ""
	for _, item := range interfaces {
		if item.Up && !item.Loopback && item.MAC != "" {
			name = item.Name
			break
		}
	}
	if name == "" {
		t.Fatal("Linux 验收容器没有可用 Ethernet 接口")
	}
	for _, kind := range []string{"rule_busy", "interface_removed", "spool_full", "candidate_conflict", "rules_missing", "engine_missing", "journal_path"} {
		t.Run(kind, func(t *testing.T) {
			e := captureFixture(t)
			s, err := NewCaptureSupervisor(e)
			if err != nil {
				t.Fatal(err)
			}
			v := false
			s.state.CaptureSettings = CaptureSettings{Interfaces: []string{name}, Threads: 1, Promiscuous: &v}
			s.state.Revision = 1
			want := ""
			switch kind {
			case "rule_busy":
				e.ruleApplyMu.Lock()
				defer e.ruleApplyMu.Unlock()
				want = "rule_operation_in_progress"
			case "interface_removed":
				s.state.Interfaces = []string{"missing-interface"}
				want = "capture_interface_unavailable"
			case "spool_full":
				f, err := os.Create(e.Config.EVEPath)
				if err != nil {
					t.Fatal(err)
				}
				err = f.Truncate(e.Config.CaptureSpoolBytes)
				_ = f.Close()
				if err != nil {
					t.Fatal(err)
				}
				want = "capture_spool_full"
			case "candidate_conflict":
				if err := os.Mkdir(filepath.Join(s.root, "candidate.yaml"), 0700); err != nil {
					t.Fatal(err)
				}
				want = "local_storage_unavailable"
			case "rules_missing":
				if err := os.Remove(e.Config.SuricataRulesPath); err != nil {
					t.Fatal(err)
				}
				want = "registered_rules_unavailable"
			case "engine_missing":
				want = "engine_not_configured"
			case "journal_path":
				parent := filepath.Join(filepath.Dir(e.Config.StatePath), "blocked")
				if err := os.WriteFile(parent, []byte("foreign"), 0600); err != nil {
					t.Fatal(err)
				}
				e.Config.StatePath = filepath.Join(parent, "agent.db")
				want = "local_storage_unavailable"
			}
			s.Start(context.Background())
			state := s.Snapshot()
			if state.Status != "failed" || state.ErrorCode != want || state.AppliedRevision != 0 || s.Ready() {
				t.Fatal("配置失败没有留下真实结果", kind, state)
			}
		})
	}
}

func TestRemoteCaptureFailedStorageAndChangedProcessRemainUnconfirmed(t *testing.T) {
	e := captureFixture(t)
	s, err := NewCaptureSupervisor(e)
	if err != nil {
		t.Fatal(err)
	}
	v := false
	settings := CaptureSettings{Interfaces: []string{}, Threads: 2, Promiscuous: &v}
	s.state.PID = 12345
	if _, code, err := s.ConfigureRemote(context.Background(), remoteCaptureInput(s, settings), "changed_process"); err == nil || code != "capture_process_or_configuration_changed" {
		t.Fatal("无法核对的进程仍接受远程配置", code, err)
	}
	s.state.PID = 0
	if err = e.WAL.Close(); err != nil {
		t.Fatal(err)
	}
	if _, code, err := s.ConfigureRemote(context.Background(), remoteCaptureInput(s, settings), "closed_storage"); err == nil || code != "local_storage_unavailable" {
		t.Fatal("失败持久化返回实际生效", code, err)
	}
}

func TestCaptureLaunchFailureDoesNotDeclareNetworkReady(t *testing.T) {
	for _, kind := range []string{"missing_binary", "early_exit", "pid_destination", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			e := captureFixture(t)
			s, err := NewCaptureSupervisor(e)
			if err != nil {
				t.Fatal(err)
			}
			e.Config.SuricataBinary = "/bin/false"
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			switch kind {
			case "missing_binary":
				e.Config.SuricataBinary = filepath.Join(t.TempDir(), "absent")
			case "pid_destination":
				if err := os.Mkdir(e.Config.SuricataPIDFile, 0700); err != nil {
					t.Fatal(err)
				}
			case "cancelled":
				cancel()
			}
			if err = s.launch(ctx, []byte("owned: true"), 1, CaptureSettings{}); err == nil {
				t.Fatal("未就绪子进程被声明为捕获")
			}
			s.stop(context.Background())
			if s.Ready() || s.active != nil {
				t.Fatal("失败启动遗留活动进程")
			}
			if kind == "missing_binary" && !errors.Is(err, os.ErrNotExist) {
				t.Fatal("启动错误身份被覆盖", err)
			}
		})
	}
}
