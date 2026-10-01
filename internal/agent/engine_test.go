package agent

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/config"
	"github.com/kkx600/StarBeacon/internal/control"
)

func TestNativeSuricataRuleValidation(t *testing.T) {
	binary := os.Getenv("SB_TEST_SURICATA_BINARY")
	path := os.Getenv("SB_TEST_SURICATA_CONFIG")
	if binary == "" || path == "" {
		t.Skip("原生引擎测试需明确指定 Suricata 8.0.7 二进制与受信任配置")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	engine := &Engine{Config: config.Config{SuricataBinary: binary, SuricataConfig: path, StatePath: filepath.Join(t.TempDir(), "state.db")}}
	for _, tc := range []struct {
		name, text string
		valid      bool
	}{{"valid", `alert http any any -> any any (msg:"StarBeacon native validation"; flow:established,to_server; http.uri; content:"/starbeacon/validation"; sid:1000001; rev:1;)`, true}, {"invalid", `alert http any any -> any any (msg:"StarBeacon invalid"; no_such_keyword; sid:1000002; rev:1;)`, false}} {
		t.Run(tc.name, func(t *testing.T) {
			p := control.RulePackage{PackageID: "rules_native", Revision: 1, EngineVersion: "8.0.7", Text: tc.text, SHA256: control.Digest([]byte(tc.text))}
			payload, _ := json.Marshal(p)
			raw, code, err := engine.Execute(ctx, control.Command{Kind: "rules.validate", Payload: payload})
			if tc.valid {
				if err != nil {
					t.Fatal("真实引擎验证失败", code, err, string(raw))
				}
				var out struct{ Syntax, Replay string }
				if json.Unmarshal(raw, &out) != nil || out.Syntax != "passed" || out.Replay != "not_run" {
					t.Fatal("装载检查与回放状态混淆")
				}
			} else if err == nil || code != "engine_validation_failed" {
				t.Fatal("真实引擎未拒绝未知关键词", code, err)
			}
		})
	}
}

func TestSocketDecoderHandlesFragmentedReply(t *testing.T) {
	dir, err := os.MkdirTemp("", "sb-sock-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "suricata.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		decoder := json.NewDecoder(conn)
		var request map[string]any
		if err = decoder.Decode(&request); err != nil {
			done <- err
			return
		}
		if request["version"] != "0.2" {
			done <- os.ErrInvalid
			return
		}
		if _, err = conn.Write([]byte(`{"return":"OK"}` + "\n")); err != nil {
			done <- err
			return
		}
		if err = decoder.Decode(&request); err != nil {
			done <- err
			return
		}
		for _, p := range []string{`{"ret`, `urn":"OK","message":[{"rules_loaded":1,`, `"rules_failed":0}]}` + "\n"} {
			if _, err = conn.Write([]byte(p)); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	raw, err := socketCommand(ctx, path, "ruleset-stats", nil)
	if err != nil || !json.Valid(raw) {
		t.Fatal("分段 socket 回复解码失败", err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
}

func TestEngineVersionCannotMatchAnotherPatch(t *testing.T) {
	for _, v := range []string{"Suricata 8.0.70 RELEASE", "Suricata 18.0.7 RELEASE", "Suricata 8.0.7-dev"} {
		if engineVersion.MatchString(v) {
			t.Fatal("版本匹配误接受", v)
		}
	}
	if !engineVersion.MatchString("This is Suricata version 8.0.7 RELEASE\n") {
		t.Fatal("正式引擎版本未识别")
	}
}
