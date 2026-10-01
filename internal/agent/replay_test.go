package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/config"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/replay"
	"github.com/kkx600/StarBeacon/internal/testpcap"
	bolt "go.etcd.io/bbolt"
)

func TestNativeReplay(t *testing.T) {
	binary, cfg := os.Getenv("SB_TEST_SURICATA_BINARY"), os.Getenv("SB_TEST_SURICATA_CONFIG")
	if binary == "" || cfg == "" {
		t.Skip("需要明确指定受信任的原生 Suricata 8.0.7")
	}
	dir := t.TempDir()
	w, e := OpenWAL(filepath.Join(dir, "state.db"), "tenant_replay", "sensor_replay", "reg_replay", 4*1024*1024)
	if e != nil {
		t.Fatal(e)
	}
	defer w.Close()
	local, e := replay.NewLocal(filepath.Join(dir, "samples"), 200*1024*1024)
	if e != nil {
		t.Fatal(e)
	}
	engine := &Engine{Config: config.Config{Mode: "development", StatePath: filepath.Join(dir, "state.db"), SuricataBinary: binary, SuricataConfig: cfg}, WAL: w}
	service := &ReplayService{WAL: w, Storage: local, Engine: engine, RetentionDays: 180}
	engine.LocalReplay = service
	for _, ng := range []bool{false, true} {
		data, e := testpcap.HTTP(ng)
		if e != nil {
			t.Fatal(e)
		}
		if !ng && os.Getenv("SB_WRITE_REPLAY_FIXTURE") != "" {
			if e = os.WriteFile(os.Getenv("SB_WRITE_REPLAY_FIXTURE"), data, 0600); e != nil {
				t.Fatal(e)
			}
		}
		id := "sample_pcap"
		if ng {
			id = "sample_ng"
		}
		sha, kind, e := local.Put(context.Background(), replay.Key(w.TenantID, id), bytes.NewReader(data), int64(len(data)))
		if e != nil {
			t.Fatal(e)
		}
		v := replay.Sample{ID: id, SHA256: sha, Size: int64(len(data)), Format: kind, ExpiresAt: time.Now().Add(time.Hour)}
		raw, _ := json.Marshal(v)
		if e = w.DB.Update(func(tx *bolt.Tx) error {
			b, e := tx.CreateBucketIfNotExists([]byte("replay_samples"))
			if e != nil {
				return e
			}
			return b.Put([]byte(id), raw)
		}); e != nil {
			t.Fatal(e)
		}
		for _, tc := range []struct {
			name, text string
			hits       int
			fail       bool
		}{{"matched", `alert http any any -> any any (msg:"StarBeacon replay"; flow:established,to_server; http.uri; content:"/starbeacon/validation"; sid:1000001; rev:1;)`, 1, false}, {"no_match", `alert http any any -> any any (msg:"StarBeacon replay miss"; http.uri; content:"/never/match"; sid:1000002; rev:1;)`, 0, false}, {"invalid_rules", `alert tcp any any -> any any (msg:"Invalid replay"; no_such_keyword; sid:1000003; rev:1;)`, 0, true}} {
			t.Run(kind+"/"+tc.name, func(t *testing.T) {
				p := control.Replay{SampleID: id, SampleSHA256: sha, SampleSize: int64(len(data)), RuleMode: "package", Package: &control.RulePackage{PackageID: "rules_test", Revision: 1, EngineVersion: "8.0.7", Text: tc.text, SHA256: control.Digest([]byte(tc.text))}}
				payload, _ := control.ReplayPayload(p)
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				raw, code, e := engine.Execute(ctx, control.Command{ID: "localtask_native", TenantID: w.TenantID, Kind: "rules.replay", Payload: payload})
				if tc.fail {
					if e == nil || code != "replay_engine_failed" || !bytes.Contains(raw, []byte("no_such_keyword")) {
						t.Fatal("未知关键词未得到原生引擎拒绝", code, e, string(raw))
					}
					return
				}
				if e != nil {
					t.Fatal(code, e, string(raw))
				}
				var result map[string]any
				if e = json.Unmarshal(raw, &result); e != nil {
					t.Fatal(e)
				}
				if result["replay"] != "completed" || result["alert_count"] != float64(tc.hits) || result["packets_processed"] != "9" {
					t.Fatal(string(raw))
				}
			})
		}
	}
	registeredText := []byte(`alert http any any -> any any (msg:"Registered replay"; http.uri; content:"/starbeacon/validation"; sid:1000011; rev:2;)`)
	registeredPath := filepath.Join(dir, "registered.rules")
	if e = os.WriteFile(registeredPath, registeredText, 0600); e != nil {
		t.Fatal(e)
	}
	engine.Config.SuricataRulesPath = registeredPath
	sample, e := service.Sample("sample_pcap")
	if e != nil {
		t.Fatal(e)
	}
	payload, _ := control.ReplayPayload(control.Replay{SampleID: sample.ID, SampleSHA256: sample.SHA256, SampleSize: sample.Size, RuleMode: "registered"})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	raw, code, e := engine.Execute(ctx, control.Command{ID: "localtask_registered", TenantID: w.TenantID, Kind: "rules.replay", Payload: payload})
	if e != nil {
		t.Fatal(code, e, string(raw))
	}
	var result map[string]any
	if e = json.Unmarshal(raw, &result); e != nil {
		t.Fatal(e)
	}
	if result["replay"] != "completed" || result["alert_count"] != float64(1) || result["rules_sha256"] != control.Digest(registeredText) {
		t.Fatal("登记规则快照结果不一致", string(raw))
	}
	original, e := os.ReadFile(registeredPath)
	if e != nil || !bytes.Equal(original, registeredText) {
		t.Fatal("重放改变了登记规则", e)
	}

}
func TestReplaySandboxDeniesCredentials(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS 开发隔离验收")
	}
	dir := t.TempDir()
	input, output := filepath.Join(dir, "input"), filepath.Join(dir, "output")
	os.Mkdir(input, 0700)
	os.Mkdir(output, 0700)
	secret := filepath.Join(dir, "collector-private-key")
	os.WriteFile(secret, []byte("sensitive-test-marker"), 0600)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd, e := sandboxCommand(ctx, "/bin/cat", dir, input, output, []string{secret})
	if e != nil {
		t.Fatal(e)
	}
	raw, e := cmd.CombinedOutput()
	if e == nil || bytes.Contains(raw, []byte("sensitive-test-marker")) {
		t.Fatal("隔离进程读取了采集器凭据", string(raw))
	}
}

func TestReplaySandboxDeniesNetwork(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS 开发隔离验收")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("replay-network-marker")) }))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	args := []string{"--noproxy", "*", "--silent", "--show-error", "--max-time", "2", server.URL}
	positive, e := exec.CommandContext(ctx, "/usr/bin/curl", args...).CombinedOutput()
	if e != nil || !bytes.Contains(positive, []byte("replay-network-marker")) {
		t.Fatal("网络测试服务不可用", e)
	}
	dir := t.TempDir()
	input, output := filepath.Join(dir, "input"), filepath.Join(dir, "output")
	os.Mkdir(input, 0700)
	os.Mkdir(output, 0700)
	cmd, e := sandboxCommand(ctx, "/usr/bin/curl", dir, input, output, args)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := cmd.CombinedOutput()
	if e == nil || bytes.Contains(raw, []byte("replay-network-marker")) {
		t.Fatal("离线隔离允许访问网络", e)
	}
}
