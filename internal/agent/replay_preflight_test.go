package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/config"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/replay"
	"github.com/kkx600/StarBeacon/internal/testpcap"
	bolt "go.etcd.io/bbolt"
)

func TestNativeReplayPreflightFailuresDoNotChangeRulesOrSamples(t *testing.T) {
	binary, cfg := os.Getenv("SB_TEST_SURICATA_BINARY"), os.Getenv("SB_TEST_SURICATA_CONFIG")
	if binary == "" || cfg == "" {
		t.Skip("需要独立容器中的 Suricata 8.0.7 与隔离工具")
	}
	for _, mode := range []string{"payload", "wrong_binary", "job_directory", "sample_missing", "digest_mismatch", "object_missing", "malformed_capture", "registered_missing", "registered_unreadable", "invalid_package", "config_missing"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			w, err := OpenWAL(filepath.Join(dir, "state.db"), "tenant_preflight", "sensor_preflight", "reg_preflight", 8<<20)
			if err != nil {
				t.Fatal(err)
			}
			defer w.Close()
			storage, err := replay.NewLocal(filepath.Join(dir, "samples"), replay.MaxSampleBytes)
			if err != nil {
				t.Fatal(err)
			}
			engine := &Engine{Config: config.Config{Mode: "development", StatePath: w.DB.Path(), SuricataBinary: binary, SuricataConfig: cfg}, WAL: w}
			service := &ReplayService{WAL: w, Storage: storage, Engine: engine, RetentionDays: 180}
			engine.LocalReplay = service
			data, err := testpcap.HTTP(false)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "malformed_capture" {
				data = data[:24]
			}
			sha, kind, err := storage.Put(context.Background(), replay.Key(w.TenantID, "sample_preflight"), bytes.NewReader(data), int64(len(data)))
			if err != nil {
				t.Fatal(err)
			}
			sample := replay.Sample{ID: "sample_preflight", Size: int64(len(data)), SHA256: sha, Format: kind, ExpiresAt: time.Now().Add(time.Hour)}
			raw, _ := json.Marshal(sample)
			if err = w.DB.Update(func(tx *bolt.Tx) error {
				b, err := tx.CreateBucketIfNotExists([]byte("replay_samples"))
				if err != nil {
					return err
				}
				return b.Put([]byte(sample.ID), raw)
			}); err != nil {
				t.Fatal(err)
			}
			pkg := control.RulePackage{PackageID: "rules_preflight", Revision: 1, EngineVersion: "8.0.7", Text: `alert tcp any any -> any any (sid:1000001;)`}
			pkg.SHA256 = control.Digest([]byte(pkg.Text))
			p := control.Replay{SampleID: sample.ID, SampleSize: sample.Size, SampleSHA256: sha, RuleMode: "package", Package: &pkg}
			code := ""
			switch mode {
			case "payload":
				code = "invalid_package"
			case "wrong_binary":
				engine.Config.SuricataBinary = "/usr/bin/false"
				code = "engine_version_mismatch"
			case "job_directory":
				engine.Config.StatePath = filepath.Join(dir, "missing", "state.db")
				code = "local_storage_unavailable"
			case "sample_missing":
				p.SampleID = "sample_missing"
				code = "replay_sample_unavailable"
			case "digest_mismatch":
				p.SampleSHA256 = control.Digest([]byte("changed"))
				code = "replay_sample_unavailable"
			case "object_missing":
				if err = storage.Remove(context.Background(), replay.Key(w.TenantID, sample.ID)); err != nil {
					t.Fatal(err)
				}
				code = "replay_sample_unavailable"
			case "malformed_capture":
				code = "replay_sample_invalid"
			case "registered_missing":
				p.RuleMode = "registered"
				p.Package = nil
				code = "registered_rules_unavailable"
			case "registered_unreadable":
				p.RuleMode = "registered"
				p.Package = nil
				engine.Config.SuricataRulesPath = filepath.Join(dir, "missing.rules")
				code = "registered_rules_unavailable"
			case "invalid_package":
				p.Package.Text = "drop tcp any any -> any any (sid:1000001;)"
				code = "invalid_package"
			case "config_missing":
				engine.Config.SuricataConfig = filepath.Join(dir, "missing.yaml")
				code = "engine_not_configured"
			}
			payload, err := control.ReplayPayload(p)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "payload" {
				payload = json.RawMessage(`{`)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			_, actual, err := engine.Replay(ctx, control.Command{ID: "localtask_preflight", TenantID: w.TenantID, Payload: payload})
			if err == nil || actual != code {
				t.Fatal("预检失败没有准确返回", mode, actual, err)
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if len(entry.Name()) >= 11 && entry.Name()[:11] == "replay-job-" {
					t.Fatal("失败预检遗留执行目录")
				}
			}
		})
	}
}
