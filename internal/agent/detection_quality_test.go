package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/config"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/detectionquality"
	"github.com/kkx600/StarBeacon/internal/replay"
	"github.com/kkx600/StarBeacon/internal/testpcap"
	bolt "go.etcd.io/bbolt"
)

func TestNativeDetectionQualityTCPAndIPReassemblyOnNonstandardPort(t *testing.T) {
	binary, cfg := os.Getenv("SB_TEST_SURICATA_BINARY"), os.Getenv("SB_TEST_SURICATA_CONFIG")
	if binary == "" || cfg == "" {
		t.Skip("检测质量验证需固定版本 Suricata 和原生隔离环境")
	}
	dir := t.TempDir()
	w, err := OpenWAL(filepath.Join(dir, "quality.db"), "tenant_quality", "sensor_quality", "reg_quality", 4<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	storage, err := replay.NewLocal(filepath.Join(dir, "samples"), 100<<20)
	if err != nil {
		t.Fatal(err)
	}
	e := &Engine{Config: config.Config{Mode: "development", StatePath: w.DB.Path(), SuricataBinary: binary, SuricataConfig: cfg}, WAL: w}
	e.LocalReplay = &ReplayService{WAL: w, Storage: storage, Engine: e, RetentionDays: 180}
	const rule = `alert http any any -> any any (msg:"StarBeacon HTTP reassembly validation"; flow:established,to_server; http.uri; content:"/starbeacon/validation"; sid:1000042; rev:1;)`
	for _, variant := range []struct {
		name              string
		segment, fragment int
		reverse           bool
	}{{"tcp_split", 7, 0, false}, {"tcp_out_of_order", 7, 0, true}, {"ipv4_fragments", 0, 32, false}, {"ipv4_fragments_out_of_order", 0, 32, true}} {
		for _, positive := range []bool{true, false} {
			t.Run(variant.name+map[bool]string{true: "/positive", false: "/negative"}[positive], func(t *testing.T) {
				path := "/starbeacon/validation"
				if !positive {
					path = "/health"
				}
				data, err := testpcap.HTTPQuality(path, 18088, variant.segment, variant.fragment, variant.reverse)
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
				defer cancel()
				const id = "sample_quality"
				sha, kind, err := storage.Put(ctx, replay.Key(w.TenantID, id), bytes.NewReader(data), int64(len(data)))
				if err != nil {
					t.Fatal(err)
				}
				defer storage.Remove(context.Background(), replay.Key(w.TenantID, id))
				v := replay.Sample{ID: id, SHA256: sha, Size: int64(len(data)), Format: kind, ExpiresAt: time.Now().Add(time.Hour)}
				encoded, _ := json.Marshal(v)
				if err = w.DB.Update(func(tx *bolt.Tx) error {
					b, err := tx.CreateBucketIfNotExists([]byte("replay_samples"))
					if err != nil {
						return err
					}
					return b.Put([]byte(id), encoded)
				}); err != nil {
					t.Fatal(err)
				}
				payload, err := control.ReplayPayload(control.Replay{SampleID: id, SampleSHA256: sha, SampleSize: int64(len(data)), RuleMode: "package", Package: &control.RulePackage{PackageID: "rules_quality", Revision: 1, EngineVersion: "8.0.7", Text: rule, SHA256: control.Digest([]byte(rule))}})
				if err != nil {
					t.Fatal(err)
				}
				raw, code, err := e.Execute(ctx, control.Command{ID: "localtask_quality", TenantID: w.TenantID, Kind: "rules.replay", Payload: payload})
				if err != nil {
					t.Fatal("原生重组验证未完成", code, err, string(raw))
				}
				var result struct {
					Replay     string `json:"replay"`
					AlertCount int    `json:"alert_count"`
				}
				if json.Unmarshal(raw, &result) != nil || result.Replay != "completed" || positive != (result.AlertCount == 1) || !positive && result.AlertCount != 0 {
					t.Fatal("跨包或分片的正反样本结果不符", string(raw))
				}
			})
		}
	}
}

func TestNativeQualityDistinguishesNoalertFromAlertQueueOverflow(t *testing.T) {
	binary, cfg := os.Getenv("SB_TEST_SURICATA_BINARY"), os.Getenv("SB_TEST_SURICATA_CONFIG")
	if binary == "" || cfg == "" {
		t.Skip("检测质量验证需固定版本 Suricata 和原生隔离环境")
	}
	for _, mode := range []string{"ordinary", "noalert", "overflow"} {
		t.Run(mode, func(t *testing.T) {
			dir, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			input, output := filepath.Join(dir, "input"), filepath.Join(dir, "output")
			for _, path := range []string{input, output} {
				if err = os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			}
			if _, _, err = offlineConfig(cfg, input); err != nil {
				t.Fatal(err)
			}
			pcap, err := testpcap.HTTP(false)
			if err != nil {
				t.Fatal(err)
			}
			if err = durableFile(filepath.Join(input, "sample.pcap"), pcap); err != nil {
				t.Fatal(err)
			}
			count, noalert := 1, ""
			if mode == "noalert" {
				noalert = "noalert;"
			}
			if mode == "overflow" {
				count = 64
			}
			var rules strings.Builder
			for i := 0; i < count; i++ {
				fmt.Fprintf(&rules, `alert http any any -> any any (msg:"StarBeacon quality counter"; flow:established,to_server; http.uri; content:"/starbeacon/validation"; %s sid:%d; rev:1;)`+"\n", noalert, 1000100+i)
			}
			if err = durableFile(filepath.Join(input, "rules.rules"), []byte(rules.String())); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			args := []string{"-c", filepath.Join(input, "suricata.yaml"), "--include", filepath.Join(input, "replay.yaml"), "-S", filepath.Join(input, "rules.rules"), "-r", filepath.Join(input, "sample.pcap"), "--runmode", "single", "--init-errors-fatal", "--strict-rule-keywords=all", "-l", output}
			log, _, limit, err := executeBounded(ctx, binary, dir, input, output, args)
			if err != nil || limit != "" {
				t.Fatal("原生质量样本执行失败", err, limit, string(log.data))
			}
			result, err := readReplayEvents(filepath.Join(output, "eve.json"))
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := json.Marshal(result["stats"])
			counters, ok := detectionquality.Extract(raw)
			if !ok {
				t.Fatal("原生统计无法解析")
			}
			value := func(key string) uint64 {
				v, err := strconv.ParseUint(counters[key], 10, 64)
				if err != nil {
					t.Fatal("原生统计缺少必需指标", key)
				}
				return v
			}
			overflow, suppressed := value("detect.alert_queue_overflow"), value("detect.alerts_suppressed")
			if mode == "ordinary" && (overflow != 0 || suppressed != 0 || result["alert_count"] != 1) || mode == "noalert" && (overflow != 0 || suppressed < 1 || result["alert_count"] != 0) || mode == "overflow" && (overflow < 1 || suppressed != 0 || result["alert_count"].(int) >= count) {
				t.Fatal("策略抑制与资源溢出未被独立计量", mode, overflow, suppressed, result["alert_count"])
			}
			t.Logf("原生离线样本 %s：队列溢出 %d，规则抑制 %d，输出告警 %d", mode, overflow, suppressed, result["alert_count"])
		})
	}
}
