package agent

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	sensorv1 "github.com/kkx600/StarBeacon/api/sensor/v1"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/replay"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/shirou/gopsutil/v4/process"
)

// 隔离环境不可用时拒绝重放，不降级为拥有采集器凭据访问权的普通子进程。
func (e *Engine) ReplayAvailable() bool {
	if e.Config.SuricataBinary == "" || e.Config.SuricataConfig == "" {
		return false
	}
	if runtime.GOOS == "darwin" {
		return e.Config.Mode == "development" && executable("/usr/bin/sandbox-exec")
	}
	if runtime.GOOS == "linux" {
		_, err := exec.LookPath("bwrap")
		return err == nil
	}
	return false
}
func executable(path string) bool {
	i, e := os.Stat(path)
	return e == nil && i.Mode().IsRegular() && i.Mode().Perm()&0111 != 0
}
func quote(path string) string { v, _ := json.Marshal(path); return string(v) }
func sandboxCommand(ctx context.Context, binary, job, input, output string, args []string) (*exec.Cmd, error) {
	binary, e := exec.LookPath(binary)
	if e != nil {
		return nil, e
	}
	binary, e = filepath.EvalSymlinks(binary)
	if e != nil {
		return nil, e
	}
	job, e = filepath.EvalSymlinks(job)
	if e != nil {
		return nil, e
	}
	input = filepath.Join(job, "input")
	output = filepath.Join(job, "output")
	var command []string
	if runtime.GOOS == "darwin" {
		profile := `(version 1)(deny default)(allow process-exec process-fork signal sysctl-read mach-lookup)(allow file-read-metadata)(allow file-read* (literal "/") (subpath "/System") (subpath "/usr/lib") (subpath "/usr/share") (subpath "/Library/Apple") (subpath "/opt/homebrew/Cellar") (subpath "/opt/homebrew/lib") (subpath "/opt/homebrew/opt") (literal "/dev/null") (literal "/dev/urandom") (literal "/dev/random") (subpath ` + quote(input) + `))(allow file-read* file-write* (subpath ` + quote(output) + `))`
		command = []string{"/usr/bin/sandbox-exec", "-p", profile, binary}
	} else if runtime.GOOS == "linux" {
		bwrap, e := exec.LookPath("bwrap")
		if e != nil {
			return nil, e
		}
		command = []string{bwrap, "--die-with-parent", "--new-session", "--unshare-all", "--cap-drop", "ALL", "--ro-bind", "/usr", "/usr", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"}
		for _, path := range []string{"/lib", "/lib64", "/bin"} {
			if _, e = os.Stat(path); e == nil {
				command = append(command, "--ro-bind", path, path)
			}
		}
		// 独立绑定业务输入，既不绑定采集器状态目录，也不暴露证书所在目录。
		command = append(command, "--ro-bind", input, input, "--bind", output, output, "--ro-bind", binary, binary, "--chdir", output, binary)
	} else {
		return nil, errors.New("操作系统不支持重放隔离")
	}
	command = append(command, args...)
	// 固定 shell 仅设置子进程资源限制；所有路径通过 argv 传递，不能成为 shell 代码。
	limits := `ulimit -c 0 && ulimit -t 90 && ulimit -f 32768`
	if runtime.GOOS == "linux" {
		limits += ` && ulimit -v 1572864`
	}
	argv := append([]string{"-c", limits + `; status=$?; if [ "$status" -ne 0 ]; then exit "$status"; fi; exec "$@"`, "starbeacon-replay"}, command...)
	cmd := exec.CommandContext(ctx, "/bin/sh", argv...)
	cmd.Dir = output
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "HOME=/nonexistent", "TMPDIR=" + output}
	cmd.WaitDelay = 2 * time.Second
	return cmd, nil
}

const replayProfile = `%YAML 1.1
---
plugins: []
unix-command:
  enabled: no
run-as: {}
stats:
  enabled: yes
  interval: 1
  decoder-events: true
  stream-events: true
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      ethernet: yes
      types:
        - alert:
            payload: no
            packet: no
            metadata: no
        - flow
        - anomaly
        - stats:
            totals: yes
            threads: no
            deltas: no
logging:
  default-log-level: notice
  outputs:
    - console:
        enabled: yes
flow:
  memcap: 32mb
  prealloc: 1000
stream:
  memcap: 32mb
  checksum-validation: yes
  reassembly:
    memcap: 64mb
    depth: 1mb
defrag:
  memcap: 16mb
file-store:
  enabled: no
`

func copyBounded(path, output string, max int64) (string, error) {
	f, e := os.Open(path)
	if e != nil {
		return "", e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Size() > max {
		return "", errors.New("检测配置或规则文件超出边界")
	}
	raw, e := io.ReadAll(io.LimitReader(f, max+1))
	if e != nil || int64(len(raw)) > max {
		return "", errors.New("检测配置或规则文件超出边界")
	}
	if e = durableFile(output, raw); e != nil {
		return "", e
	}
	return control.Digest(raw), nil
}
func (e *Engine) Replay(ctx context.Context, c control.Command) (json.RawMessage, string, error) {
	if !e.ReplayAvailable() {
		return nil, "replay_isolation_unavailable", errors.New("重放隔离环境不可用")
	}
	var p control.Replay
	if err := json.Unmarshal(c.Payload, &p); err != nil {
		return nil, "invalid_package", err
	}
	build, err := exec.CommandContext(ctx, e.Config.SuricataBinary, "-V").Output()
	if err != nil || !engineVersion.Match(build) {
		return nil, "engine_version_mismatch", errors.New("检测引擎版本不匹配")
	}
	dir, err := os.MkdirTemp(filepath.Dir(e.Config.StatePath), "replay-job-")
	if err != nil {
		return nil, "local_storage_unavailable", err
	}
	defer os.RemoveAll(dir)
	dir, err = filepath.EvalSymlinks(dir)
	if err != nil {
		return nil, "local_storage_unavailable", err
	}
	input := filepath.Join(dir, "input")
	output := filepath.Join(dir, "output")
	for _, path := range []string{input, output} {
		if err = os.Mkdir(path, 0700); err != nil {
			return nil, "local_storage_unavailable", err
		}
	}
	samplePath := filepath.Join(input, "sample.pcap")
	if err = e.downloadSample(ctx, c, p, samplePath); err != nil {
		return nil, "replay_sample_unavailable", err
	}
	metadata, err := replay.Inspect(ctx, samplePath)
	if err != nil {
		raw, _ := json.Marshal(map[string]any{"replay": "failed", "reason": err.Error(), "sample_id": p.SampleID})
		return raw, "replay_sample_invalid", err
	}
	normalizedSHA := ""
	header := make([]byte, 4)
	headerFile, err := os.Open(samplePath)
	if err != nil {
		return nil, "replay_sample_unavailable", err
	}
	_, err = io.ReadFull(headerFile, header)
	headerFile.Close()
	if err != nil {
		return nil, "replay_sample_invalid", err
	}
	if string(header) == "\x0a\x0d\x0d\x0a" {
		normalized := filepath.Join(input, "normalized.pcap")
		normalizedSHA, err = replay.NormalizeNG(ctx, samplePath, normalized)
		if err != nil {
			return nil, "replay_sample_invalid", err
		}
		samplePath = normalized
	}
	rulesPath := filepath.Join(input, "snapshot.rules")
	var ruleSHA string
	if p.RuleMode == "package" {
		if err = store.ValidateRules(p.Package.Text); err != nil {
			return nil, "invalid_package", err
		}
		err = durableFile(rulesPath, []byte(p.Package.Text))
		ruleSHA = p.Package.SHA256
	} else {
		if e.Config.SuricataRulesPath == "" {
			return nil, "registered_rules_unavailable", errors.New("未登记规则文件")
		}
		ruleSHA, err = copyBounded(e.Config.SuricataRulesPath, rulesPath, 64*1024*1024)
	}
	if err != nil {
		return nil, "registered_rules_unavailable", err
	}
	cfg := filepath.Join(input, "suricata.yaml")
	configSHA, err := copyBounded(e.Config.SuricataConfig, cfg, 2*1024*1024)
	if err != nil {
		return nil, "engine_not_configured", err
	}
	profile := replayProfile
	// 明确覆盖配置中的辅助文件路径，防止离线解析器读取作业目录之外的业务文件。
	for _, item := range []struct{ name, key string }{{"classification.config", "classification-file"}, {"reference.config", "reference-config-file"}, {"threshold.config", "threshold-file"}} {
		dest := filepath.Join(input, item.name)
		source := filepath.Join(filepath.Dir(e.Config.SuricataConfig), item.name)
		if _, err := os.Stat(source); errors.Is(err, os.ErrNotExist) {
			if err = durableFile(dest, nil); err != nil {
				return nil, "local_storage_unavailable", err
			}
		} else {
			if _, err = copyBounded(source, dest, 1024*1024); err != nil {
				return nil, "engine_not_configured", err
			}
		}
		profile += item.key + ": " + quote(dest) + "\n"
	}
	overlay := filepath.Join(input, "replay.yaml")
	if err = durableFile(overlay, []byte(profile)); err != nil {
		return nil, "local_storage_unavailable", err
	}
	args := []string{"-c", cfg, "--include", overlay, "-S", rulesPath, "-r", samplePath, "--runmode", "single", "--init-errors-fatal", "--strict-rule-keywords=all", "-l", output}
	call, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd, err := sandboxCommand(call, e.Config.SuricataBinary, dir, input, output, args)
	if err != nil {
		return nil, "replay_isolation_unavailable", err
	}
	var log boundedLog
	cmd.Stdout = &log
	cmd.Stderr = &log
	if err = cmd.Start(); err != nil {
		return nil, "replay_engine_failed", err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	limit := ""
	started := time.Now()
	waiting := true
	for waiting {
		select {
		case err = <-done:
			waiting = false
		case <-ticker.C:
			proc, e := process.NewProcess(int32(cmd.Process.Pid))
			if e == nil {
				if processTreeRSS(call, proc) > 1536*1024*1024 {
					limit = "memory"
					cancel()
				}
			}
			var total int64
			_ = filepath.WalkDir(output, func(path string, d os.DirEntry, e error) error {
				if e != nil {
					return nil
				}
				if !d.IsDir() {
					if i, e := d.Info(); e == nil {
						total += i.Size()
					}
				}
				return nil
			})
			if total > 64*1024*1024 {
				limit = "output"
				cancel()
			}
		}
	}
	result := map[string]any{"engine_version": "8.0.7", "sample_id": p.SampleID, "sample_sha256": p.SampleSHA256, "sample_bytes": p.SampleSize, "rule_mode": p.RuleMode, "rules_sha256": ruleSHA, "config_sha256": configSHA, "profile": "offline-bounded-v1", "profile_sha256": control.Digest([]byte(profile)), "duration_ms": time.Since(started).Milliseconds(), "log": boundedReplayText(string(log.data), 8192), "log_truncated": log.truncated || len(log.data) > 8192, "replay": "failed", "handshake_status": "not_verified", "checksum_validation": true, "reassembly_depth_bytes": 1048576, "isolation": runtime.GOOS}
	if p.Package != nil {
		result["package_id"] = p.Package.PackageID
		result["revision"] = p.Package.Revision
	}
	parsed, parseErr := readReplayEvents(filepath.Join(output, "eve.json"))
	result["sample_metadata"] = metadata
	if normalizedSHA != "" {
		result["normalized_pcap_sha256"] = normalizedSHA
		result["input_normalized"] = true
	}
	if parseErr == nil && parsed["packets_processed"] != strconv.FormatInt(metadata.Packets, 10) {
		parseErr = errors.New("引擎处理包数与样本包数不一致")
	}
	for key, value := range parsed {
		result[key] = value
	}
	code := ""
	if err != nil {
		code = "replay_engine_failed"
		if ctx.Err() != nil {
			code = "replay_timeout"
		}
		if limit != "" {
			code = "replay_resource_limit"
			result["resource_limit"] = limit
		}
	} else if parseErr != nil {
		err = parseErr
		code = "replay_result_incomplete"
	} else {
		result["replay"] = "completed"
	}
	raw, marshalErr := json.Marshal(result)
	if marshalErr != nil {
		return nil, "replay_result_incomplete", marshalErr
	}
	// 回执有固定预算，保留真实汇总并显式标记被截断的明细。
	for len(raw) > 60*1024 {
		if rows, ok := result["alerts"].([]map[string]any); ok && len(rows) > 0 {
			result["alerts"] = rows[:len(rows)-1]
			result["alerts_truncated"] = true
		} else if rows, ok := result["flow_samples"].([]map[string]any); ok && len(rows) > 0 {
			result["flow_samples"] = rows[:len(rows)-1]
			result["flow_samples_truncated"] = true
		} else if _, ok := result["stats"]; ok {
			delete(result, "stats")
			result["stats_truncated"] = true
		} else {
			return nil, "replay_result_incomplete", errors.New("执行回执超过容量限制")
		}
		raw, _ = json.Marshal(result)
	}
	return raw, code, err
}
func (e *Engine) downloadSample(ctx context.Context, c control.Command, p control.Replay, path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	sink := io.MultiWriter(f, h)
	var size int64
	if strings.HasPrefix(c.ID, "localtask_") {
		if e.LocalReplay == nil {
			return errors.New("本地样本存储不可用")
		}
		sample, err := e.LocalReplay.Sample(p.SampleID)
		if err != nil {
			return err
		}
		if sample.SHA256 != p.SampleSHA256 || sample.Size != p.SampleSize {
			return errors.New("样本摘要不匹配")
		}
		source, err := e.LocalReplay.Storage.Open(ctx, replay.Key(c.TenantID, p.SampleID))
		if err != nil {
			return err
		}
		defer source.Close()
		size, err = io.Copy(sink, io.LimitReader(source, p.SampleSize+1))
		if err != nil {
			return err
		}
	} else {
		if e.ReplayClient == nil {
			return errors.New("平台样本连接不可用")
		}
		call, cancel := context.WithTimeout(ctx, 90*time.Second)
		defer cancel()
		stream, err := e.ReplayClient.DownloadReplaySample(call, &sensorv1.ReplaySampleRequest{CommandId: c.ID, SampleId: p.SampleID})
		if err != nil {
			return err
		}
		for {
			chunk, err := stream.Recv()
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}
			if chunk.Offset != uint64(size) || len(chunk.Data) == 0 || len(chunk.Data) > 128*1024 || size+int64(len(chunk.Data)) > p.SampleSize {
				return errors.New("样本分块顺序或长度无效")
			}
			n, err := sink.Write(chunk.Data)
			if err != nil {
				return err
			}
			size += int64(n)
		}
	}
	if size != p.SampleSize || hex.EncodeToString(h.Sum(nil)) != p.SampleSHA256 {
		return errors.New("样本长度或 SHA-256 不匹配")
	}
	return f.Sync()
}
func readReplayEvents(path string) (map[string]any, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil || info.Size() > 64*1024*1024 {
		return nil, errors.New("重放结果超过边界")
	}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	alerts := []map[string]any{}
	flows := []map[string]any{}
	hits := map[string]int{}
	total, anomalies := 0, 0
	hitsTruncated := false
	var stats map[string]any
	for scanner.Scan() {
		var v map[string]any
		decoder := json.NewDecoder(strings.NewReader(scanner.Text()))
		decoder.UseNumber()
		if e := decoder.Decode(&v); e != nil {
			return nil, e
		}
		switch v["event_type"] {
		case "alert":
			total++
			a, _ := v["alert"].(map[string]any)
			sid := fmt.Sprint(a["signature_id"])
			if len(hits) < 200 || hits[sid] > 0 {
				hits[sid]++
			} else {
				hitsTruncated = true
			}
			if len(alerts) < 30 {
				row := map[string]any{}
				for _, key := range []string{"timestamp", "pcap_cnt", "src_ip", "src_port", "dest_ip", "dest_port", "proto", "app_proto", "ether"} {
					if value, ok := v[key]; ok {
						row[key] = value
					}
				}
				for _, key := range []string{"signature_id", "rev", "signature", "severity", "action"} {
					if value, ok := a[key]; ok {
						if text, ok := value.(string); ok {
							value = boundedReplayText(text, 1024)
						}
						row[key] = value
					}
				}
				alerts = append(alerts, row)
			}
		case "flow":
			if len(flows) < 10 {
				row := map[string]any{}
				for _, key := range []string{"timestamp", "src_ip", "dest_ip", "proto", "app_proto", "ether", "flow", "tcp"} {
					if value, ok := v[key]; ok {
						row[key] = value
					}
				}
				flows = append(flows, row)
			}
		case "anomaly":
			anomalies++
		case "stats":
			stats, _ = v["stats"].(map[string]any)
		}
	}
	if e = scanner.Err(); e != nil {
		return nil, e
	}
	if stats == nil {
		return nil, errors.New("缺少引擎完成统计")
	}
	decoder, _ := stats["decoder"].(map[string]any)
	packets, _ := decoder["pkts"].(json.Number)
	count, e := strconv.ParseUint(string(packets), 10, 64)
	if e != nil || count == 0 {
		return nil, errors.New("引擎未处理有效数据包")
	}
	return map[string]any{"alert_count": total, "alerts": alerts, "alerts_truncated": total > len(alerts), "rule_hits": hits, "rule_hits_truncated": hitsTruncated, "anomaly_count": anomalies, "flow_samples": flows, "stats": stats, "packets_processed": strconv.FormatUint(count, 10), "match_status": map[bool]string{true: "matched", false: "no_match"}[total > 0]}, nil
}

func boundedReplayText(text string, limit int) string {
	if len(text) <= limit {
		return text
	}
	for limit > 0 && text[limit]&0xc0 == 0x80 {
		limit--
	}
	return text[:limit] + "…"
}

// Linux 的 bwrap 监督进程与引擎子进程一起计入监视，不将监督进程的内存当作引擎占用。
func processTreeRSS(ctx context.Context, p *process.Process) uint64 {
	var rss uint64
	if m, e := p.MemoryInfoWithContext(ctx); e == nil {
		rss = m.RSS
	}
	children, _ := p.ChildrenWithContext(ctx)
	for _, child := range children {
		rss += processTreeRSS(ctx, child)
	}
	return rss
}
