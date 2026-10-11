package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/shirou/gopsutil/v4/process"
)

// 装载检查和重放使用相同的隔离与预算，不向原生引擎暴露采集器状态目录。
func executeBounded(ctx context.Context, binary, job, input, output string, args []string) (boundedLog, int64, string, error) {
	var log boundedLog
	call, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	cmd, err := sandboxCommand(call, binary, job, input, output, args)
	if err != nil {
		return log, 0, "isolation", err
	}
	cmd.Stdout, cmd.Stderr = &log, &log
	started := time.Now()
	if err = cmd.Start(); err != nil {
		return log, 0, "isolation", err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	limit := ""
	for {
		select {
		case err = <-done:
			if call.Err() != nil && limit == "" {
				limit = "time"
			}
			if limit != "" && err == nil {
				err = call.Err()
			}
			return log, time.Since(started).Milliseconds(), limit, err
		case <-ticker.C:
			proc, err := process.NewProcess(int32(cmd.Process.Pid))
			if err == nil && processTreeRSS(call, proc) > 1536*1024*1024 {
				limit = "memory"
				cancel()
			}
			var total int64
			_ = filepath.WalkDir(output, func(_ string, entry os.DirEntry, err error) error {
				if err == nil && !entry.IsDir() {
					if info, err := entry.Info(); err == nil {
						total += info.Size()
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
}

type inspectionFile struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
}

func offlineConfig(source, input string) (string, string, error) {
	configSHA, err := copyBounded(source, filepath.Join(input, "suricata.yaml"), 2*1024*1024)
	if err != nil {
		return "", "", err
	}
	profile := replayProfile
	var files []inspectionFile
	for _, item := range []struct{ name, key string }{{"classification.config", "classification-file"}, {"reference.config", "reference-config-file"}, {"threshold.config", "threshold-file"}} {
		destination := filepath.Join(input, item.name)
		origin := filepath.Join(filepath.Dir(source), item.name)
		digest := control.Digest(nil)
		if _, err := os.Stat(origin); os.IsNotExist(err) {
			if err = durableFile(destination, nil); err != nil {
				return "", "", err
			}
		} else if digest, err = copyBounded(origin, destination, 1024*1024); err != nil {
			return "", "", err
		}
		files = append(files, inspectionFile{Name: item.name, SHA256: digest})
		profile += item.key + ": " + quote(destination) + "\n"
	}
	if err = durableFile(filepath.Join(input, "replay.yaml"), []byte(profile)); err != nil {
		return "", "", err
	}
	// 原生 YAML 需要绝对路径，资格摘要只绑定其固定剖面及辅助文件字节，不能绑定临时目录。
	canonical, err := json.Marshal(struct {
		Profile string           `json:"profile"`
		Files   []inspectionFile `json:"files"`
	}{Profile: replayProfile, Files: files})
	if err != nil {
		return "", "", err
	}
	return configSHA, string(canonical), nil
}
