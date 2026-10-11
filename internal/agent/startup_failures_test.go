package agent

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/config"
	"github.com/kkx600/StarBeacon/internal/replay"
)

func TestAgentStartupDependencyFailureLeavesWALReopenable(t *testing.T) {
	for _, mode := range []string{"wal_directory", "signer_key", "sample_quota", "sample_directory", "certificate"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			c := config.Config{StatePath: filepath.Join(dir, "state.db"), TenantID: "tenant_startup", SensorID: "sensor_startup", RegistrationID: "registration_startup", WALBytes: 4 << 20, ReplayDir: filepath.Join(dir, "samples"), ReplayBytes: replay.MaxSampleBytes, Mode: "development"}
			switch mode {
			case "wal_directory":
				c.StatePath = dir
			case "signer_key":
				c.CommandPublicKey = filepath.Join(dir, "missing.pub")
			case "sample_quota":
				c.ReplayBytes = 1
			case "sample_directory":
				if err := os.WriteFile(c.ReplayDir, []byte("owned"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if err := Run(ctx, c); err == nil {
				t.Fatal("采集器依赖不可用仍报告启动正常")
			}
			if mode != "wal_directory" {
				wal, err := OpenWAL(c.StatePath, c.TenantID, c.SensorID, c.RegistrationID, c.WALBytes)
				if err != nil {
					t.Fatal("启动失败未释放本地队列", err)
				}
				if err := wal.Close(); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
