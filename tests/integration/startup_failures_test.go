//go:build integration

package integration

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/app"
	"github.com/kkx600/StarBeacon/internal/config"
	"github.com/kkx600/StarBeacon/internal/replay"
)

// 使用真实数据库与服务连接验证启动门控，所有文件和端口均为本用例所有。
func TestRoleStartupRejectsUnavailableDependenciesAndOwnerCredentials(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	f := newIsolatedDatabase(t, ctx)
	base := config.Config{Mode: "development", DatabaseURL: f.RuntimeDSN, ESURL: os.Getenv("SB_ES_URL"), ESAPIKey: os.Getenv("SB_ES_API_KEY"), RedisURL: os.Getenv("SB_REDIS_URL"), NATSURL: os.Getenv("SB_NATS_URL"), NATSNamespace: "startup_owned", Replicas: 1, StreamBytes: 1 << 20, HTTPAddr: "127.0.0.1:0", GRPCAddr: "127.0.0.1:0", ReplayBytes: replay.MaxSampleBytes}
	for _, mode := range []string{"database_owner", "es_invalid", "es_unavailable", "redis_invalid", "redis_unavailable", "signer", "sample_quota", "sample_directory", "s3_endpoint", "mcp_configuration", "queue_namespace"} {
		t.Run(mode, func(t *testing.T) {
			c, role := base, "platform"
			dir := t.TempDir()
			c.ReplayDir = filepath.Join(dir, "samples")
			switch mode {
			case "database_owner":
				c.DatabaseURL = f.OwnerDSN
			case "es_invalid":
				c.ESURL = "http://%invalid"
			case "es_unavailable":
				c.ESURL = "http://" + availableAddress(t)
			case "redis_invalid":
				c.RedisURL = "redis://%invalid"
			case "redis_unavailable":
				c.RedisURL = "redis://" + availableAddress(t) + "/0"
			case "signer":
				c.CommandSigningKey = filepath.Join(dir, "missing.key")
			case "sample_quota":
				c.ReplayBackend, c.ReplayBytes = "filesystem", 1
			case "sample_directory":
				c.ReplayBackend = "filesystem"
				require(t, os.WriteFile(c.ReplayDir, []byte("owned"), 0600))
			case "s3_endpoint":
				c.ReplayBackend, c.ReplayS3Endpoint, c.ReplayS3Bucket = "s3", "invalid:endpoint:format", "sample-bucket"
			case "mcp_configuration":
				c.MCPIssuer = "invalid-issuer"
			case "queue_namespace":
				role, c.NATSNamespace = "ingest", "id.invalid"
			}
			work, stop := context.WithTimeout(ctx, 4*time.Second)
			defer stop()
			if e := app.Run(work, role, c); e == nil || work.Err() != nil {
				t.Fatal("启动依赖错误没有被及时识别", e)
			}
		})
	}
	require(t, f.Runtime.VerifyRuntimeRole(ctx))
}
