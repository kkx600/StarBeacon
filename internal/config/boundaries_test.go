package config

import (
	"path/filepath"
	"strings"
	"testing"
)

func completeDevelopment(t *testing.T) {
	t.Helper()
	development(t)
	for _, k := range []string{"REPLAY_DIR", "REPLAY_BYTES", "REPLAY_BACKEND", "REPLAY_RETENTION_DAYS", "TASK_RETENTION_DAYS", "REPLAY_S3_ENDPOINT", "REPLAY_S3_BUCKET", "REPLAY_S3_ACCESS_KEY", "REPLAY_S3_SECRET_KEY", "REPLAY_S3_SECURE", "WAL_BYTES", "MCP_ISSUER", "MCP_INTROSPECTION_URL", "MCP_CLIENT_ID", "MCP_CLIENT_SECRET", "STATE_PATH", "CAPTURE_MANAGED", "CAPTURE_SPOOL_BYTES", "CAPTURE_ROTATE_BYTES"} {
		t.Setenv("SB_"+k, "")
	}
	t.Setenv("SB_TRUSTED_PROXY_CIDRS", "")
	t.Setenv("SB_MCP_CLIENT_SECRET_FILE", "")
	t.Setenv("SB_TENANT_ID", "tenant_bound")
	t.Setenv("SB_SENSOR_ID", "sensor_bound")
	t.Setenv("SB_REGISTRATION_ID", "reg_bound")
	t.Setenv("SB_LOCAL_PASSWORD", "test-local-password-only")
}

func completeProduction(t *testing.T) {
	t.Helper()
	completeDevelopment(t)
	for k, v := range map[string]string{"MODE": "production", "NATS_REPLICAS": "3", "DATABASE_URL": "postgres://app@db/db?sslmode=verify-full", "NATS_URL": "tls://bus:4222", "REDIS_URL": "rediss://cache:6379", "ES_URL": "https://search:9200", "ES_API_KEY": "test-api-key-only", "ALLOWED_ORIGIN": "https://console.example"} {
		t.Setenv("SB_"+k, v)
	}
}

func TestRoleDefaultsAndConfigurationFailureBoundaries(t *testing.T) {
	for _, role := range []string{"platform", "ingest", "worker", "agent"} {
		t.Run(role, func(t *testing.T) {
			completeDevelopment(t)
			c, err := Load(role)
			if err != nil {
				t.Fatal(err)
			}
			if c.TaskRetentionDays != 180 || c.ReplayRetentionDays != 180 || c.HeartbeatInterval.Seconds() != 10 || c.ReplayBytes != 1073741824 {
				t.Fatal("默认保留期、容量或心跳错误", c)
			}
			if role == "agent" && c.CookieName != "starbeacon_collector_session" {
				t.Fatal("采集器会话未隔离")
			}
			completeProduction(t)
			c, err = Load(role)
			if err != nil {
				t.Fatal(err)
			}
			if !filepath.IsAbs(c.ReplayDir) {
				t.Fatal("生产存储目录不是绝对路径")
			}
		})
	}
	cases := []struct {
		name, role, key, value, message string
		production                      bool
	}{
		{"unknown_role", "collector", "", "", "运行角色", false},
		{"unknown_mode", "platform", "MODE", "test", "SB_MODE", false},
		{"replay_capacity", "agent", "REPLAY_BYTES", "invalid", "SB_REPLAY_BYTES", false},
		{"replay_capacity_small", "agent", "REPLAY_BYTES", "1024", "SB_REPLAY_BYTES", false},
		{"capture_managed_invalid", "agent", "CAPTURE_MANAGED", "yes", "SB_CAPTURE_MANAGED", false},
		{"capture_spool_small", "agent", "CAPTURE_SPOOL_BYTES", "1024", "采集缓冲额度", false},
		{"capture_spool_invalid", "agent", "CAPTURE_SPOOL_BYTES", "invalid", "采集缓冲额度", false},
		{"capture_rotate_small", "agent", "CAPTURE_ROTATE_BYTES", "1024", "轮转阈值", false},
		{"capture_rotate_invalid", "agent", "CAPTURE_ROTATE_BYTES", "invalid", "轮转阈值", false},
		{"capture_rotate_large", "agent", "CAPTURE_ROTATE_BYTES", "1073741824", "轮转阈值", false},
		{"retention_zero", "agent", "REPLAY_RETENTION_DAYS", "0", "保留期", false},
		{"retention_large", "platform", "REPLAY_RETENTION_DAYS", "3651", "保留期", false},
		{"retention_invalid", "platform", "REPLAY_RETENTION_DAYS", "invalid", "保留期", false},
		{"task_retention_zero", "agent", "TASK_RETENTION_DAYS", "0", "任务保留期", false},
		{"task_retention_large", "agent", "TASK_RETENTION_DAYS", "3651", "任务保留期", false},
		{"task_retention_invalid", "agent", "TASK_RETENTION_DAYS", "invalid", "任务保留期", false},
		{"backend_unknown", "platform", "REPLAY_BACKEND", "zip", "存储类型", false},
		{"s3_incomplete", "platform", "REPLAY_BACKEND", "s3", "S3", false},
		{"wal_capacity", "agent", "WAL_BYTES", "-1", "SB_WAL_BYTES", false},
		{"stream_capacity", "ingest", "STREAM_BYTES", "1024", "SB_STREAM_BYTES", false},
		{"replica_invalid", "worker", "NATS_REPLICAS", "6", "SB_NATS_REPLICAS", false},
		{"missing_database", "platform", "DATABASE_URL", "", "DATABASE_URL", false},
		{"missing_nats", "ingest", "NATS_URL", "", "NATS_URL", false},
		{"missing_es", "worker", "ES_URL", "", "ES_URL", false},
		{"missing_redis", "platform", "REDIS_URL", "", "Redis", false},
		{"missing_ca", "agent", "TLS_CA", "", "mTLS", false},
		{"missing_identity", "agent", "SENSOR_ID", "", "身份", false},
		{"password_short", "agent", "LOCAL_PASSWORD", "short", "密码", false},
		{"password_long", "agent", "LOCAL_PASSWORD", strings.Repeat("a", 73), "密码", false},
		{"missing_origin", "agent", "ALLOWED_ORIGIN", "", "Origin", false},
		{"invalid_listener", "platform", "HTTP_ADDR", "127.0.0.1", "监听地址", false},
		{"unsafe_trusted_proxy", "platform", "TRUSTED_PROXY_CIDRS", "0.0.0.0/0", "可信代理", false},
		{"relative_replay", "agent", "REPLAY_DIR", "relative", "绝对路径", true},
		{"filesystem_production", "platform", "REPLAY_BACKEND", "filesystem", "S3", true},
		{"too_few_replicas", "worker", "NATS_REPLICAS", "1", "副本", true},
		{"plaintext_es", "platform", "ES_URL", "http://search:9200", "TLS", true},
		{"plaintext_pg", "platform", "DATABASE_URL", "postgres://app@db/db?sslmode=require", "verify-full", true},
		{"missing_es_key", "platform", "ES_API_KEY", "", "API Key", true},
		{"worker_certificate", "worker", "TLS_KEY", "", "证书和私钥", true},
		{"partial_mcp", "platform", "MCP_ISSUER", "https://idp.example", "MCP", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.production {
				completeProduction(t)
			} else {
				completeDevelopment(t)
			}
			if tc.key != "" {
				t.Setenv("SB_"+tc.key, tc.value)
			}
			if _, err := Load(tc.role); err == nil || !strings.Contains(err.Error(), tc.message) {
				t.Fatalf("无效配置未按预期拒绝：%v", err)
			}
		})
	}
	t.Run("complete_s3_and_mcp", func(t *testing.T) {
		completeProduction(t)
		for k, v := range map[string]string{"REPLAY_BACKEND": "s3", "REPLAY_S3_ENDPOINT": "objects.example", "REPLAY_S3_BUCKET": "samples", "REPLAY_S3_ACCESS_KEY": "access-only", "REPLAY_S3_SECRET_KEY": "secret-only", "MCP_ISSUER": "https://idp.example", "MCP_INTROSPECTION_URL": "https://idp.example/introspect", "MCP_CLIENT_ID": "resource", "MCP_CLIENT_SECRET": "test-client-secret-only"} {
			t.Setenv("SB_"+k, v)
		}
		if _, err := Load("platform"); err != nil {
			t.Fatal(err)
		}
		t.Setenv("SB_REPLAY_S3_SECURE", "false")
		if _, err := Load("platform"); err == nil {
			t.Fatal("生产 S3 未启用 TLS 仍启动")
		}
	})
}
