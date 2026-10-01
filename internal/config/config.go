// Package config 校验运行角色的环境配置，生产模式不接受隐式开发凭据。
package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

type Config struct {
	NATSNamespace                                                             string
	WALBytes                                                                  uint64
	Mode, HTTPAddr, GRPCAddr, DatabaseURL, NATSURL, RedisURL, ESURL, ESAPIKey string
	TLSCA, TLSCert, TLSKey, AllowedOrigin, TenantID, SensorID, RegistrationID string
	PlatformAddr, IngestAddr, EVEPath, StatePath, LocalPassword, CookieName   string
	StreamBytes                                                               int64
	Replicas                                                                  int
	HeartbeatInterval                                                         time.Duration
	CommandSigningKey, CommandPublicKey                                       string
	SuricataBinary, SuricataConfig, SuricataSocket, SuricataRulesPath         string
	AllowRuleApply                                                            bool
	SuricataPIDFile                                                           string
	ReplayDir, ReplayBackend, ReplayS3Endpoint, ReplayS3Bucket                string
	ReplayS3AccessKey, ReplayS3SecretKey                                      string
	ReplayS3Secure                                                            bool
	ReplayBytes                                                               int64
	ReplayRetentionDays                                                       int
}

func env(key, fallback string) string {
	if s := os.Getenv("SB_" + key); s != "" {
		return s
	}
	return fallback
}

func Load(role string) (Config, error) {
	httpAddr, grpcAddr := "127.0.0.1:28080", "127.0.0.1:29091"
	switch role {
	case "agent":
		httpAddr = "127.0.0.1:28081"
	case "ingest":
		httpAddr = "127.0.0.1:28180"
		grpcAddr = "127.0.0.1:29090"
	case "worker":
		httpAddr = "127.0.0.1:28181"
	}
	c := Config{
		NATSNamespace: env("NATS_NAMESPACE", "sb"),
		Mode:          env("MODE", "production"), HTTPAddr: env("HTTP_ADDR", httpAddr), GRPCAddr: env("GRPC_ADDR", grpcAddr),
		DatabaseURL: env("DATABASE_URL", ""), NATSURL: env("NATS_URL", ""), RedisURL: env("REDIS_URL", ""), ESURL: env("ES_URL", ""), ESAPIKey: env("ES_API_KEY", ""),
		TLSCA: env("TLS_CA", ""), TLSCert: env("TLS_CERT", ""), TLSKey: env("TLS_KEY", ""), AllowedOrigin: env("ALLOWED_ORIGIN", ""),
		TenantID: env("TENANT_ID", ""), SensorID: env("SENSOR_ID", ""), RegistrationID: env("REGISTRATION_ID", ""),
		PlatformAddr: env("PLATFORM_ADDR", "127.0.0.1:29091"), IngestAddr: env("INGEST_ADDR", "127.0.0.1:29090"),
		EVEPath: env("EVE_PATH", "/var/log/suricata/eve.json"), StatePath: env("STATE_PATH", "/var/lib/starbeacon/agent.db"), LocalPassword: env("LOCAL_PASSWORD", ""),
		CookieName: "starbeacon_session", HeartbeatInterval: 10 * time.Second,
		CommandSigningKey: env("COMMAND_SIGNING_KEY", ""), CommandPublicKey: env("COMMAND_PUBLIC_KEY", ""),
		SuricataBinary: env("SURICATA_BINARY", ""), SuricataConfig: env("SURICATA_CONFIG", ""),
		SuricataSocket: env("SURICATA_SOCKET", ""), SuricataRulesPath: env("SURICATA_RULES_PATH", ""),
		AllowRuleApply:  env("ALLOW_RULE_APPLY", "false") == "true",
		SuricataPIDFile: env("SURICATA_PID_FILE", ""),
		ReplayDir:       env("REPLAY_DIR", ".local/replay-"+role), ReplayBackend: env("REPLAY_BACKEND", ""),
		ReplayS3Endpoint: env("REPLAY_S3_ENDPOINT", ""), ReplayS3Bucket: env("REPLAY_S3_BUCKET", ""),
		ReplayS3AccessKey: env("REPLAY_S3_ACCESS_KEY", ""), ReplayS3SecretKey: env("REPLAY_S3_SECRET_KEY", ""), ReplayS3Secure: env("REPLAY_S3_SECURE", "true") == "true",
	}
	if c.Mode != "development" && c.Mode != "production" {
		return c, fmt.Errorf("SB_MODE 必须为 development 或 production")
	}
	if c.Mode == "production" {
		fallback := "/var/lib/starbeacon/replay-staging"
		if role == "agent" {
			fallback = filepath.Join(filepath.Dir(c.StatePath), "replay")
		}
		c.ReplayDir = env("REPLAY_DIR", fallback)
		if !filepath.IsAbs(c.ReplayDir) {
			return c, fmt.Errorf("生产重放目录必须为绝对路径")
		}
	}
	var err error
	c.ReplayBytes, err = strconv.ParseInt(env("REPLAY_BYTES", "1073741824"), 10, 64)
	if err != nil || c.ReplayBytes < 100*1024*1024 {
		return c, fmt.Errorf("SB_REPLAY_BYTES 至少为 100 MiB")
	}
	c.ReplayRetentionDays, err = strconv.Atoi(env("REPLAY_RETENTION_DAYS", "180"))
	if err != nil || c.ReplayRetentionDays < 1 || c.ReplayRetentionDays > 3650 {
		return c, fmt.Errorf("样本保留期必须为 1–3650 天")
	}
	if role == "platform" {
		if c.Mode == "development" && c.ReplayBackend == "" {
			c.ReplayBackend = "filesystem"
		}
		if c.ReplayBackend != "" && c.ReplayBackend != "filesystem" && c.ReplayBackend != "s3" {
			return c, fmt.Errorf("重放存储类型无效")
		}
		if c.Mode == "production" && c.ReplayBackend == "filesystem" {
			return c, fmt.Errorf("生产平台重放样本要求 S3 对象存储")
		}
		if c.ReplayBackend == "s3" && (c.ReplayS3Endpoint == "" || c.ReplayS3Bucket == "" || c.ReplayS3AccessKey == "" || c.ReplayS3SecretKey == "" || (c.Mode == "production" && !c.ReplayS3Secure)) {
			return c, fmt.Errorf("S3 样本存储配置不完整或未启用 TLS")
		}
	}
	c.WALBytes, err = strconv.ParseUint(env("WAL_BYTES", "268435456"), 10, 64)
	if err != nil || c.WALBytes < 4*1024*1024 {
		return c, fmt.Errorf("SB_WAL_BYTES 必须至少为 4 MiB")
	}
	c.StreamBytes, err = strconv.ParseInt(env("STREAM_BYTES", "268435456"), 10, 64)
	if err != nil || c.StreamBytes < 1024*1024 {
		return c, fmt.Errorf("SB_STREAM_BYTES 不合法")
	}
	c.Replicas, err = strconv.Atoi(env("NATS_REPLICAS", "3"))
	if err != nil || c.Replicas < 1 || c.Replicas > 5 {
		return c, fmt.Errorf("SB_NATS_REPLICAS 不合法")
	}
	if c.Mode == "production" && c.Replicas < 3 && (role == "ingest" || role == "worker") {
		return c, fmt.Errorf("生产接入要求至少 3 个 JetStream 副本")
	}
	if role == "platform" || role == "ingest" || role == "ctl" {
		if c.DatabaseURL == "" {
			return c, fmt.Errorf("缺少 SB_DATABASE_URL")
		}
	}
	if role == "ingest" || role == "worker" {
		if c.NATSURL == "" {
			return c, fmt.Errorf("缺少 SB_NATS_URL")
		}
	}
	if role == "platform" || role == "worker" {
		if c.ESURL == "" {
			return c, fmt.Errorf("缺少 SB_ES_URL")
		}
	}
	if role == "platform" {
		if c.RedisURL == "" || c.AllowedOrigin == "" {
			return c, fmt.Errorf("缺少 Redis 或前端 Origin 配置")
		}
	}
	if role == "agent" || role == "ingest" || role == "platform" {
		if c.TLSCA == "" || c.TLSCert == "" || c.TLSKey == "" {
			return c, fmt.Errorf("缺少 mTLS CA、证书或私钥路径")
		}
	}
	if role == "agent" {
		c.CookieName = "starbeacon_collector_session"
		if c.TenantID == "" || c.SensorID == "" || c.RegistrationID == "" {
			return c, fmt.Errorf("缺少采集器身份")
		}
		if len(c.LocalPassword) < 12 || len(c.LocalPassword) > 72 {
			return c, fmt.Errorf("采集器本地管理密码必须为 12–72 字节")
		}
		if c.AllowedOrigin == "" {
			return c, fmt.Errorf("缺少采集器前端 Origin")
		}
	}
	if c.Mode == "production" {
		if role != "ctl" && (c.TLSCert == "" || c.TLSKey == "") {
			return c, fmt.Errorf("生产 HTTP 服务要求证书和私钥")
		}
		for _, s := range []string{c.ESURL, c.RedisURL, c.NATSURL, c.AllowedOrigin} {
			if s != "" {
				u, e := url.Parse(s)
				if e != nil || !(u.Scheme == "https" || u.Scheme == "rediss" || u.Scheme == "tls") {
					return c, fmt.Errorf("生产依赖与前端地址要求 TLS")
				}
			}
		}
		if c.DatabaseURL != "" {
			u, e := url.Parse(c.DatabaseURL)
			if e != nil || u.Query().Get("sslmode") != "verify-full" {
				return c, fmt.Errorf("生产 PostgreSQL 要求 sslmode=verify-full")
			}
		}
		if c.ESURL != "" && c.ESAPIKey == "" {
			return c, fmt.Errorf("生产 Elasticsearch 要求 API Key")
		}
	}
	if c.HTTPAddr != "" {
		host, _, e := net.SplitHostPort(c.HTTPAddr)
		if e != nil {
			return c, fmt.Errorf("HTTP 监听地址不合法")
		}
		if !net.ParseIP(host).IsLoopback() {
			return c, fmt.Errorf("HTTP 仅允许回环监听；外部访问请通过反向代理")
		}
	}
	if c.AllowedOrigin != "" {
		u, e := url.Parse(c.AllowedOrigin)
		if e != nil || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "http" && u.Scheme != "https") {
			return c, fmt.Errorf("Origin 必须是完整来源，不含路径")
		}
	}
	return c, nil
}
