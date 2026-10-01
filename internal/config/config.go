// Package config 校验运行角色的环境配置，生产模式不接受隐式开发凭据。
package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
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
	}
	if c.Mode != "development" && c.Mode != "production" {
		return c, fmt.Errorf("SB_MODE 必须为 development 或 production")
	}
	var err error
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
