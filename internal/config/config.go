// Package config 校验运行角色的环境配置，生产模式不接受隐式开发凭据。
package config

import (
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/kkx600/StarBeacon/internal/clientip"
)

type Config struct {
	HTTPClientIPs                                                             clientip.Policy
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
	BPFCompilerBinary                                                         string
	CaptureManaged                                                            bool
	CaptureSpoolBytes                                                         int64
	CaptureRotateBytes                                                        int64
	PacketCapture                                                             bool
	PacketDir, PacketBackend, PacketCodec                                     string
	PacketSpoolBytes, PacketSegmentBytes, PacketStorageBytes                  int64
	PacketRotateInterval                                                      time.Duration
	ReplayDir, ReplayBackend, ReplayS3Endpoint, ReplayS3Bucket                string
	ReplayS3AccessKey, ReplayS3SecretKey                                      string
	ReplayS3Secure                                                            bool
	ReplayBytes                                                               int64
	ReplayRetentionDays                                                       int
	TaskRetentionDays                                                         int
	CredentialKey, OutboundNetworks, OutboundCA                               string
	MCPIssuer, MCPIntrospectionURL, MCPClientID, MCPClientSecret              string
	ResponseConnectorsFile                                                    string
	SyslogSourcesFile                                                         string
	ProbeCAURL, ProbeCARoot, ProbeCAProvisioner, ProbeCAJWK                   string
	ProbeCertificateLifetime                                                  time.Duration
	IdentityDir, IdentityRoot, HTTPTLSCert, HTTPTLSKey                        string
}

func Load(role string) (Config, error) {
	if role != "platform" && role != "ingest" && role != "worker" && role != "agent" {
		return Config{}, fmt.Errorf("运行角色无效")
	}
	secrets, e := fileSecrets()
	if e != nil {
		return Config{}, e
	}
	env := func(key, fallback string) string {
		if value, ok := secrets[key]; ok {
			return value
		}
		if value := os.Getenv("SB_" + key); value != "" {
			return value
		}
		return fallback
	}
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
		AllowRuleApply:    env("ALLOW_RULE_APPLY", "false") == "true",
		SuricataPIDFile:   env("SURICATA_PID_FILE", ""),
		BPFCompilerBinary: env("BPF_COMPILER", "/usr/sbin/tcpdump"),
		CaptureManaged:    env("CAPTURE_MANAGED", "false") == "true",
		ReplayDir:         env("REPLAY_DIR", ".local/replay-"+role), ReplayBackend: env("REPLAY_BACKEND", ""),
		ReplayS3Endpoint: env("REPLAY_S3_ENDPOINT", ""), ReplayS3Bucket: env("REPLAY_S3_BUCKET", ""),
		ReplayS3AccessKey: env("REPLAY_S3_ACCESS_KEY", ""), ReplayS3SecretKey: env("REPLAY_S3_SECRET_KEY", ""), ReplayS3Secure: env("REPLAY_S3_SECURE", "true") == "true",
		CredentialKey: env("CREDENTIAL_KEY", ""), OutboundNetworks: env("OUTBOUND_PRIVATE_NETWORKS", ""), OutboundCA: env("OUTBOUND_CA", ""),
		MCPIssuer: env("MCP_ISSUER", ""), MCPIntrospectionURL: env("MCP_INTROSPECTION_URL", ""), MCPClientID: env("MCP_CLIENT_ID", ""), MCPClientSecret: env("MCP_CLIENT_SECRET", ""),
		ResponseConnectorsFile: env("RESPONSE_CONNECTORS_FILE", ""),
		SyslogSourcesFile:      env("SYSLOG_SOURCES_FILE", ""),
		ProbeCAURL:             env("PROBE_CA_URL", ""), ProbeCARoot: env("PROBE_CA_ROOT", ""), ProbeCAProvisioner: env("PROBE_CA_PROVISIONER", ""), ProbeCAJWK: env("PROBE_CA_JWK", ""),
		IdentityDir: env("IDENTITY_DIR", ""), IdentityRoot: env("IDENTITY_ROOT", ""), HTTPTLSCert: env("HTTP_TLS_CERT", ""), HTTPTLSKey: env("HTTP_TLS_KEY", ""),
	}
	certSeconds, certErr := strconv.Atoi(env("PROBE_CERTIFICATE_SECONDS", "86400"))
	if certErr != nil || certSeconds < 300 || certSeconds > 604800 {
		return c, fmt.Errorf("探针证书有效期须为 300–604800 秒")
	}
	c.ProbeCertificateLifetime = time.Duration(certSeconds) * time.Second
	if c.ProbeCAURL != "" || c.ProbeCARoot != "" || c.ProbeCAProvisioner != "" || c.ProbeCAJWK != "" {
		if role != "platform" || c.ProbeCAURL == "" || c.ProbeCARoot == "" || c.ProbeCAProvisioner == "" || c.ProbeCAJWK == "" || !filepath.IsAbs(c.ProbeCARoot) || !filepath.IsAbs(c.ProbeCAJWK) {
			return c, fmt.Errorf("独立 CA 仅在平台配置，要求完整 HTTPS 来源及绝对信任根和 JWK 路径")
		}
		u, err := url.Parse(c.ProbeCAURL)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
			return c, fmt.Errorf("独立 CA 地址须为 HTTPS 来源")
		}
	}
	if (c.HTTPTLSCert == "") != (c.HTTPTLSKey == "") {
		return c, fmt.Errorf("HTTP 服务证书和私钥须同时配置")
	}
	if c.IdentityDir != "" {
		if role != "agent" || !filepath.IsAbs(c.IdentityDir) || !filepath.IsAbs(c.IdentityRoot) || c.TLSCert != "" || c.TLSKey != "" {
			return c, fmt.Errorf("托管探针身份要求绝对目录和独立身份信任根，不能同时指定静态客户端证书")
		}
		c.TLSCert = filepath.Join(c.IdentityDir, "identity.pem")
		c.TLSKey = c.TLSCert
		if c.Mode == "production" && c.HTTPTLSCert == "" {
			return c, fmt.Errorf("托管身份的本地 HTTPS 服务要求独立服务证书")
		}
	}
	if c.IdentityRoot != "" && c.IdentityDir == "" {
		return c, fmt.Errorf("身份信任根要求同时配置托管身份目录")
	}
	if c.Mode != "development" && c.Mode != "production" {
		return c, fmt.Errorf("SB_MODE 必须为 development 或 production")
	}
	if c.SyslogSourcesFile != "" && (role != "agent" || !filepath.IsAbs(c.SyslogSourcesFile)) {
		return c, fmt.Errorf("Syslog 来源配置仅接受采集器的绝对路径")
	}
	if c.ResponseConnectorsFile != "" && (role != "agent" || !filepath.IsAbs(c.ResponseConnectorsFile)) {
		return c, fmt.Errorf("联动连接器仅在采集器配置，配置文件须为绝对路径")
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
	c.HTTPClientIPs, err = clientip.Parse(env("TRUSTED_PROXY_CIDRS", ""))
	if err != nil {
		return c, err
	}
	c.ReplayBytes, err = strconv.ParseInt(env("REPLAY_BYTES", "1073741824"), 10, 64)
	if err != nil || c.ReplayBytes < 100*1024*1024 {
		return c, fmt.Errorf("SB_REPLAY_BYTES 至少为 100 MiB")
	}
	c.ReplayRetentionDays, err = strconv.Atoi(env("REPLAY_RETENTION_DAYS", "180"))
	if err != nil || c.ReplayRetentionDays < 1 || c.ReplayRetentionDays > 3650 {
		return c, fmt.Errorf("样本保留期必须为 1–3650 天")
	}
	c.TaskRetentionDays, err = strconv.Atoi(env("TASK_RETENTION_DAYS", "180"))
	if err != nil || c.TaskRetentionDays < 1 || c.TaskRetentionDays > 3650 {
		return c, fmt.Errorf("任务保留期必须为 1–3650 天")
	}
	if value := env("CAPTURE_MANAGED", "false"); value != "true" && value != "false" {
		return c, fmt.Errorf("SB_CAPTURE_MANAGED 必须为 true 或 false")
	}
	c.CaptureSpoolBytes, err = strconv.ParseInt(env("CAPTURE_SPOOL_BYTES", "1073741824"), 10, 64)
	if err != nil || c.CaptureSpoolBytes < 100*1024*1024 {
		return c, fmt.Errorf("采集缓冲额度至少为 100 MiB")
	}
	c.CaptureRotateBytes, err = strconv.ParseInt(env("CAPTURE_ROTATE_BYTES", strconv.FormatInt(min(64*1024*1024, c.CaptureSpoolBytes/2), 10)), 10, 64)
	if err != nil || c.CaptureRotateBytes < 1024*1024 || c.CaptureRotateBytes > c.CaptureSpoolBytes/2 {
		return c, fmt.Errorf("EVE 轮转阈值至少为 1 MiB，且不超过采集缓冲额度的一半")
	}
	packetDefault := "false"
	if role == "agent" && c.CaptureManaged {
		packetDefault = "true"
	}
	packetEnabled := env("PACKET_CAPTURE", packetDefault)
	if packetEnabled != "true" && packetEnabled != "false" {
		return c, fmt.Errorf("SB_PACKET_CAPTURE 必须为 true 或 false")
	}
	c.PacketCapture = packetEnabled == "true"
	if c.PacketCapture && (role != "agent" || !c.CaptureManaged) {
		return c, fmt.Errorf("原包捕获要求采集器托管网卡配置")
	}
	c.PacketDir = env("PACKET_DIR", filepath.Join(filepath.Dir(c.StatePath), "packets"))
	if role == "platform" {
		c.PacketDir = env("PACKET_DIR", filepath.Join(filepath.Dir(c.ReplayDir), "packet-archives-platform"))
	}
	if c.Mode == "production" && !filepath.IsAbs(c.PacketDir) {
		return c, fmt.Errorf("生产原包目录必须为绝对路径")
	}
	c.PacketCodec = env("PACKET_CODEC", "zstd")
	if c.PacketCodec != "zstd" && c.PacketCodec != "none" {
		return c, fmt.Errorf("原包编码仅支持 zstd 或 none")
	}
	c.PacketSpoolBytes, err = strconv.ParseInt(env("PACKET_SPOOL_BYTES", "1073741824"), 10, 64)
	if err != nil || c.PacketSpoolBytes < 100*1024*1024 {
		return c, fmt.Errorf("原包暂存额度至少为 100 MiB")
	}
	c.PacketSegmentBytes, err = strconv.ParseInt(env("PACKET_SEGMENT_BYTES", "16777216"), 10, 64)
	if err != nil || c.PacketSegmentBytes < 1024*1024 || c.PacketSegmentBytes > 64*1024*1024 || c.PacketSegmentBytes*3+512*1024 > c.PacketSpoolBytes {
		return c, fmt.Errorf("原包切片需为 1–64 MiB，且暂存区须容纳原件和校验制品")
	}
	c.PacketStorageBytes, err = strconv.ParseInt(env("PACKET_STORAGE_BYTES", "1099511627776"), 10, 64)
	if err != nil || c.PacketStorageBytes < 100*1024*1024 {
		return c, fmt.Errorf("租户原包持久存储额度至少为 100 MiB")
	}
	seconds, e := strconv.Atoi(env("PACKET_ROTATE_SECONDS", "30"))
	if e != nil || seconds < 1 || seconds > 3600 {
		return c, fmt.Errorf("原包轮转间隔需为 1–3600 秒")
	}
	c.PacketRotateInterval = time.Duration(seconds) * time.Second
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
		c.PacketBackend = env("PACKET_BACKEND", c.ReplayBackend)
		if c.PacketBackend != "" && c.PacketBackend != "filesystem" && c.PacketBackend != "s3" {
			return c, fmt.Errorf("原包对象存储类型无效")
		}
		if c.Mode == "production" && c.PacketBackend == "filesystem" {
			return c, fmt.Errorf("生产原包归档要求带版本的 S3 对象存储")
		}
		if c.PacketBackend == "s3" && (c.ReplayS3Endpoint == "" || c.ReplayS3Bucket == "" || c.ReplayS3AccessKey == "" || c.ReplayS3SecretKey == "" || c.Mode == "production" && !c.ReplayS3Secure) {
			return c, fmt.Errorf("原包对象存储配置不完整或未启用 TLS")
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
	if role == "platform" || role == "ingest" || role == "worker" {
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
		if c.CaptureManaged && (!filepath.IsAbs(c.StatePath) || !filepath.IsAbs(c.SuricataConfig) || !filepath.IsAbs(c.SuricataBinary)) {
			return c, fmt.Errorf("托管采集要求检测模板、二进制和持久队列均为绝对路径")
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
	if role == "platform" && (c.MCPIssuer != "" || c.MCPIntrospectionURL != "" || c.MCPClientID != "" || c.MCPClientSecret != "") {
		if c.MCPIssuer == "" || c.MCPIntrospectionURL == "" || c.MCPClientID == "" || c.MCPClientSecret == "" || !strings.HasPrefix(c.AllowedOrigin, "https://") {
			return c, fmt.Errorf("MCP 要求 HTTPS 公开来源及完整授权方、内省端点与资源服务凭据")
		}
	}
	return c, nil
}

// Docker Secret 仅用于凭据及注册身份，文件值不会写回进程环境或日志。
func fileSecrets() (map[string]string, error) {
	values := map[string]string{}
	for _, key := range []string{"DATABASE_URL", "NATS_URL", "REDIS_URL", "ES_API_KEY", "LOCAL_PASSWORD", "REGISTRATION_ID", "REPLAY_S3_ACCESS_KEY", "REPLAY_S3_SECRET_KEY", "CREDENTIAL_KEY", "MCP_CLIENT_SECRET"} {
		path := os.Getenv("SB_" + key + "_FILE")
		if path == "" {
			continue
		}
		if os.Getenv("SB_"+key) != "" {
			return nil, fmt.Errorf("SB_%s 与 SB_%s_FILE 不能同时配置", key, key)
		}
		// 在打开前拒绝命名管道和设备，避免启动阶段等待外部写入者。
		info, e := os.Stat(path)
		if e != nil || !info.Mode().IsRegular() || info.Size() > 65536 {
			return nil, fmt.Errorf("SB_%s_FILE 必须为不超过 64 KiB 的普通文件", key)
		}
		file, e := os.Open(path)
		if e != nil {
			return nil, fmt.Errorf("SB_%s_FILE 无法读取", key)
		}
		info, e = file.Stat()
		if e != nil || !info.Mode().IsRegular() || info.Size() > 65536 {
			file.Close()
			return nil, fmt.Errorf("SB_%s_FILE 必须为不超过 64 KiB 的普通文件", key)
		}
		data, e := io.ReadAll(io.LimitReader(file, 65537))
		file.Close()
		if e != nil || len(data) > 65536 {
			return nil, fmt.Errorf("SB_%s_FILE 读取失败或超过容量", key)
		}
		value := strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r")
		if value == "" || strings.ContainsAny(value, "\x00\r\n") {
			return nil, fmt.Errorf("SB_%s_FILE 必须包含单个非空配置值", key)
		}
		values[key] = value
	}
	return values, nil
}
