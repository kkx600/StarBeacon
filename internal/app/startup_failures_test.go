package app

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/admin"
	"github.com/kkx600/StarBeacon/internal/config"
	"github.com/kkx600/StarBeacon/internal/ingest"
)

func TestStartupConfigurationFailureNeverReportsServiceStarted(t *testing.T) {
	for _, tc := range []struct {
		name, role string
		config     config.Config
	}{
		{"凭据主密钥无效", "platform", config.Config{CredentialKey: "invalid-key"}},
		{"出站网段无效", "platform", config.Config{OutboundNetworks: "invalid-network"}},
		{"出站证书丢失", "worker", config.Config{OutboundCA: filepath.Join(t.TempDir(), "missing.crt")}},
		{"出站证书损坏", "ingest", config.Config{OutboundCA: malformedRoot(t)}},
		{"平台数据库地址无效", "platform", config.Config{DatabaseURL: "postgres://%invalid"}},
		{"接入数据库地址无效", "ingest", config.Config{DatabaseURL: "postgres://%invalid"}},
		{"工作进程数据库地址无效", "worker", config.Config{DatabaseURL: "postgres://%invalid"}},
		{"运行角色未知", "invalid-role", config.Config{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := Run(ctx, tc.role, tc.config); err == nil {
				t.Fatal("启动配置错误被当作服务正常")
			}
		})
	}
}

func malformedRoot(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bad.crt")
	if err := os.WriteFile(path, []byte("invalid certificate"), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestGRPCStartupRejectsCertificateAndOccupiedPort(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := serveGRPC(ctx, config.Config{}, &ingest.Server{}); err == nil {
		t.Fatal("没有服务证书仍启动了控制端口")
	}
	ca := filepath.Join(t.TempDir(), "pki")
	if err := admin.DevPKI(ca); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	c := config.Config{TLSCA: filepath.Join(ca, "ca.crt"), TLSCert: filepath.Join(ca, "server.crt"), TLSKey: filepath.Join(ca, "server.key"), GRPCAddr: listener.Addr().String()}
	if err := serveGRPC(ctx, c, &ingest.Server{}); err == nil || !strings.Contains(err.Error(), "bind") {
		t.Fatal("被占用的控制端口没有启动失败", err)
	}
}

// 无效 MCP 配置须在连接数据库或启动队列之前返回，不能依赖外部服务的响应速度。
func TestRunRejectsMCPConfigurationBeforeDependencies(t *testing.T) {
	base := config.Config{Mode: "development", DatabaseURL: "postgres://%invalid", AllowedOrigin: "https://platform.example", MCPIssuer: "https://identity.example", MCPIntrospectionURL: "https://identity.example/introspect", MCPClientID: "owned", MCPClientSecret: "owned-secret"}
	for _, tc := range []struct {
		name      string
		configure func(*config.Config)
		message   string
	}{
		{"公开来源", func(c *config.Config) { c.AllowedOrigin = "http://platform.example" }, "MCP 公开来源"},
		{"授权方", func(c *config.Config) { c.MCPIssuer = "invalid-issuer" }, "MCP 授权方"},
		{"内省来源", func(c *config.Config) { c.MCPIntrospectionURL = "https://other.example/introspect" }, "MCP 令牌内省"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := base
			tc.configure(&c)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			err := Run(ctx, "platform", c)
			if err == nil || !strings.Contains(err.Error(), tc.message) || ctx.Err() != nil {
				t.Fatal("MCP 配置未在依赖访问前拒绝", err)
			}
		})
	}
}
