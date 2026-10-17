package config

import (
	"path/filepath"
	"testing"
	"time"
)

func clearProbeIdentity(t *testing.T) {
	t.Helper()
	completeDevelopment(t)
	for _, key := range []string{"PROBE_CA_URL", "PROBE_CA_ROOT", "PROBE_CA_PROVISIONER", "PROBE_CA_JWK", "PROBE_CERTIFICATE_SECONDS", "IDENTITY_DIR", "IDENTITY_ROOT", "HTTP_TLS_CERT", "HTTP_TLS_KEY"} {
		t.Setenv("SB_"+key, "")
	}
}

func TestProbeCertificateConfigurationScopeAndTrustSeparation(t *testing.T) {
	for _, settings := range []map[string]string{
		{"PROBE_CERTIFICATE_SECONDS": "299"}, {"PROBE_CERTIFICATE_SECONDS": "604801"}, {"PROBE_CERTIFICATE_SECONDS": "invalid"},
		{"PROBE_CA_URL": "https://ca.example"}, {"PROBE_CA_URL": "http://ca.example", "PROBE_CA_ROOT": "/trust/ca.pem", "PROBE_CA_JWK": "/keys/provisioner.jwk", "PROBE_CA_PROVISIONER": "starbeacon-probes"},
		{"HTTP_TLS_CERT": "/certs/server.pem"}, {"IDENTITY_ROOT": "/trust/probe.pem"}, {"IDENTITY_DIR": "relative", "IDENTITY_ROOT": "/trust/probe.pem"},
	} {
		clearProbeIdentity(t)
		for key, value := range settings {
			t.Setenv("SB_"+key, value)
		}
		if _, err := Load("platform"); err == nil {
			t.Fatal("不完整或越界的证书配置被接受")
		}
	}
	clearProbeIdentity(t)
	for key, value := range map[string]string{"PROBE_CA_URL": "https://ca.example", "PROBE_CA_ROOT": "/trust/ca.pem", "PROBE_CA_JWK": "/keys/provisioner.jwk", "PROBE_CA_PROVISIONER": "starbeacon-probes", "PROBE_CERTIFICATE_SECONDS": "300"} {
		t.Setenv("SB_"+key, value)
	}
	if c, err := Load("platform"); err != nil || c.ProbeCertificateLifetime != 5*time.Minute {
		t.Fatal("合法独立 CA 配置未通过", err)
	}
	for _, role := range []string{"ingest", "worker", "agent"} {
		if _, err := Load(role); err == nil {
			t.Fatal("平台 CA 授权密钥扩散到其他角色", role)
		}
	}
	clearProbeIdentity(t)
	dir := filepath.Join(t.TempDir(), "identity")
	t.Setenv("SB_IDENTITY_DIR", dir)
	t.Setenv("SB_IDENTITY_ROOT", "/trust/probe.pem")
	if _, err := Load("agent"); err == nil {
		t.Fatal("托管身份与静态身份同时配置")
	}
	t.Setenv("SB_TLS_CERT", "")
	t.Setenv("SB_TLS_KEY", "")
	if c, err := Load("agent"); err != nil || c.TLSCert != filepath.Join(dir, "identity.pem") || c.IdentityRoot == c.TLSCA {
		t.Fatal("探针签发根与平台服务根未分离", err)
	}
	t.Setenv("SB_MODE", "production")
	if _, err := Load("agent"); err == nil {
		t.Fatal("客户端证书被用于本地 HTTPS 服务")
	}
}
