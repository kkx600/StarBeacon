package admin

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kkx600/StarBeacon/internal/transport"
)

func certificate(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(b)
	v, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return v
}
func TestDevelopmentServiceSANAndSensorIdentity(t *testing.T) {
	dir := t.TempDir()
	if err := DevPKIWithHosts(dir, []string{"platform", "ingest", "collector", "192.0.2.10", "PLATFORM"}); err != nil {
		t.Fatal(err)
	}
	cert := certificate(t, filepath.Join(dir, "server.crt"))
	for _, host := range []string{"localhost", "127.0.0.1", "::1", "platform", "ingest", "collector", "192.0.2.10"} {
		if err := cert.VerifyHostname(host); err != nil {
			t.Fatal(host, err)
		}
	}
	if cert.VerifyHostname("other-service") == nil {
		t.Fatal("签发了未授权主机")
	}
	if _, err := tls.LoadX509KeyPair(filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if DevPKI(dir) == nil {
		t.Fatal("覆盖已有 CA")
	}
	after, _ := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if string(before) != string(after) {
		t.Fatal("已有 CA 被修改")
	}
	identity := transport.SensorIdentity{TenantID: "tenant_test", SensorID: "sensor_test", RegistrationID: "sr_test"}
	if _, err := Issue(dir, filepath.Join(dir, "agent"), &identity, false); err != nil {
		t.Fatal(err)
	}
	agent := certificate(t, filepath.Join(dir, "agent.crt"))
	if len(agent.URIs) != 1 || agent.URIs[0].String() != transport.SensorURI(identity) {
		t.Fatal("采集器身份不匹配")
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate(t, filepath.Join(dir, "ca.crt")))
	if _, err := agent.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ca.key", "server.key", "agent.key"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("私钥权限无效", name)
		}
	}
	if _, err := Issue(dir, filepath.Join(dir, "agent"), &identity, false); err == nil {
		t.Fatal("重签覆盖已有身份")
	}
}
func TestServerHostsRejectBeforeWriting(t *testing.T) {
	for _, host := range []string{"", " *.example.com", "*.example.com", "http://platform", "platform:29091", "foo/bar", "a..b", "-platform", "platform-", "fe80::1%eth0", "underscore_name", strings.Repeat("a", 64) + ".com", strings.Repeat("x", 254)} {
		t.Run(host, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "pki")
			if DevPKIWithHosts(dir, []string{host}) == nil {
				t.Fatal("接受非法 SAN")
			}
			if _, err := os.Stat(dir); !os.IsNotExist(err) {
				t.Fatal("非法请求创建了证书目录")
			}
		})
	}
	if _, _, err := serverHosts(make([]string, 17)); err == nil {
		t.Fatal("超出 SAN 数量")
	}
	dir := t.TempDir()
	if err := DevPKI(dir); err != nil {
		t.Fatal(err)
	}
	for _, identity := range []*transport.SensorIdentity{nil, {TenantID: "../other", SensorID: "sensor_x", RegistrationID: "sr_x"}} {
		if _, err := Issue(dir, filepath.Join(dir, "invalid"), identity, false); err == nil {
			t.Fatal("接受非法身份")
		}
	}
	if _, err := IssueWithHosts(dir, filepath.Join(dir, "bad-san"), nil, true, []string{"*"}); err == nil {
		t.Fatal("接受通配 SAN")
	}
}

func TestCertificatePairFailurePreservesExistingFiles(t *testing.T) {
	dir := t.TempDir()
	if err := DevPKI(dir); err != nil {
		t.Fatal(err)
	}
	prefix := filepath.Join(dir, "collision")
	if err := os.WriteFile(prefix+".crt", []byte("已有证书"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Issue(dir, prefix, nil, true); err == nil {
		t.Fatal("覆盖已有证书")
	}
	if _, err := os.Stat(prefix + ".key"); !os.IsNotExist(err) {
		t.Fatal("失败签发遗留孤立私钥")
	}
	content, err := os.ReadFile(prefix + ".crt")
	if err != nil || string(content) != "已有证书" {
		t.Fatal("已有证书被删除或覆盖")
	}
	if _, err := Issue(dir, filepath.Join(dir, "missing", "cert"), nil, true); err == nil {
		t.Fatal("接受不存在的输出目录")
	}
}

func TestDevelopmentCAFailureIsRetryable(t *testing.T) {
	for _, collision := range []string{"ca.key", "server.key", "server.crt"} {
		t.Run(collision, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, collision)
			if err := os.WriteFile(path, []byte("保留的身份"), 0600); err != nil {
				t.Fatal(err)
			}
			if DevPKI(dir) == nil {
				t.Fatal("覆盖已有身份")
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 1 || entries[0].Name() != collision {
				t.Fatal("失败留下半套 CA 或删除原文件", entries, err)
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := DevPKI(dir); err != nil {
				t.Fatal("失败之后无法重试", err)
			}
		})
	}
}

func TestPrivateFileRollbackDoesNotRemoveReplacement(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.key")
	files, err := writePrivateFiles([]privateArtifact{{path, []byte("原私钥")}})
	if err != nil {
		t.Fatal(err)
	}
	// 保留原 inode，避免文件系统复用 inode 影响并发替换场景。
	if err := os.Rename(path, path+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("替换的私钥"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := removePrivateFiles(files); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil || string(content) != "替换的私钥" {
		t.Fatal("回滚删除了不属于当前操作的文件")
	}
	if err := removePrivateFiles([]ownedPrivateFile{{filepath.Join(dir, "absent"), files[0].info}}); err != nil {
		t.Fatal("已不存在的文件不应使回滚失败", err)
	}
}
