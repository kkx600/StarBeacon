package admin

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestCorruptCAAndUnavailableCertificateDirectoriesNeverPublishIdentity(t *testing.T) {
	for _, mode := range []string{"certificate_missing", "certificate_pem", "certificate_der", "not_ca", "key_missing", "key_pem", "key_der", "unsupported_key"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			if err := DevPKI(dir); err != nil {
				t.Fatal(err)
			}
			certificatePath, keyPath := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")
			switch mode {
			case "certificate_missing":
				if err := os.Remove(certificatePath); err != nil {
					t.Fatal(err)
				}
			case "certificate_pem":
				if err := os.WriteFile(certificatePath, []byte("invalid"), 0600); err != nil {
					t.Fatal(err)
				}
			case "certificate_der":
				if err := os.WriteFile(certificatePath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("invalid")}), 0600); err != nil {
					t.Fatal(err)
				}
			case "not_ca":
				raw, err := os.ReadFile(filepath.Join(dir, "server.crt"))
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(certificatePath, raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "key_missing":
				if err := os.Remove(keyPath); err != nil {
					t.Fatal(err)
				}
			case "key_pem":
				if err := os.WriteFile(keyPath, []byte("invalid"), 0600); err != nil {
					t.Fatal(err)
				}
			case "key_der":
				if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("invalid")}), 0600); err != nil {
					t.Fatal(err)
				}
			case "unsupported_key":
				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				raw, err := x509.MarshalPKCS8PrivateKey(key)
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw}), 0600); err != nil {
					t.Fatal(err)
				}
			}
			prefix := filepath.Join(dir, "issued")
			if _, err := Issue(dir, prefix, nil, true); err == nil {
				t.Fatal("损坏的 CA 仍签发了证书")
			}
			for _, suffix := range []string{".key", ".crt"} {
				if _, err := os.Stat(prefix + suffix); !os.IsNotExist(err) {
					t.Fatal("签发失败发布了部分身份")
				}
			}
		})
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "file")
	if err := os.WriteFile(path, []byte("owned"), 0600); err != nil {
		t.Fatal(err)
	}
	if DevPKI(filepath.Join(path, "pki")) == nil {
		t.Fatal("证书路径经过普通文件仍被接受")
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := removePrivateFiles([]ownedPrivateFile{{path: dir, info: info}}); err == nil {
		t.Fatal("清理非空目录未报告失败")
	}
}
