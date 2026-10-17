package probepki

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	sensorv1 "github.com/kkx600/StarBeacon/api/sensor/v1"
)

func TestLocalIdentityRejectsUntrustedFilesAndCorruptPendingKeys(t *testing.T) {
	a := testAuthority(t)
	for _, item := range []struct {
		name    string
		prepare func(string)
	}{
		{"symlink_lock", func(dir string) {
			if err := os.Symlink(a.rootFile, filepath.Join(dir, "identity.lock")); err != nil {
				t.Fatal(err)
			}
		}},
		{"public_lock", func(dir string) {
			if err := os.WriteFile(filepath.Join(dir, "identity.lock"), nil, 0644); err != nil {
				t.Fatal(err)
			}
		}},
		{"public_identity", func(dir string) {
			if err := os.WriteFile(filepath.Join(dir, "identity.pem"), []byte("invalid"), 0644); err != nil {
				t.Fatal(err)
			}
		}},
		{"corrupt_identity", func(dir string) {
			if err := os.WriteFile(filepath.Join(dir, "identity.pem"), []byte("invalid"), 0600); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(item.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "identity")
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			item.prepare(dir)
			if local, err := OpenLocal(dir, a.rootFile, testID); err == nil {
				local.Close()
				t.Fatal("不可信身份材料被接受")
			}
		})
	}
	for _, root := range []string{"/missing/probe-root.pem", filepath.Join(t.TempDir(), "invalid-root.pem")} {
		if strings.Contains(root, "invalid-root") {
			if err := os.WriteFile(root, []byte("invalid"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		if local, err := OpenLocal(filepath.Join(t.TempDir(), "identity"), root, testID); err == nil {
			local.Close()
			t.Fatal("无信任根仍可管理身份")
		}
	}
	local, err := OpenLocal(filepath.Join(t.TempDir(), "identity"), a.rootFile, testID)
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	if changed, err := local.Renew(context.Background(), nil, nil); err == nil || changed {
		t.Fatal("空身份可以续签")
	}
	p, err := local.pending("credential")
	if err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []func(*pendingIdentity){
		func(v *pendingIdentity) { v.Schema = "unknown" }, func(v *pendingIdentity) { v.CSR = "invalid" }, func(v *pendingIdentity) { v.Key = []byte("invalid") },
		func(v *pendingIdentity) { _, v.Key, _ = NewCSR(testID) },
	} {
		bad := p
		mutation(&bad)
		raw, _ := json.Marshal(bad)
		if err := local.write("pending.json", raw); err != nil {
			t.Fatal(err)
		}
		if _, err := local.pending("credential"); err == nil {
			t.Fatal("损坏或不匹配的在途私钥被接受")
		}
		retained, err := privateRead(filepath.Join(local.dir, "pending.json"), 32768)
		if err != nil || !bytes.Equal(retained, raw) {
			t.Fatal("错误在途身份被静默覆盖")
		}
	}
	if err := os.Chmod(filepath.Join(local.dir, "pending.json"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := local.pending("credential"); err == nil {
		t.Fatal("公开待办身份被读取")
	}
	if err := os.Symlink(a.rootFile, filepath.Join(local.dir, "previous.pem")); err != nil {
		t.Fatal(err)
	}
	if err := local.write("previous.pem", []byte("replacement")); err == nil {
		t.Fatal("写入跟随了不可信链接")
	}
}

func TestLocalEnrollmentFailurePreservesExactCSRAndRejectsForeignReceipts(t *testing.T) {
	a := testAuthority(t)
	local, err := OpenLocal(filepath.Join(t.TempDir(), "identity"), a.rootFile, testID)
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	token, _ := NewCredential(testID, "enroll_faults")
	var mode atomic.Int32
	var redirected atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirected" {
			redirected.Add(1)
			w.WriteHeader(503)
			return
		}
		switch mode.Load() {
		case 0:
			w.WriteHeader(503)
		case 1:
			_, _ = w.Write([]byte("invalid-json"))
		case 2:
			_, _ = w.Write([]byte(strings.Repeat("x", 65537)))
		case 4:
			w.Header().Set("Location", "https://"+r.Host+"/redirected")
			w.WriteHeader(http.StatusTemporaryRedirect)
		default:
			_ = json.NewEncoder(w).Encode(Certificate{Chain: "invalid", Fingerprint: strings.Repeat("a", 64)})
		}
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{fixtureTLS(t, a)}, MinVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()
	for value := range 5 {
		mode.Store(int32(value))
		if err := local.Enroll(context.Background(), server.URL, a.rootFile, token); err == nil {
			t.Fatal("不可核实注册回执被接受")
		}
		if local.Status().Fingerprint != "" {
			t.Fatal("注册失败后出现可用身份")
		}
		if _, err := privateRead(filepath.Join(local.dir, "pending.json"), 32768); err != nil {
			t.Fatal("注册失败丢失了原待办")
		}
	}
	if redirected.Load() != 0 {
		t.Fatal("注册请求携带凭据跟随重定向")
	}
	other, _ := NewCredential(testID, "another_enrollment")
	if err := local.Enroll(context.Background(), server.URL, a.rootFile, other); !errors.Is(err, ErrConflict) {
		t.Fatal("不同凭据替换了原提交", err)
	}
	if err := local.Enroll(context.Background(), server.URL, a.rootFile, "invalid"); err == nil {
		t.Fatal("非法令牌被发送")
	}
	for _, path := range []string{filepath.Join(t.TempDir(), "missing"), a.rootFile} {
		if _, err := ReadTokenFile(path); err == nil {
			t.Fatal("非注册令牌文件可用")
		}
	}
}

func TestLocalRenewalRejectsMalformedRepliesAndExpiredIdentity(t *testing.T) {
	a := testAuthority(t)
	local, err := OpenLocal(filepath.Join(t.TempDir(), "identity"), a.rootFile, testID)
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	csr, key, _ := NewCSR(testID)
	chain := a.issue(t, csr, time.Now().Add(-15*time.Minute), time.Now().Add(time.Minute), nil)
	cert, err := VerifyChain(chain, csr, testID, a.roots, time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := local.accept(pendingIdentity{CSR: csr, Key: key}, cert, nil); err != nil {
		t.Fatal(err)
	}
	original, _ := privateRead(filepath.Join(local.dir, "identity.pem"), 81920)
	for _, client := range []renewalFixture{
		{renew: func(context.Context, *sensorv1.CertificateRenewalRequest) (*sensorv1.CertificateIdentity, error) {
			return nil, errors.New("connection lost")
		}},
		{renew: func(context.Context, *sensorv1.CertificateRenewalRequest) (*sensorv1.CertificateIdentity, error) {
			return nil, nil
		}},
		{renew: func(context.Context, *sensorv1.CertificateRenewalRequest) (*sensorv1.CertificateIdentity, error) {
			return &sensorv1.CertificateIdentity{}, nil
		}},
	} {
		if changed, err := local.Renew(context.Background(), client, nil); err == nil || changed {
			t.Fatal("续签失败却切换身份")
		}
		raw, _ := privateRead(filepath.Join(local.dir, "identity.pem"), 81920)
		if !bytes.Equal(raw, original) {
			t.Fatal("续签失败破坏旧身份")
		}
	}
	corrupt := []byte("corrupt pending submission")
	if err := os.WriteFile(filepath.Join(local.dir, "pending.json"), corrupt, 0600); err != nil {
		t.Fatal(err)
	}
	if changed, err := local.Renew(context.Background(), nil, nil); err == nil || changed {
		t.Fatal("损坏待办仍进入续签发送")
	}
	if raw, err := os.ReadFile(filepath.Join(local.dir, "pending.json")); err != nil || !bytes.Equal(raw, corrupt) {
		t.Fatal("损坏待办被静默覆盖", err)
	}
	// 只改变本地测试对象的有效期，不修改数据库，也不将此用例作为实际时钟续签证明。
	current, _ := local.ClientCertificate(nil)
	expired := *current
	leaf := *current.Leaf
	leaf.NotAfter = time.Now().Add(-time.Second)
	expired.Leaf = &leaf
	local.pair.Store(&expired)
	if changed, err := local.Renew(context.Background(), nil, nil); err == nil || changed {
		t.Fatal("过期身份被用于续签")
	}
}
