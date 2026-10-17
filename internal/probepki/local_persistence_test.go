package probepki

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func localCandidate(t *testing.T, a authorityFixture) (pendingIdentity, Certificate) {
	t.Helper()
	csr, key, err := NewCSR(testID)
	if err != nil {
		t.Fatal(err)
	}
	chain := a.issue(t, csr, time.Now().Add(-time.Minute), time.Now().Add(time.Hour), nil)
	cert, err := VerifyChain(chain, csr, testID, a.roots, time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return pendingIdentity{CSR: csr, Key: key}, cert
}

func TestLocalIdentityPublicationFailureRetainsCurrentIdentity(t *testing.T) {
	a := testAuthority(t)
	for _, fault := range []string{"receipt_fingerprint", "receipt_expiry", "private_key", "missing_current_file", "untrusted_backup", "missing_directory"} {
		t.Run(fault, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "identity")
			local, err := OpenLocal(dir, a.rootFile, testID)
			if err != nil {
				t.Fatal(err)
			}
			defer local.Close()
			p, cert := localCandidate(t, a)
			if err := local.accept(p, cert, nil); err != nil {
				t.Fatal(err)
			}
			oldStatus := local.Status()
			oldPath := filepath.Join(dir, "identity.pem")
			original, err := os.ReadFile(oldPath)
			if err != nil {
				t.Fatal(err)
			}
			p, cert = localCandidate(t, a)
			switch fault {
			case "receipt_fingerprint":
				cert.Fingerprint = strings.Repeat("0", 64)
			case "receipt_expiry":
				cert.NotAfter = cert.NotAfter.Add(time.Second)
			case "private_key":
				_, p.Key, err = NewCSR(testID)
			case "missing_current_file":
				err = os.Rename(oldPath, oldPath+".retained")
				oldPath += ".retained"
			case "untrusted_backup":
				err = os.Symlink(a.rootFile, filepath.Join(dir, "previous.pem"))
			case "missing_directory":
				err = os.Rename(dir, dir+".retained")
				oldPath = filepath.Join(dir+".retained", "identity.pem")
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := local.accept(p, cert, nil); err == nil {
				t.Fatal("身份发布失败条件未被拒绝")
			}
			if local.Status() != oldStatus {
				t.Fatal("失败后内存身份已切换")
			}
			retained, err := os.ReadFile(oldPath)
			if err != nil || !bytes.Equal(retained, original) {
				t.Fatal("失败后旧身份无法恢复", err)
			}
		})
	}
	t.Run("untrusted_initial_target", func(t *testing.T) {
		local, err := OpenLocal(filepath.Join(t.TempDir(), "identity"), a.rootFile, testID)
		if err != nil {
			t.Fatal(err)
		}
		defer local.Close()
		if err = os.Symlink(a.rootFile, filepath.Join(local.dir, "identity.pem")); err != nil {
			t.Fatal(err)
		}
		p, cert := localCandidate(t, a)
		if err = local.accept(p, cert, nil); err == nil || local.Status().Fingerprint != "" {
			t.Fatal("不可信目标文件仍发布了初始身份")
		}
	})
}

func TestLocalPersistedIdentityRechecksBindingTrustAndExpiredStatus(t *testing.T) {
	a := testAuthority(t)
	for _, fault := range []string{"foreign_identity", "untrusted_issuer", "server_usage", "corrupt_intermediate", "expired"} {
		t.Run(fault, func(t *testing.T) {
			id, issuer := testID, a
			before, after := time.Now().Add(-time.Minute), time.Now().Add(time.Hour)
			if fault == "foreign_identity" {
				id.SensorID = "another_probe"
			}
			if fault == "untrusted_issuer" {
				issuer = testAuthority(t)
			}
			if fault == "expired" {
				before, after = time.Now().Add(-30*time.Minute), time.Now().Add(-time.Minute)
			}
			csr, key, err := NewCSR(id)
			if err != nil {
				t.Fatal(err)
			}
			chain := issuer.issue(t, csr, before, after, func(c *x509.Certificate) {
				if fault == "server_usage" {
					c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
				}
			})
			if fault == "corrupt_intermediate" {
				chain += string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("invalid DER")}))
			}
			dir := filepath.Join(t.TempDir(), "identity")
			if err = os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			bundle := append([]byte(chain), key...)
			if err = os.WriteFile(filepath.Join(dir, "identity.pem"), bundle, 0600); err != nil {
				t.Fatal(err)
			}
			local, err := OpenLocal(dir, a.rootFile, testID)
			if fault != "expired" {
				if err == nil {
					local.Close()
					t.Fatal("持久身份未重新核对绑定与信任")
				}
				return
			}
			if err != nil {
				t.Fatal("过期身份状态不可读取", err)
			}
			defer local.Close()
			if status := local.Status(); status.Fingerprint == "" || !status.NotAfter.Before(time.Now()) {
				t.Fatal("未报告实际过期状态")
			}
			if changed, err := local.Renew(context.Background(), nil, nil); changed || err == nil {
				t.Fatal("过期持久身份可续签")
			}
		})
	}
}

func TestLocalPendingRejectsMalformedAndUnsupportedPrivateKeys(t *testing.T) {
	a := testAuthority(t)
	local, err := OpenLocal(filepath.Join(t.TempDir(), "identity"), a.rootFile, testID)
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	p, err := local.pending("credential")
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherDER, err := x509.MarshalPKCS8PrivateKey(otherKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, der := range [][]byte{[]byte("invalid PKCS8"), otherDER} {
		p.Key = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		raw, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		if err = local.write("pending.json", raw); err != nil {
			t.Fatal(err)
		}
		if _, err = local.pending("credential"); err == nil {
			t.Fatal("损坏或不受支持的待办密钥被接受")
		}
		retained, err := os.ReadFile(filepath.Join(local.dir, "pending.json"))
		if err != nil || !bytes.Equal(raw, retained) {
			t.Fatal("原待办被覆盖", err)
		}
	}
}

func TestLocalEnrollmentTrustFailuresPreserveSubmission(t *testing.T) {
	a := testAuthority(t)
	local, err := OpenLocal(filepath.Join(t.TempDir(), "identity"), a.rootFile, testID)
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	token, err := NewCredential(testID, "enrollment_trust")
	if err != nil {
		t.Fatal(err)
	}
	invalidRoot := filepath.Join(t.TempDir(), "invalid-root.pem")
	if err = os.WriteFile(invalidRoot, []byte("not a certificate"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, root := range []string{invalidRoot + ".missing", invalidRoot} {
		if err = local.Enroll(context.Background(), "https://127.0.0.1:1", root, token); err == nil {
			t.Fatal("平台信任材料无效仍接受注册")
		}
	}
	original, err := os.ReadFile(filepath.Join(local.dir, "pending.json"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err = local.Enroll(ctx, "https://127.0.0.1:1", a.rootFile, token); err == nil {
		t.Fatal("已取消注册仍成功")
	}
	retained, err := os.ReadFile(filepath.Join(local.dir, "pending.json"))
	if err != nil || !bytes.Equal(original, retained) || local.Status().Fingerprint != "" {
		t.Fatal("信任或传输失败改变了原注册提交", err)
	}
}

func TestLocalEnrollmentCannotPublishIntoUnavailableIdentityDirectory(t *testing.T) {
	a := testAuthority(t)
	for _, replacement := range []string{"missing", "regular_file"} {
		t.Run(replacement, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "identity")
			local, err := OpenLocal(dir, a.rootFile, testID)
			if err != nil {
				t.Fatal(err)
			}
			defer local.Close()
			p, err := local.pending("credential")
			if err != nil {
				t.Fatal(err)
			}
			chain := a.issue(t, p.CSR, time.Now().Add(-time.Minute), time.Now().Add(time.Hour), nil)
			cert, err := VerifyChain(chain, p.CSR, testID, a.roots, time.Now(), time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			original, err := os.ReadFile(filepath.Join(dir, "pending.json"))
			if err != nil {
				t.Fatal(err)
			}
			retained := dir + ".retained"
			if err = os.Rename(dir, retained); err != nil {
				t.Fatal(err)
			}
			if replacement == "regular_file" {
				if err = os.WriteFile(dir, []byte("occupied"), 0600); err != nil {
					t.Fatal(err)
				}
				if reopened, err := OpenLocal(dir, a.rootFile, testID); err == nil {
					reopened.Close()
					t.Fatal("注册接受了非目录身份路径")
				}
			}
			if err = local.accept(p, cert, nil); err == nil || local.Status().Fingerprint != "" {
				t.Fatal("未持久发布却报告注册完成")
			}
			actual, err := os.ReadFile(filepath.Join(retained, "pending.json"))
			if err != nil || !bytes.Equal(actual, original) {
				t.Fatal("目录故障后原 CSR 和私钥丢失", err)
			}
		})
	}
}
