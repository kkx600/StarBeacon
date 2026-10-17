package probepki

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	sensorv1 "github.com/kkx600/StarBeacon/api/sensor/v1"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type renewalFixture struct {
	sensorv1.SensorServiceClient
	renew func(context.Context, *sensorv1.CertificateRenewalRequest) (*sensorv1.CertificateIdentity, error)
}

func (f renewalFixture) RenewCertificate(ctx context.Context, r *sensorv1.CertificateRenewalRequest, _ ...grpc.CallOption) (*sensorv1.CertificateIdentity, error) {
	return f.renew(ctx, r)
}

func TestLocalEnrollmentPersistsProofAndNeverOverwritesUnknownCSR(t *testing.T) {
	a := testAuthority(t)
	dir := filepath.Join(t.TempDir(), "identity")
	local, err := OpenLocal(dir, a.rootFile, testID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = OpenLocal(dir, a.rootFile, testID); err == nil {
		t.Fatal("允许并发管理同一身份目录")
	}
	if _, err = local.ClientCertificate(nil); err == nil {
		t.Fatal("空身份成为 TLS 凭据")
	}
	token, err := NewCredential(testID, "enroll_local")
	if err != nil {
		t.Fatal(err)
	}
	var received string
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request Exchange
		if json.NewDecoder(r.Body).Decode(&request) != nil || request.Token != token {
			w.WriteHeader(403)
			return
		}
		if received != "" && received != request.CSR {
			t.Error("重试覆盖了原 CSR")
		}
		received = request.CSR
		chain := a.issue(t, request.CSR, time.Now().Add(-time.Minute), time.Now().Add(time.Hour), nil)
		cert, err := VerifyChain(chain, request.CSR, testID, a.roots, time.Now(), time.Hour)
		if err != nil {
			t.Error(err)
			return
		}
		_ = json.NewEncoder(w).Encode(cert)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{fixtureTLS(t, a)}, MinVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()
	if err = local.Enroll(context.Background(), "http://untrusted.invalid", a.rootFile, token); err == nil {
		t.Fatal("注册使用未验证 HTTP")
	}
	if err = local.Enroll(context.Background(), server.URL, a.rootFile, token); err != nil {
		t.Fatal(err)
	}
	status := local.Status()
	if status.Fingerprint == "" || status.Mode != "managed" || !status.RenewAfter.Before(status.NotAfter) {
		t.Fatal("未发布实际身份状态")
	}
	if _, err = local.ClientCertificate(nil); err != nil {
		t.Fatal(err)
	}
	if err = local.Enroll(context.Background(), server.URL, a.rootFile, token); !errors.Is(err, ErrConflict) {
		t.Fatal("注册覆盖现有身份", err)
	}
	info, err := os.Stat(filepath.Join(dir, "identity.pem"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("私钥文件权限错误", err)
	}
	if _, err = os.Stat(filepath.Join(dir, "pending.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("已完成待办仍持有私钥副本")
	}
	if err = local.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenLocal(dir, a.rootFile, testID)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Status().Fingerprint != status.Fingerprint {
		t.Fatal("重启后证书身份变化")
	}
	reopened.Close()
	private := filepath.Join(t.TempDir(), "token")
	if err = os.WriteFile(private, []byte(token+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadTokenFile(private); err != nil || got != token {
		t.Fatal("令牌私有文件不能读取", err)
	}
	if err = os.Chmod(private, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadTokenFile(private); err == nil {
		t.Fatal("公开令牌被读取")
	}
	if _, err = OpenLocal("relative", a.rootFile, testID); err == nil {
		t.Fatal("身份目录不要求绝对路径")
	}
	if err = os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err = OpenLocal(dir, a.rootFile, testID); err == nil {
		t.Fatal("共享身份目录被接受")
	}
}

func TestLocalRenewalRetainsOldIdentityUntilIndependentAuthentication(t *testing.T) {
	a := testAuthority(t)
	dir := filepath.Join(t.TempDir(), "identity")
	local, err := OpenLocal(dir, a.rootFile, testID)
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
	if err = local.accept(pendingIdentity{CSR: csr, Key: key}, cert, nil); err != nil {
		t.Fatal(err)
	}
	original, err := privateRead(filepath.Join(dir, "identity.pem"), 81920)
	if err != nil {
		t.Fatal(err)
	}
	var frozen string
	var issued *sensorv1.CertificateIdentity
	client := renewalFixture{renew: func(_ context.Context, r *sensorv1.CertificateRenewalRequest) (*sensorv1.CertificateIdentity, error) {
		if frozen != "" && frozen != r.CsrPem {
			t.Fatal("新生成私钥覆盖在途续签")
		}
		frozen = r.CsrPem
		if issued == nil {
			raw := a.issue(t, r.CsrPem, time.Now().Add(-time.Minute), time.Now().Add(time.Hour), nil)
			cert, err := VerifyChain(raw, r.CsrPem, testID, a.roots, time.Now(), time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			issued = &sensorv1.CertificateIdentity{ChainPem: raw, FingerprintSha256: cert.Fingerprint, NotAfter: timestamppb.New(cert.NotAfter)}
		}
		return issued, nil
	}}
	changed, err := local.Renew(context.Background(), client, func(*tls.Certificate) error { return errors.New("平台拒绝认证") })
	if err == nil || changed {
		t.Fatal("未通过接入认证却切换证书")
	}
	retained, _ := privateRead(filepath.Join(dir, "identity.pem"), 81920)
	if !bytes.Equal(original, retained) {
		t.Fatal("失败覆盖旧证书")
	}
	other, _ := NewCredential(testID, "enroll_other")
	if _, err = local.pending(Digest([]byte(other))); !errors.Is(err, ErrConflict) {
		t.Fatal("更改凭据覆盖未知 CSR")
	}
	changed, err = local.Renew(context.Background(), client, func(pair *tls.Certificate) error {
		if Digest(pair.Leaf.Raw) != issued.FingerprintSha256 {
			t.Fatal("认证未绑定候选证书")
		}
		return nil
	})
	if err != nil || !changed {
		t.Fatal("精确重试未完成续签", err)
	}
	if local.Status().Fingerprint == cert.Fingerprint {
		t.Fatal("续签后仍使用旧证书")
	}
	previous, _ := privateRead(filepath.Join(dir, "previous.pem"), 81920)
	if !bytes.Equal(original, previous) {
		t.Fatal("切换缺少旧身份恢复依据")
	}
	if changed, err = local.Renew(context.Background(), client, nil); err != nil || changed {
		t.Fatal("窗口外重复续签", err)
	}
	// 模拟已原子发布身份，但进程在删除待办前退出；重启只清理匹配当前公钥的原待办。
	p := pendingIdentity{Schema: "probe.identity.v1", Credential: cert.Fingerprint, CSR: frozen}
	current, _ := privateRead(filepath.Join(dir, "identity.pem"), 81920)
	for rest := current; len(rest) > 0; {
		b, remaining := pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type == "PRIVATE KEY" {
			p.Key = pem.EncodeToMemory(b)
			break
		}
		rest = remaining
	}
	raw, _ := json.Marshal(p)
	if err = local.write("pending.json", raw); err != nil {
		t.Fatal(err)
	}
	local.Close()
	local, err = OpenLocal(dir, a.rootFile, testID)
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	if _, err = os.Stat(filepath.Join(dir, "pending.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("已完成身份发布未恢复")
	}
}
