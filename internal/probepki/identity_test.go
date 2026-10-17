package probepki

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/transport"
)

type authorityFixture struct {
	root     *x509.Certificate
	key      ed25519.PrivateKey
	roots    *x509.CertPool
	rootFile string
}

func testAuthority(t *testing.T) authorityFixture {
	t.Helper()
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "isolated-test-root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, root, root, public, key)
	if err != nil {
		t.Fatal(err)
	}
	root, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	raw := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	path := filepath.Join(t.TempDir(), "root.pem")
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	return authorityFixture{root, key, roots, path}
}
func (a authorityFixture) issue(t *testing.T, csr string, before, after time.Time, change func(*x509.Certificate)) string {
	t.Helper()
	b, _ := pem.Decode([]byte(csr))
	if b == nil {
		t.Fatal("缺少 CSR")
	}
	r, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	c := &x509.Certificate{SerialNumber: serial, Subject: r.Subject, URIs: r.URIs, NotBefore: before, NotAfter: after, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	if change != nil {
		change(c)
	}
	der, err := x509.CreateCertificate(rand.Reader, c, a.root, r.PublicKey, a.key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})) + string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.root.Raw}))
}

var testID = transport.SensorIdentity{TenantID: "tenant_a", SensorID: "probe_a", RegistrationID: "registration_a"}

func TestCredentialCSRAndIssuedIdentityBoundary(t *testing.T) {
	token, err := NewCredential(testID, "enrollment_a")
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseCredential(token)
	if err != nil || c.Identity != testID || c.String() != token {
		t.Fatal("注册令牌未绑定身份", err)
	}
	for _, bad := range []string{"", strings.Repeat("a", 601), token + ".", strings.Replace(token, "sbe1", "sbe2", 1), strings.Replace(token, "probe_a", "Probe_a", 1), token[:len(token)-2]} {
		if _, err = ParseCredential(bad); err == nil {
			t.Fatal("非法令牌被接受")
		}
	}
	if _, err = NewCredential(transport.SensorIdentity{}, "enrollment_a"); err == nil {
		t.Fatal("空身份令牌被接受")
	}
	input := EnrollmentInput{Token: token, Name: "办公探针", TTLSeconds: 3600}
	if input.Validate() != nil {
		t.Fatal("正常注册参数被拒绝")
	}
	for _, name := range []string{"", " 办公探针", "办公\n探针", strings.Repeat("测", 129), string([]byte{0xff})} {
		bad := input
		bad.Name = name
		if bad.Validate() == nil {
			t.Fatal("非法名称被接受")
		}
	}
	for _, ttl := range []int{0, 59, 86401} {
		bad := input
		bad.TTLSeconds = ttl
		if bad.Validate() == nil {
			t.Fatal("非法令牌期限被接受")
		}
	}
	csr, _, err := NewCSR(testID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ParseCSR(csr, testID); err != nil {
		t.Fatal(err)
	}
	foreign := testID
	foreign.RegistrationID = "foreign"
	for _, bad := range []string{"", csr + csr, strings.Repeat("a", 16385), strings.Replace(csr, "CERTIFICATE REQUEST", "PRIVATE KEY", 1)} {
		if _, err = ParseCSR(bad, testID); err == nil {
			t.Fatal("非法 CSR 被接受")
		}
	}
	if _, err = ParseCSR(csr, foreign); err == nil {
		t.Fatal("跨注册 CSR 被接受")
	}
	a := testAuthority(t)
	now := time.Now()
	chain := a.issue(t, csr, now.Add(-time.Minute), now.Add(time.Hour), nil)
	cert, err := VerifyChain(chain, csr, testID, a.roots, now, time.Hour)
	if err != nil || len(cert.Fingerprint) != 64 || cert.State != "issued" {
		t.Fatal("正常证书核验失败", err)
	}
	for _, change := range []func(*x509.Certificate){
		func(c *x509.Certificate) { c.IsCA = true; c.BasicConstraintsValid = true },
		func(c *x509.Certificate) { c.DNSNames = []string{"unexpected.example"} },
		func(c *x509.Certificate) { c.ExtKeyUsage = append(c.ExtKeyUsage, x509.ExtKeyUsageServerAuth) },
		func(c *x509.Certificate) { c.KeyUsage |= x509.KeyUsageKeyEncipherment },
		func(c *x509.Certificate) { c.URIs = []*url.URL{} },
		func(c *x509.Certificate) { c.NotAfter = now.Add(7 * 24 * time.Hour) },
		func(c *x509.Certificate) { c.NotAfter = now.Add(-time.Minute) },
	} {
		if _, err = VerifyChain(a.issue(t, csr, now.Add(-time.Minute), now.Add(time.Hour), change), csr, testID, a.roots, now, time.Hour); err == nil {
			t.Fatal("越权或过期证书被接受")
		}
	}
	other, _, _ := NewCSR(testID)
	if _, err = VerifyChain(chain, other, testID, a.roots, now, time.Hour); err == nil {
		t.Fatal("错误公钥被接受")
	}
	if _, err = VerifyChain(chain, csr, testID, x509.NewCertPool(), now, time.Hour); err == nil {
		t.Fatal("无可信 CA 被接受")
	}
	if _, err = VerifyChain("bad", csr, testID, a.roots, now, time.Hour); err == nil {
		t.Fatal("非法链被接受")
	}
	if _, err = VerifyChain(chain, "bad", testID, a.roots, now, time.Hour); err == nil {
		t.Fatal("非法原 CSR 被接受")
	}
	for _, bad := range []string{"", strings.Repeat("a", 65537), chain + "trailing", strings.Repeat(chain, 3)} {
		if _, err = ParseChain(bad); err == nil {
			t.Fatal("非法证书链被接受")
		}
	}
}
