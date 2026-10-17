package probepki

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func fixtureTLS(t *testing.T, a authorityFixture) tls.Certificate {
	t.Helper()
	csr, key, err := NewCSR(testID)
	if err != nil {
		t.Fatal(err)
	}
	chain := a.issue(t, csr, time.Now().Add(-time.Minute), time.Now().Add(time.Hour), func(c *x509.Certificate) {
		c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		c.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	})
	pair, err := tls.X509KeyPair([]byte(chain), key)
	if err != nil {
		t.Fatal(err)
	}
	return pair
}
func fixtureStepKey(t *testing.T) (string, jose.JSONWebKey) {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key := jose.JSONWebKey{Key: private, KeyID: "platform-signing", Algorithm: string(jose.EdDSA), Use: "sig"}
	raw, err := json.Marshal(key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "provisioner.jwk")
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return path, key
}
func TestStepAdapterPinsRootBindsCSRAndChecksReceipt(t *testing.T) {
	a := testAuthority(t)
	keyFile, key := fixtureStepKey(t)
	csr, _, _ := NewCSR(testID)
	var mode atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			CSR     string `json:"csr"`
			OTT     string `json:"ott"`
			Serial  string `json:"serial"`
			Passive bool   `json:"passive"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			t.Error("非法 CA 请求体")
			w.WriteHeader(400)
			return
		}
		token, err := jwt.ParseSigned(body.OTT, []jose.SignatureAlgorithm{jose.EdDSA})
		if err != nil {
			t.Error(err)
			w.WriteHeader(401)
			return
		}
		var claims jwt.Claims
		var additional struct {
			SANs []string          `json:"sans"`
			CNF  map[string]string `json:"cnf"`
		}
		if err = token.Claims(key.Public(), &claims, &additional); err != nil || claims.Issuer != "starbeacon-probes" || claims.ID == "" {
			t.Error("JWT 未经授权")
			w.WriteHeader(401)
			return
		}
		if r.URL.Path == "/1.0/revoke" {
			if claims.Subject != body.Serial || !body.Passive {
				t.Error("吊销身份不符")
			}
			if mode.Load() == 6 {
				_, _ = io.WriteString(w, `{"status":"pending"}`)
			} else {
				_, _ = io.WriteString(w, `{"status":"ok"}`)
			}
			return
		}
		block, _ := pem.Decode([]byte(body.CSR))
		if block == nil || additional.CNF["x5rt#S256"] != shaCSR(block.Bytes) || len(additional.SANs) != 1 || claims.Subject != testID.SensorID {
			t.Error("JWT 未绑定原 CSR")
			w.WriteHeader(403)
			return
		}
		switch mode.Load() {
		case 1:
			w.WriteHeader(500)
			return
		case 2:
			_, _ = io.WriteString(w, strings.Repeat("x", 65537))
			return
		case 3:
			w.Header().Set("Location", "https://untrusted.invalid/sign")
			w.WriteHeader(307)
			return
		case 4:
			_, _ = io.WriteString(w, `{"certChain":["invalid"]}`)
			return
		case 5:
			_, _ = io.WriteString(w, `not-json`)
			return
		}
		chain := a.issue(t, body.CSR, time.Now().Add(-time.Minute), time.Now().Add(time.Hour), nil)
		_ = json.NewEncoder(w).Encode(map[string]any{"certChain": []string{chain}})
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{fixtureTLS(t, a)}}
	server.StartTLS()
	defer server.Close()
	cfg := StepConfig{URL: server.URL, RootFile: a.rootFile, Provisioner: "starbeacon-probes", JWKFile: keyFile, Lifetime: time.Hour}
	client, err := NewStep(cfg)
	if err != nil {
		t.Fatal(err)
	}
	job := Job{ID: "cert_a", Identity: testID, CSR: csr}
	cert, err := client.Sign(context.Background(), job)
	if err != nil || cert.ID != job.ID {
		t.Fatal("CA 签发未核对", err)
	}
	if err = client.Revoke(context.Background(), cert.Serial, "revoke_a"); err != nil {
		t.Fatal(err)
	}
	mode.Store(6)
	if err = client.Revoke(context.Background(), cert.Serial, "revoke_unknown"); err == nil {
		t.Fatal("CA 未确认吊销却视作成功")
	}
	for _, value := range []int32{1, 2, 3, 4, 5} {
		mode.Store(value)
		if _, err = client.Sign(context.Background(), job); err == nil {
			t.Fatal("错误 CA 回执被接受", value)
		}
	}
	mode.Store(0)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = client.Sign(ctx, job); err == nil {
		t.Fatal("取消请求未拒绝")
	}
	if err = client.Revoke(ctx, cert.Serial, "revoke_canceled"); err == nil {
		t.Fatal("已取消吊销仍返回成功")
	}
	job.CSR = "invalid"
	if _, err = client.Sign(context.Background(), job); err == nil {
		t.Fatal("非法 CSR 被发送")
	}
	for _, origin := range []string{"http://localhost", "https://a/path", "https://a?q=1", "https://u:p@a", "https://a#fragment", "https://"} {
		bad := cfg
		bad.URL = origin
		if _, err = NewStep(bad); err == nil {
			t.Fatal("不受控 CA 来源被接受")
		}
	}
	bad := cfg
	bad.Lifetime = time.Second
	if _, err = NewStep(bad); err == nil {
		t.Fatal("不受控证书期限")
	}
	bad = cfg
	bad.RootFile = "/missing"
	if _, err = NewStep(bad); err == nil {
		t.Fatal("缺失信任根被接受")
	}
	bad = cfg
	bad.RootFile = keyFile
	if _, err = NewStep(bad); err == nil {
		t.Fatal("无有效根被接受")
	}
	if err = os.Chmod(keyFile, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = NewStep(cfg); err == nil {
		t.Fatal("公开可读签发授权密钥被接受")
	}
	if err = os.Chmod(keyFile, 0600); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(key.Public())
	if err = os.WriteFile(keyFile, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = NewStep(cfg); err == nil {
		t.Fatal("公钥被用于签发 JWT")
	}
	unsupported, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = json.Marshal(jose.JSONWebKey{Key: unsupported, KeyID: "unsupported", Algorithm: string(jose.ES256), Use: "sig"})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(keyFile, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = NewStep(cfg); err == nil {
		t.Fatal("未配置的签发密钥算法被接受")
	}
}
