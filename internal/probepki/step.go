package probepki

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/kkx600/StarBeacon/internal/transport"
)

type StepConfig struct {
	URL, RootFile, Provisioner, JWKFile string
	Lifetime                            time.Duration
}
type Step struct {
	config StepConfig
	client *http.Client
	roots  *x509.CertPool
	signer jose.Signer
}

func NewStep(c StepConfig) (*Step, error) {
	u, err := url.Parse(c.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || c.Provisioner == "" || len(c.Provisioner) > 128 || c.Lifetime < 5*time.Minute || c.Lifetime > 7*24*time.Hour {
		return nil, ErrInput
	}
	root, err := os.ReadFile(c.RootFile)
	if err != nil {
		return nil, errors.New("探针 CA 信任根不可读取")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(root) {
		return nil, errors.New("探针 CA 信任根无效")
	}
	info, err := os.Lstat(c.JWKFile)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 16384 {
		return nil, errors.New("CA 授权密钥须为私有普通文件")
	}
	raw, err := os.ReadFile(c.JWKFile)
	if err != nil {
		return nil, errors.New("CA 授权密钥不可读取")
	}
	var key jose.JSONWebKey
	if json.Unmarshal(raw, &key) != nil || !key.Valid() || key.IsPublic() || key.KeyID == "" {
		return nil, errors.New("CA 授权 JWK 无效")
	}
	if _, ok := key.Key.(ed25519.PrivateKey); !ok {
		return nil, errors.New("CA 授权 JWK 要求 Ed25519")
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: key}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return nil, errors.New("CA 授权签名不可用")
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}, MaxConnsPerHost: 8, MaxIdleConnsPerHost: 4, ResponseHeaderTimeout: 5 * time.Second, IdleConnTimeout: 30 * time.Second}
	return &Step{config: c, roots: roots, signer: signer, client: &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func (s *Step) token(path, id, subject string, additional any) (string, error) {
	now := time.Now().UTC()
	return jwt.Signed(s.signer).Claims(jwt.Claims{Issuer: s.config.Provisioner, Subject: subject, Audience: jwt.Audience{s.config.URL + path}, ID: id, IssuedAt: jwt.NewNumericDate(now), NotBefore: jwt.NewNumericDate(now.Add(-30 * time.Second)), Expiry: jwt.NewNumericDate(now.Add(time.Minute))}).Claims(additional).Serialize()
}
func (s *Step) post(ctx context.Context, path string, body, result any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, s.config.URL+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	r.Header.Set("Content-Type", "application/json")
	res, err := s.client.Do(r)
	if err != nil {
		return errors.New("CA 请求未取得可核实结果")
	}
	defer res.Body.Close()
	b, err = io.ReadAll(io.LimitReader(res.Body, 65537))
	if err != nil || len(b) > 65536 || res.StatusCode < 200 || res.StatusCode > 299 {
		return errors.New("CA 未返回有效成功回执")
	}
	if json.Unmarshal(b, result) != nil {
		return errors.New("CA 成功回执格式无效")
	}
	return nil
}
func (s *Step) Sign(ctx context.Context, j Job) (Certificate, error) {
	csr, err := ParseCSR(j.CSR, j.Identity)
	if err != nil {
		return Certificate{}, err
	}
	hash := shaCSR(csr.Raw)
	additional := map[string]any{"sans": []string{transport.SensorURI(j.Identity)}, "cnf": map[string]string{"x5rt#S256": hash}}
	token, err := s.token("/1.0/sign", j.ID, j.Identity.SensorID, additional)
	if err != nil {
		return Certificate{}, err
	}
	var response struct {
		Chain []string `json:"certChain"`
	}
	err = s.post(ctx, "/1.0/sign", map[string]any{"csr": j.CSR, "ott": token, "notAfter": fmt.Sprintf("%ds", int64(s.config.Lifetime/time.Second))}, &response)
	if err != nil {
		return Certificate{}, err
	}
	cert, err := VerifyChain(strings.Join(response.Chain, "\n"), j.CSR, j.Identity, s.roots, time.Now().UTC(), s.config.Lifetime)
	cert.ID = j.ID
	return cert, err
}
func shaCSR(b []byte) string {
	hash := sha256.Sum256(b)
	return base64.RawURLEncoding.EncodeToString(hash[:])
}
func (s *Step) Revoke(ctx context.Context, serial, id string) error {
	token, err := s.token("/1.0/revoke", id, serial, map[string]any{})
	if err != nil {
		return err
	}
	var result struct {
		Status string `json:"status"`
	}
	if err = s.post(ctx, "/1.0/revoke", map[string]any{"serial": serial, "ott": token, "reasonCode": 0, "reason": "StarBeacon certificate disabled", "passive": true}, &result); err != nil {
		return err
	}
	if result.Status != "ok" {
		return errors.New("CA 吊销回执无效")
	}
	return nil
}
