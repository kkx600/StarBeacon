// Package probepki 定义探针注册凭据、CSR 和独立 CA 的边界。
package probepki

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/transport"
)

var (
	ErrInput    = errors.New("探针证书参数无效")
	ErrDenied   = errors.New("探针注册凭据或证书不可用")
	ErrConflict = errors.New("原提交已绑定其他 CSR，或签发结果尚未核实")
	ErrQuota    = errors.New("探针证书操作超过额度")
	ErrNotDue   = errors.New("证书尚未进入续签窗口")
)

type Credential struct {
	Identity   transport.SensorIdentity
	ID, Secret string
}

// 注册凭据包含公开的绑定信息；只有最后 32 字节随机量是认证秘密。
func NewCredential(id transport.SensorIdentity, enrollmentID string) (string, error) {
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return "", err
	}
	c := Credential{id, enrollmentID, base64.RawURLEncoding.EncodeToString(secret[:])}
	value := c.String()
	_, err := ParseCredential(value)
	return value, err
}
func (c Credential) String() string {
	return strings.Join([]string{"sbe1", c.Identity.TenantID, c.Identity.SensorID, c.Identity.RegistrationID, c.ID, c.Secret}, ".")
}
func ParseCredential(value string) (Credential, error) {
	var c Credential
	if len(value) > 600 {
		return c, ErrInput
	}
	p := strings.Split(value, ".")
	if len(p) != 6 || p[0] != "sbe1" {
		return c, ErrInput
	}
	for _, v := range p[1:5] {
		if !contract.ValidID(v) {
			return c, ErrInput
		}
	}
	b, err := base64.RawURLEncoding.DecodeString(p[5])
	if err != nil || len(b) != 32 || base64.RawURLEncoding.EncodeToString(b) != p[5] {
		return c, ErrInput
	}
	c = Credential{transport.SensorIdentity{TenantID: p[1], SensorID: p[2], RegistrationID: p[3]}, p[4], p[5]}
	return c, nil
}
func Digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

type EnrollmentInput struct {
	Token      string `json:"token"`
	Name       string `json:"name"`
	TTLSeconds int    `json:"ttl_seconds"`
}

func (v EnrollmentInput) Validate() error {
	if _, err := ParseCredential(v.Token); err != nil {
		return err
	}
	if !utf8.ValidString(v.Name) || strings.TrimSpace(v.Name) != v.Name || utf8.RuneCountInString(v.Name) < 1 || utf8.RuneCountInString(v.Name) > 128 || strings.ContainsAny(v.Name, "\r\n\x00") || v.TTLSeconds < 60 || v.TTLSeconds > 86400 {
		return ErrInput
	}
	return nil
}

type Enrollment struct {
	ID             string    `json:"id"`
	SensorID       string    `json:"sensor_id"`
	RegistrationID string    `json:"registration_id"`
	CreatedAt      time.Time `json:"created_at"`
	ExpiresAt      time.Time `json:"expires_at"`
	Revoked        bool      `json:"revoked"`
	State          string    `json:"state"`
	JobID          string    `json:"job_id,omitempty"`
	CSRSHA256      string    `json:"csr_sha256,omitempty"`
}
type Exchange struct {
	Token string `json:"token"`
	CSR   string `json:"csr_pem"`
}
type Certificate struct {
	ID             string     `json:"id"`
	SensorID       string     `json:"sensor_id"`
	RegistrationID string     `json:"registration_id"`
	Fingerprint    string     `json:"fingerprint_sha256"`
	Serial         string     `json:"serial"`
	NotBefore      time.Time  `json:"not_before"`
	NotAfter       time.Time  `json:"not_after"`
	RevokedAt      *time.Time `json:"revoked_at,omitempty"`
	CARevocation   string     `json:"ca_revocation"`
	Chain          string     `json:"chain_pem,omitempty"`
	State          string     `json:"state"`
	CSRSHA256      string     `json:"csr_sha256,omitempty"`
}
type Job struct {
	ID          string
	Identity    transport.SensorIdentity
	CSR         string
	State       string
	Certificate Certificate
}
type Authority interface {
	Sign(context.Context, Job) (Certificate, error)
	Revoke(context.Context, string, string) error
}

func NewCSR(id transport.SensorIdentity) (string, []byte, error) {
	if !contract.ValidID(id.TenantID) || !contract.ValidID(id.SensorID) || !contract.ValidID(id.RegistrationID) {
		return "", nil, ErrInput
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", nil, err
	}
	u, _ := url.Parse(transport.SensorURI(id))
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: id.SensorID}, URIs: []*url.URL{u}}, key)
	if err != nil {
		return "", nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", nil, err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), nil
}
func ParseCSR(raw string, id transport.SensorIdentity) (*x509.CertificateRequest, error) {
	if len(raw) > 16384 {
		return nil, ErrInput
	}
	b, rest := pem.Decode([]byte(raw))
	if b == nil || b.Type != "CERTIFICATE REQUEST" || len(b.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrInput
	}
	c, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil || c.CheckSignature() != nil || c.PublicKeyAlgorithm != x509.Ed25519 || c.Subject.CommonName != id.SensorID || len(c.Subject.Names) != 1 || len(c.URIs) != 1 || c.URIs[0].String() != transport.SensorURI(id) || len(c.DNSNames)+len(c.IPAddresses)+len(c.EmailAddresses) != 0 {
		return nil, ErrInput
	}
	// 仅接受标准 SAN 扩展，不允许通过 CSR 请求 CA、用途或自定义身份扩展。
	for _, e := range c.Extensions {
		if e.Id.String() != "2.5.29.17" || e.Critical {
			return nil, ErrInput
		}
	}
	return c, nil
}
func ParseChain(raw string) ([]*x509.Certificate, error) {
	if len(raw) > 65536 {
		return nil, ErrInput
	}
	var out []*x509.Certificate
	rest := []byte(raw)
	for len(bytes.TrimSpace(rest)) > 0 {
		b, next := pem.Decode(rest)
		if b == nil || b.Type != "CERTIFICATE" || len(b.Headers) != 0 || len(out) >= 4 {
			return nil, ErrInput
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, ErrInput
		}
		out = append(out, c)
		rest = next
	}
	if len(out) == 0 {
		return nil, ErrInput
	}
	return out, nil
}

// CA 返回的内容仍需按信任根、原 CSR、公钥、用途和注册身份独立核验。
func VerifyChain(raw, csr string, id transport.SensorIdentity, roots *x509.CertPool, now time.Time, lifetime time.Duration) (Certificate, error) {
	var result Certificate
	chain, err := ParseChain(raw)
	if err != nil {
		return result, err
	}
	request, err := ParseCSR(csr, id)
	if err != nil {
		return result, err
	}
	leaf := chain[0]
	if leaf.IsCA || leaf.Subject.CommonName != id.SensorID || len(leaf.URIs) != 1 || leaf.URIs[0].String() != transport.SensorURI(id) || len(leaf.DNSNames)+len(leaf.IPAddresses)+len(leaf.EmailAddresses) != 0 || !bytes.Equal(leaf.RawSubjectPublicKeyInfo, request.RawSubjectPublicKeyInfo) || leaf.KeyUsage != x509.KeyUsageDigitalSignature || len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || len(leaf.UnknownExtKeyUsage) != 0 || leaf.SerialNumber.Sign() <= 0 || !leaf.NotAfter.After(now.Add(30*time.Second)) || leaf.NotAfter.After(now.Add(lifetime+2*time.Minute)) || leaf.NotAfter.Sub(leaf.NotBefore) > lifetime+2*time.Minute {
		return result, ErrDenied
	}
	intermediate := x509.NewCertPool()
	for _, c := range chain[1:] {
		intermediate.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediate, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return result, ErrDenied
	}
	result = Certificate{SensorID: id.SensorID, RegistrationID: id.RegistrationID, Fingerprint: Digest(leaf.Raw), Serial: leaf.SerialNumber.String(), NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter, CARevocation: "none", Chain: raw, State: "issued", CSRSHA256: Digest([]byte(csr))}
	return result, nil
}
