package probepki

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	sensorv1 "github.com/kkx600/StarBeacon/api/sensor/v1"
	"github.com/kkx600/StarBeacon/internal/transport"
	"golang.org/x/sys/unix"
)

type Local struct {
	dir   string
	id    transport.SensorIdentity
	roots *x509.CertPool
	lock  *os.File
	mu    sync.Mutex
	pair  atomic.Pointer[tls.Certificate]
}
type pendingIdentity struct {
	Schema     string `json:"schema"`
	Credential string `json:"credential_sha256"`
	CSR        string `json:"csr_pem"`
	Key        []byte `json:"key_pem"`
}
type LocalStatus struct {
	Mode           string    `json:"mode"`
	SensorID       string    `json:"sensor_id"`
	RegistrationID string    `json:"registration_id"`
	Fingerprint    string    `json:"fingerprint_sha256"`
	NotBefore      time.Time `json:"not_before"`
	NotAfter       time.Time `json:"not_after"`
	RenewAfter     time.Time `json:"renew_after"`
}

func privateRead(path string, max int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > max {
		return nil, errors.New("身份文件类型、权限或大小不可用")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	actual, err := f.Stat()
	if err != nil || !os.SameFile(info, actual) {
		return nil, errors.New("身份文件已变化")
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil || int64(len(b)) > max {
		return nil, errors.New("身份文件读取超限")
	}
	return b, nil
}
func (l *Local) write(name string, raw []byte) error {
	path := filepath.Join(l.dir, name)
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return errors.New("身份目标文件不可信")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.CreateTemp(l.dir, ".identity-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(raw)
	}
	if err == nil {
		err = f.Sync()
	}
	if err == nil {
		err = f.Close()
	}
	if err != nil {
		return err
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	d, err := os.Open(l.dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
func OpenLocal(dir, root string, id transport.SensorIdentity) (*Local, error) {
	if !filepath.IsAbs(dir) || !filepath.IsAbs(root) {
		return nil, ErrInput
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("探针身份目录须为专属私有目录")
	}
	lockPath := filepath.Join(dir, "identity.lock")
	if info, err := os.Lstat(lockPath); err == nil && (!info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0) {
		return nil, errors.New("身份锁文件不可信")
	}
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	if err = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		lock.Close()
		return nil, errors.New("探针身份目录正由其他进程使用")
	}
	rootPEM, err := os.ReadFile(root)
	if err != nil {
		lock.Close()
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootPEM) {
		lock.Close()
		return nil, ErrInput
	}
	l := &Local{dir: dir, id: id, roots: roots, lock: lock}
	if raw, err := privateRead(filepath.Join(dir, "identity.pem"), 81920); err == nil {
		pair, err := tls.X509KeyPair(raw, raw)
		if err != nil {
			l.Close()
			return nil, errors.New("持久探针证书与私钥不匹配")
		}
		if err = l.validatePair(&pair); err != nil {
			l.Close()
			return nil, err
		}
		l.pair.Store(&pair)
		if pending, readErr := privateRead(filepath.Join(dir, "pending.json"), 32768); readErr == nil {
			var saved pendingIdentity
			if json.Unmarshal(pending, &saved) == nil && saved.Schema == "probe.identity.v1" {
				if csr, parseErr := ParseCSR(saved.CSR, id); parseErr == nil && bytes.Equal(csr.RawSubjectPublicKeyInfo, pair.Leaf.RawSubjectPublicKeyInfo) {
					_ = os.Remove(filepath.Join(dir, "pending.json"))
				}
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		l.Close()
		return nil, err
	}
	return l, nil
}
func (l *Local) Close() error {
	if l == nil || l.lock == nil {
		return nil
	}
	return l.lock.Close()
}
func (l *Local) validatePair(pair *tls.Certificate) error {
	if len(pair.Certificate) == 0 {
		return ErrDenied
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return ErrDenied
	}
	id, err := transport.CertificateIdentity(leaf)
	if err != nil || id != l.id || leaf.IsCA || len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		return ErrDenied
	}
	intermediate := x509.NewCertPool()
	for _, raw := range pair.Certificate[1:] {
		c, err := x509.ParseCertificate(raw)
		if err != nil {
			return err
		}
		intermediate.AddCert(c)
	}
	// 允许读取已过期的旧身份，以便明确报告续签失败；TLS 握手仍核验证书当前有效期。
	verifyAt := time.Now()
	if verifyAt.After(leaf.NotAfter) {
		verifyAt = leaf.NotAfter.Add(-time.Second)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: l.roots, Intermediates: intermediate, CurrentTime: verifyAt, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return ErrDenied
	}
	pair.Leaf = leaf
	return nil
}
func (l *Local) ClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	pair := l.pair.Load()
	if pair == nil {
		return nil, ErrDenied
	}
	return pair, nil
}
func (l *Local) Status() LocalStatus {
	out := LocalStatus{Mode: "managed", SensorID: l.id.SensorID, RegistrationID: l.id.RegistrationID}
	if pair := l.pair.Load(); pair != nil {
		leaf := pair.Leaf
		out.Fingerprint = Digest(leaf.Raw)
		out.NotBefore = leaf.NotBefore
		out.NotAfter = leaf.NotAfter
		out.RenewAfter = leaf.NotAfter.Add(-leaf.NotAfter.Sub(leaf.NotBefore) / 3)
	}
	return out
}
func (l *Local) pending(credential string) (pendingIdentity, error) {
	var p pendingIdentity
	raw, err := privateRead(filepath.Join(l.dir, "pending.json"), 32768)
	if err == nil {
		if json.Unmarshal(raw, &p) != nil || p.Schema != "probe.identity.v1" || p.Credential != credential {
			return p, ErrConflict
		}
		csr, err := ParseCSR(p.CSR, l.id)
		if err != nil {
			return p, err
		}
		b, rest := pem.Decode(p.Key)
		if b == nil || b.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
			return p, ErrInput
		}
		key, err := x509.ParsePKCS8PrivateKey(b.Bytes)
		if err != nil {
			return p, ErrInput
		}
		private, ok := key.(ed25519.PrivateKey)
		if !ok {
			return p, ErrInput
		}
		public, err := x509.MarshalPKIXPublicKey(private.Public())
		if err != nil || !bytes.Equal(public, csr.RawSubjectPublicKeyInfo) {
			return p, ErrInput
		}
		return p, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return p, err
	}
	p = pendingIdentity{Schema: "probe.identity.v1", Credential: credential}
	p.CSR, p.Key, err = NewCSR(l.id)
	if err != nil {
		return p, err
	}
	raw, err = json.Marshal(p)
	if err != nil {
		return p, err
	}
	return p, l.write("pending.json", raw)
}

func (l *Local) accept(p pendingIdentity, c Certificate, check func(*tls.Certificate) error) error {
	cert, err := VerifyChain(c.Chain, p.CSR, l.id, l.roots, time.Now(), 7*24*time.Hour)
	if err != nil {
		return err
	}
	if cert.Fingerprint != c.Fingerprint || !cert.NotAfter.Equal(c.NotAfter) {
		return ErrDenied
	}
	bundle := append([]byte(c.Chain+"\n"), p.Key...)
	pair, err := tls.X509KeyPair(bundle, bundle)
	if err != nil {
		return err
	}
	if err = l.validatePair(&pair); err != nil {
		return err
	}
	if check != nil {
		if err = check(&pair); err != nil {
			return err
		}
	}
	if prior := l.pair.Load(); prior != nil {
		old, err := privateRead(filepath.Join(l.dir, "identity.pem"), 81920)
		if err != nil {
			return err
		}
		if err = l.write("previous.pem", old); err != nil {
			return err
		}
	}
	if err = l.write("identity.pem", bundle); err != nil {
		return err
	}
	l.pair.Store(&pair)
	// 身份文件已耐久发布；待办删除失败不撤销证书，重启可按 CSR 公钥识别完成记录。
	_ = os.Remove(filepath.Join(l.dir, "pending.json"))
	return nil
}

func (l *Local) Enroll(ctx context.Context, origin, platformRoot, token string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	c, err := ParseCredential(token)
	if err != nil || c.Identity != l.id {
		return ErrInput
	}
	if l.pair.Load() != nil {
		return ErrConflict
	}
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return ErrInput
	}
	p, err := l.pending(Digest([]byte(token)))
	if err != nil {
		return err
	}
	rootPEM, err := os.ReadFile(platformRoot)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootPEM) {
		return ErrInput
	}
	client := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	body, _ := json.Marshal(Exchange{Token: token, CSR: p.CSR})
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, origin+"/api/v1/sensor-enrollments/exchange", bytes.NewReader(body))
	if err != nil {
		return err
	}
	r.Header.Set("Content-Type", "application/json")
	res, err := client.Do(r)
	if err != nil {
		return errors.New("注册尚未取得平台回执，请保留原 CSR 和令牌文件")
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 65537))
	if err != nil || len(raw) > 65536 || res.StatusCode != 200 {
		return fmt.Errorf("注册未成功，HTTP %d；请核对平台状态并保留原提交", res.StatusCode)
	}
	var cert Certificate
	if json.Unmarshal(raw, &cert) != nil {
		return ErrInput
	}
	return l.accept(p, cert, nil)
}
func (l *Local) Renew(ctx context.Context, client sensorv1.SensorServiceClient, check func(*tls.Certificate) error) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	current := l.Status()
	if current.Fingerprint == "" {
		return false, ErrDenied
	}
	if time.Now().Before(current.RenewAfter) {
		return false, nil
	}
	if !current.NotAfter.After(time.Now()) {
		return false, ErrDenied
	}
	p, err := l.pending(current.Fingerprint)
	if err != nil {
		return false, err
	}
	result, err := client.RenewCertificate(ctx, &sensorv1.CertificateRenewalRequest{CsrPem: p.CSR})
	if err != nil {
		return false, errors.New("证书续签尚未完成，请保留原 CSR")
	}
	if result == nil || result.NotAfter == nil || result.NotAfter.CheckValid() != nil {
		return false, ErrInput
	}
	c := Certificate{Chain: result.ChainPem, Fingerprint: result.FingerprintSha256, NotAfter: result.NotAfter.AsTime()}
	if err = l.accept(p, c, check); err != nil {
		return false, err
	}
	return true, nil
}

func ReadTokenFile(path string) (string, error) {
	raw, err := privateRead(path, 600)
	if err != nil {
		return "", errors.New("注册令牌须由不超过 600 字节的私有普通文件提供")
	}
	value := strings.TrimSuffix(string(raw), "\n")
	if _, err = ParseCredential(value); err != nil {
		return "", err
	}
	return value, nil
}
