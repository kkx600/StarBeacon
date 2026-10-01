package admin

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/transport"
)

func serial() (*big.Int, error) { return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128)) }
func writePrivate(path string, bytes []byte) error {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	if _, e = f.Write(bytes); e != nil {
		return e
	}
	return f.Sync()
}
func keyBytes(k ed25519.PrivateKey) ([]byte, error) {
	b, e := x509.MarshalPKCS8PrivateKey(k)
	if e != nil {
		return nil, e
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b}), nil
}
func DevPKI(dir string) error {
	if _, e := os.Stat(filepath.Join(dir, "ca.crt")); e == nil {
		return fmt.Errorf("CA 已存在，禁止覆盖")
	}
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	pub, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return e
	}
	n, e := serial()
	if e != nil {
		return e
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: n, Subject: pkix.Name{CommonName: "StarBeacon development CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, e := x509.CreateCertificate(rand.Reader, ca, ca, pub, private)
	if e != nil {
		return e
	}
	key, e := keyBytes(private)
	if e != nil {
		return e
	}
	if e = writePrivate(filepath.Join(dir, "ca.key"), key); e != nil {
		return e
	}
	if e = writePrivate(filepath.Join(dir, "ca.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})); e != nil {
		return e
	}
	_, e = Issue(dir, filepath.Join(dir, "server"), nil, true)
	return e
}
func Issue(caDir, prefix string, identity *transport.SensorIdentity, server bool) ([]byte, error) {
	b, e := os.ReadFile(filepath.Join(caDir, "ca.crt"))
	if e != nil {
		return nil, e
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("CA 无效")
	}
	ca, e := x509.ParseCertificate(block.Bytes)
	if e != nil {
		return nil, e
	}
	b, e = os.ReadFile(filepath.Join(caDir, "ca.key"))
	if e != nil {
		return nil, e
	}
	block, _ = pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("CA 密钥无效")
	}
	signer, e := x509.ParsePKCS8PrivateKey(block.Bytes)
	if e != nil {
		return nil, e
	}
	private, ok := signer.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("CA 密钥类型不支持")
	}
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return nil, e
	}
	n, e := serial()
	if e != nil {
		return nil, e
	}
	cert := &x509.Certificate{SerialNumber: n, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(30 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}}
	if server {
		cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		cert.Subject = pkix.Name{CommonName: "StarBeacon server"}
	} else {
		if identity == nil {
			return nil, fmt.Errorf("缺少采集器身份")
		}
		u, e := url.Parse(transport.SensorURI(*identity))
		if e != nil {
			return nil, e
		}
		cert.URIs = []*url.URL{u}
		cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
		cert.Subject = pkix.Name{CommonName: identity.SensorID}
	}
	der, e := x509.CreateCertificate(rand.Reader, cert, ca, pub, private)
	if e != nil {
		return nil, e
	}
	keyPEM, e := keyBytes(key)
	if e != nil {
		return nil, e
	}
	if e = writePrivate(prefix+".key", keyPEM); e != nil {
		return nil, e
	}
	return der, writePrivate(prefix+".crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
func Provision(ctx context.Context, p *store.Postgres, tenant, sensor, name, caDir, dir string) (transport.SensorIdentity, error) {
	id := transport.SensorIdentity{TenantID: tenant, SensorID: sensor, RegistrationID: store.RandomID("sr_")}
	if !contract.ValidID(tenant) || !contract.ValidID(sensor) {
		return id, fmt.Errorf("采集器标识不合法")
	}
	if e := os.MkdirAll(dir, 0700); e != nil {
		return id, e
	}
	if _, e := Issue(caDir, filepath.Join(dir, "agent"), &id, false); e != nil {
		return id, e
	}
	e := p.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, "INSERT INTO sensors(tenant_id,id,name,registration_id) VALUES($1,$2,$3,$4)", tenant, sensor, name, id.RegistrationID)
		return e
	})
	return id, e
}
