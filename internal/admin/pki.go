package admin

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/transport"
)

func serial() (*big.Int, error) { return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128)) }

type privateArtifact struct {
	path string
	data []byte
}
type ownedPrivateFile struct {
	path string
	info os.FileInfo
}

// 回滚仅删除本次创建的 inode，不影响已有文件或并发替换后的身份。
func removePrivateFiles(files []ownedPrivateFile) error {
	var failure error
	for _, file := range files {
		info, err := os.Lstat(file.path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			failure = errors.Join(failure, err)
			continue
		}
		if os.SameFile(info, file.info) {
			failure = errors.Join(failure, os.Remove(file.path))
		}
	}
	return failure
}
func writePrivateFiles(artifacts []privateArtifact) (owned []ownedPrivateFile, failure error) {
	defer func() {
		if failure != nil {
			failure = errors.Join(failure, removePrivateFiles(owned))
		}
	}()
	for _, artifact := range artifacts {
		file, err := os.OpenFile(artifact.path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return owned, err
		}
		info, err := file.Stat()
		if err != nil {
			return owned, errors.Join(err, file.Close())
		}
		owned = append(owned, ownedPrivateFile{artifact.path, info})
		_, err = file.Write(artifact.data)
		if err == nil {
			err = file.Sync()
		}
		if err = errors.Join(err, file.Close()); err != nil {
			return owned, err
		}
	}
	return owned, nil
}
func keyBytes(k ed25519.PrivateKey) ([]byte, error) {
	b, e := x509.MarshalPKCS8PrivateKey(k)
	if e != nil {
		return nil, e
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b}), nil
}
func DevPKI(dir string) error {
	return DevPKIWithHosts(dir, nil)
}
func DevPKIWithHosts(dir string, hosts []string) error {
	if _, _, e := serverHosts(hosts); e != nil {
		return e
	}
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
	created, e := writePrivateFiles([]privateArtifact{
		{filepath.Join(dir, "ca.key"), key},
		{filepath.Join(dir, "ca.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})},
	})
	if e != nil {
		return e
	}
	if _, e = IssueWithHosts(dir, filepath.Join(dir, "server"), nil, true, hosts); e != nil {
		return errors.Join(e, removePrivateFiles(created))
	}
	return nil
}
func Issue(caDir, prefix string, identity *transport.SensorIdentity, server bool) ([]byte, error) {
	return IssueWithHosts(caDir, prefix, identity, server, nil)
}
func IssueWithHosts(caDir, prefix string, identity *transport.SensorIdentity, server bool, hosts []string) ([]byte, error) {
	der, key, e := certificateMaterial(caDir, identity, server, hosts)
	if e != nil {
		return nil, e
	}
	_, e = writePrivateFiles([]privateArtifact{{prefix + ".key", key}, {prefix + ".crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}})
	if e != nil {
		return nil, e
	}
	return der, nil
}

func certificateMaterial(caDir string, identity *transport.SensorIdentity, server bool, hosts []string) ([]byte, []byte, error) {
	dns, ips, e := serverHosts(hosts)
	if e != nil {
		return nil, nil, e
	}
	if !server && (identity == nil || !contract.ValidID(identity.TenantID) || !contract.ValidID(identity.SensorID) || !contract.ValidID(identity.RegistrationID)) {
		return nil, nil, fmt.Errorf("采集器证书身份无效")
	}
	b, e := os.ReadFile(filepath.Join(caDir, "ca.crt"))
	if e != nil {
		return nil, nil, e
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, nil, fmt.Errorf("CA 无效")
	}
	ca, e := x509.ParseCertificate(block.Bytes)
	if e != nil {
		return nil, nil, e
	}
	if !ca.IsCA || !ca.BasicConstraintsValid || time.Now().Before(ca.NotBefore) || time.Now().Add(30*24*time.Hour).After(ca.NotAfter) {
		return nil, nil, fmt.Errorf("CA 无效或有效期不能覆盖采集器证书")
	}
	b, e = os.ReadFile(filepath.Join(caDir, "ca.key"))
	if e != nil {
		return nil, nil, e
	}
	block, _ = pem.Decode(b)
	if block == nil {
		return nil, nil, fmt.Errorf("CA 密钥无效")
	}
	signer, e := x509.ParsePKCS8PrivateKey(block.Bytes)
	if e != nil {
		return nil, nil, e
	}
	private, ok := signer.(ed25519.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("CA 密钥类型不支持")
	}
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return nil, nil, e
	}
	n, e := serial()
	if e != nil {
		return nil, nil, e
	}
	cert := &x509.Certificate{SerialNumber: n, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(30 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, DNSNames: dns, IPAddresses: ips}
	if server {
		cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		cert.Subject = pkix.Name{CommonName: "StarBeacon server"}
	} else {
		if identity == nil {
			return nil, nil, fmt.Errorf("缺少采集器身份")
		}
		u, e := url.Parse(transport.SensorURI(*identity))
		if e != nil {
			return nil, nil, e
		}
		cert.URIs = []*url.URL{u}
		cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
		cert.Subject = pkix.Name{CommonName: identity.SensorID}
	}
	der, e := x509.CreateCertificate(rand.Reader, cert, ca, pub, private)
	if e != nil {
		return nil, nil, e
	}
	keyPEM, e := keyBytes(key)
	if e != nil {
		return nil, nil, e
	}
	return der, keyPEM, nil
}

// 只签发显式主机身份，不接受通配符、URL 或网段作为服务证书名称。
func serverHosts(hosts []string) ([]string, []net.IP, error) {
	dns := []string{"localhost"}
	ips := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	if len(hosts) > 16 {
		return nil, nil, fmt.Errorf("服务证书最多允许 16 个附加主机")
	}
	seen := map[string]bool{"localhost": true, "127.0.0.1": true, "::1": true}
	for _, host := range hosts {
		if host == "" || strings.TrimSpace(host) != host || len(host) > 253 {
			return nil, nil, fmt.Errorf("服务证书主机名称无效")
		}
		host = strings.ToLower(host)
		if seen[host] {
			continue
		}
		seen[host] = true
		if ip := net.ParseIP(host); ip != nil {
			ips = append(ips, ip)
			continue
		}
		for _, label := range strings.Split(host, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return nil, nil, fmt.Errorf("服务证书 DNS 名称无效")
			}
			for _, c := range label {
				if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
					return nil, nil, fmt.Errorf("服务证书 DNS 名称无效")
				}
			}
		}
		dns = append(dns, host)
	}
	return dns, ips, nil
}
func Provision(ctx context.Context, p *store.Postgres, tenant, sensor, name, caDir, dir string) (transport.SensorIdentity, error) {
	id := transport.SensorIdentity{TenantID: tenant, SensorID: sensor, RegistrationID: store.RandomID("sr_")}
	if !contract.ValidID(tenant) || !contract.ValidID(sensor) {
		return id, fmt.Errorf("采集器标识不合法")
	}
	if e := os.MkdirAll(dir, 0700); e != nil {
		return id, e
	}
	der, key, e := certificateMaterial(caDir, &id, false, nil)
	if e != nil {
		return id, e
	}
	prefix := filepath.Join(dir, "agent")
	created, e := writePrivateFiles([]privateArtifact{{prefix + ".key", key}, {prefix + ".crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}})
	if e != nil {
		return id, e
	}
	e = p.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, "INSERT INTO sensors(tenant_id,id,name,registration_id) VALUES($1,$2,$3,$4)", tenant, sensor, name, id.RegistrationID)
		return e
	})
	if e != nil {
		e = errors.Join(e, removePrivateFiles(created))
	}
	return id, e
}
