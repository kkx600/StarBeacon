// Package transport 从固定信任根建立双向认证连接。
package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"

	"github.com/kkx600/StarBeacon/internal/contract"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

func TLS(ca, cert, key string, server bool) (*tls.Config, error) {
	b, e := os.ReadFile(ca)
	if e != nil {
		return nil, e
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil, fmt.Errorf("CA 文件无有效证书")
	}
	pair, e := tls.LoadX509KeyPair(cert, key)
	if e != nil {
		return nil, e
	}
	c := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}, RootCAs: pool}
	if server {
		c.ClientCAs = pool
		c.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return c, nil
}

type SensorIdentity struct{ TenantID, SensorID, RegistrationID string }

func SensorURI(i SensorIdentity) string {
	return "spiffe://starbeacon/tenants/" + i.TenantID + "/sensors/" + i.SensorID + "/registrations/" + i.RegistrationID
}
func PeerIdentity(ctx context.Context) (SensorIdentity, error) {
	var id SensorIdentity
	p, ok := peer.FromContext(ctx)
	if !ok {
		return id, fmt.Errorf("未提供 TLS 身份")
	}
	v, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(v.State.VerifiedChains) == 0 || len(v.State.VerifiedChains[0]) == 0 {
		return id, fmt.Errorf("未验证 TLS 身份")
	}
	cert := v.State.VerifiedChains[0][0]
	if len(cert.URIs) != 1 {
		return id, fmt.Errorf("证书身份不唯一")
	}
	u := cert.URIs[0]
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if u.Scheme != "spiffe" || u.Host != "starbeacon" || len(parts) != 6 || parts[0] != "tenants" || parts[2] != "sensors" || parts[4] != "registrations" {
		return id, fmt.Errorf("证书身份不合法")
	}
	id = SensorIdentity{parts[1], parts[3], parts[5]}
	if !contract.ValidID(id.TenantID) || !contract.ValidID(id.SensorID) || !contract.ValidID(id.RegistrationID) {
		return SensorIdentity{}, fmt.Errorf("证书标识不合法")
	}
	if u.String() != SensorURI(id) {
		return SensorIdentity{}, fmt.Errorf("证书身份必须使用规范 URI")
	}
	return id, nil
}
