package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/url"
	"testing"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

func TestPeerIdentityOnlyAcceptsVerifiedCanonicalIdentity(t *testing.T) {
	want := SensorIdentity{"tenant_a", "sensor_a", "sr_a"}
	for _, tc := range []struct {
		name, uri       string
		verified, valid bool
	}{
		{"有效身份", SensorURI(want), true, true},
		{"未经验证", SensorURI(want), false, false},
		{"错误信任域", "spiffe://other/tenants/tenant_a/sensors/sensor_a/registrations/sr_a", true, false},
		{"附加参数", SensorURI(want) + "?role=admin", true, false},
		{"不规范路径", SensorURI(want) + "/", true, false},
		{"未绑定注册", "spiffe://starbeacon/tenants/tenant_a/sensors/sensor_a", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u, err := url.Parse(tc.uri)
			if err != nil {
				t.Fatal(err)
			}
			cert := &x509.Certificate{URIs: []*url.URL{u}}
			state := tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
			if tc.verified {
				state.VerifiedChains = [][]*x509.Certificate{{cert}}
			}
			ctx := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{State: state}})
			got, err := PeerIdentity(ctx)
			if (err == nil) != tc.valid || tc.valid && got != want {
				t.Fatalf("身份校验错误：%+v，%v", got, err)
			}
		})
	}
	if _, err := PeerIdentity(context.Background()); err == nil {
		t.Fatal("无 TLS 连接也可取得身份")
	}
}
