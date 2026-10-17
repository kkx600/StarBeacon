package ingest

import (
	"context"
	"testing"

	sensorv1 "github.com/kkx600/StarBeacon/api/sensor/v1"
	"github.com/kkx600/StarBeacon/internal/probepki"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestCertificateRPCRequiresControlAuthorityAndAuthenticatedPeer(t *testing.T) {
	for _, server := range []*Server{{}, {ControlOnly: true}, {Authority: &probepki.Step{}}} {
		if _, err := server.RenewCertificate(context.Background(), &sensorv1.CertificateRenewalRequest{}); status.Code(err) != codes.Unimplemented {
			t.Fatal("未配置的续签入口未明确拒绝", err)
		}
	}
	server := &Server{ControlOnly: true, Authority: &probepki.Step{}}
	if _, err := server.RenewCertificate(context.Background(), &sensorv1.CertificateRenewalRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatal("未认证的调用进入续签流程", err)
	}
	if _, err := server.CertificateStatus(context.Background(), &sensorv1.CertificateStatusRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatal("未认证的调用取得证书状态", err)
	}
}
