package ingest

import (
	"context"
	"errors"
	"time"

	sensorv1 "github.com/kkx600/StarBeacon/api/sensor/v1"
	"github.com/kkx600/StarBeacon/internal/probepki"
	"github.com/kkx600/StarBeacon/internal/transport"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (s *Server) CertificateStatus(ctx context.Context, _ *sensorv1.CertificateStatusRequest) (*sensorv1.CertificateIdentity, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, err := s.identity(ctx); err != nil {
		return nil, err
	}
	cert, err := transport.PeerCertificate(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "未验证探针证书")
	}
	return &sensorv1.CertificateIdentity{FingerprintSha256: probepki.Digest(cert.Raw), NotAfter: timestamppb.New(cert.NotAfter)}, nil
}
func (s *Server) RenewCertificate(ctx context.Context, input *sensorv1.CertificateRenewalRequest) (*sensorv1.CertificateIdentity, error) {
	if !s.ControlOnly || s.Authority == nil {
		return nil, status.Error(codes.Unimplemented, "证书续签服务未配置")
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	id, err := s.identity(ctx)
	if err != nil {
		return nil, err
	}
	cert, err := transport.PeerCertificate(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "未验证探针证书")
	}
	j, send, err := s.DB.BeginProbeRenewal(ctx, id, probepki.Digest(cert.Raw), input.GetCsrPem())
	if errors.Is(err, probepki.ErrNotDue) {
		return nil, status.Error(codes.FailedPrecondition, "证书尚未进入续签窗口")
	}
	if errors.Is(err, probepki.ErrInput) {
		return nil, status.Error(codes.InvalidArgument, "CSR 与当前探针身份不符")
	}
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, "续签提交不可用，请核对原 CSR 与签发状态")
	}
	c := j.Certificate
	if send {
		issued, signErr := s.Authority.Sign(ctx, j)
		// 客户端取消不应撤销已经发出的签发状态记录。
		finish, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		c, err = s.DB.FinishProbeCertificate(finish, j, issued, signErr)
		stop()
		if err != nil {
			return nil, status.Error(codes.Unavailable, "签发未取得可核实结果，请保留原 CSR")
		}
	}
	return &sensorv1.CertificateIdentity{ChainPem: c.Chain, FingerprintSha256: c.Fingerprint, NotAfter: timestamppb.New(c.NotAfter)}, nil
}
