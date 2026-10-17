package agent

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"time"

	sensorv1 "github.com/kkx600/StarBeacon/api/sensor/v1"
	"github.com/kkx600/StarBeacon/internal/config"
	"github.com/kkx600/StarBeacon/internal/probepki"
	"github.com/kkx600/StarBeacon/internal/transport"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func runCertificateRenewal(ctx context.Context, c config.Config, identity *probepki.Local, base *tls.Config, wal *WAL, data, control, packets *transport.RotatingConn) error {
	check := func(pair *tls.Certificate) error {
		for _, target := range []string{c.PlatformAddr, c.IngestAddr} {
			fresh := base.Clone()
			fresh.GetClientCertificate = nil
			fresh.Certificates = []tls.Certificate{*pair}
			conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(credentials.NewTLS(fresh)))
			if err != nil {
				return err
			}
			call, cancel := context.WithTimeout(ctx, 5*time.Second)
			result, err := sensorv1.NewSensorServiceClient(conn).CertificateStatus(call, &sensorv1.CertificateStatusRequest{})
			cancel()
			conn.Close()
			if err != nil || result.GetFingerprintSha256() != probepki.Digest(pair.Leaf.Raw) {
				return errors.New("新证书尚未通过平台与事件接入认证")
			}
		}
		return nil
	}
	rotate := func() error {
		targets := []string{c.IngestAddr, c.PlatformAddr}
		connections := []*transport.RotatingConn{data, control}
		sizes := []int{4 * 1024 * 1024, 4 * 1024 * 1024}
		if packets != nil {
			targets = append(targets, c.PlatformAddr)
			connections = append(connections, packets)
			sizes = append(sizes, 1024*1024)
		}
		fresh := make([]*grpc.ClientConn, 0, len(targets))
		for i, target := range targets {
			conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(credentials.NewTLS(base.Clone())), grpc.WithDefaultCallOptions(grpc.MaxCallSendMsgSize(sizes[i])))
			if err != nil {
				for _, prior := range fresh {
					prior.Close()
				}
				return err
			}
			fresh = append(fresh, conn)
		}
		for i, conn := range fresh {
			_ = connections[i].Replace(conn)
		}
		return nil
	}
	needsRotate := false
	for ctx.Err() == nil {
		call, cancel := context.WithTimeout(ctx, 25*time.Second)
		changed, err := identity.Renew(call, sensorv1.NewSensorServiceClient(control), check)
		cancel()
		needsRotate = needsRotate || changed
		if needsRotate && err == nil {
			err = rotate()
			if err == nil {
				needsRotate = false
			}
		}
		wal.setFailure("certificate_renewal_unavailable", err != nil)
		if err != nil && ctx.Err() == nil {
			slog.Warn("探针证书续签等待核对", "error", err)
		}
		if !pause(ctx, 30*time.Second) {
			break
		}
	}
	return nil
}
