package agent

import (
	"context"
	"encoding/json"
	"log/slog"
	"math/rand/v2"
	"sync"
	"time"

	sensorv1 "github.com/kkx600/StarBeacon/api/sensor/v1"
	"github.com/kkx600/StarBeacon/internal/config"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/transport"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func pause(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
func upload(ctx context.Context, client sensorv1.SensorServiceClient, wal *WAL, streamID string) {
	backoff := time.Second
	for ctx.Err() == nil {
		b, e := wal.Next(streamID)
		if e == nil && b == nil {
			if !pause(ctx, 200*time.Millisecond) {
				return
			}
			continue
		}
		if e == nil {
			call, cancel := context.WithTimeout(ctx, 20*time.Second)
			var stream grpc.BidiStreamingClient[sensorv1.EventBatch, sensorv1.IngestAck]
			stream, e = client.UploadEvents(call)
			if e == nil {
				e = stream.Send(b)
			}
			if e == nil {
				var ack *sensorv1.IngestAck
				ack, e = stream.Recv()
				if e == nil {
					e = wal.Confirm(b, ack)
				}
			}
			if stream != nil {
				_ = stream.CloseSend()
			}
			cancel()
		}
		if e != nil {
			slog.Warn("事件上报待重试", "stream", streamID, "error", e)
			wal.setFailure("upload_"+streamID+"_unavailable", true)
			if !pause(ctx, backoff+time.Duration(rand.Int64N(int64(backoff/2)))) {
				return
			}
			backoff = min(backoff*2, 30*time.Second)
		} else {
			backoff = time.Second
			wal.setFailure("upload_"+streamID+"_unavailable", false)
		}
	}
}
func heartbeat(ctx context.Context, client sensorv1.SensorServiceClient, wal *WAL, c config.Config) {
	for ctx.Err() == nil {
		call, cancel := context.WithTimeout(ctx, 8*time.Second)
		h := wal.Health(call, c.StatePath)
		raw, e := json.Marshal(h)
		if e == nil {
			var stream grpc.BidiStreamingClient[sensorv1.AgentMessage, sensorv1.PlatformCommand]
			stream, e = client.Control(call)
			if e == nil {
				e = stream.Send(&sensorv1.AgentMessage{SensorId: c.SensorID, SensorRegistrationId: c.RegistrationID, MessageId: store.RandomID("hb_"), Kind: sensorv1.AgentMessageKind_AGENT_MESSAGE_KIND_HEARTBEAT, PayloadSchema: "host.health.v1", PayloadJson: raw, ObservedAt: timestamppb.New(h.ObservedAt)})
			}
			if e == nil {
				_, e = stream.Recv()
			}
			if stream != nil {
				_ = stream.CloseSend()
			}
		}
		cancel()
		if e != nil {
			slog.Warn("健康上报待重试", "error", e)
		}
		wal.setFailure("control_unavailable", e != nil)
		if !pause(ctx, c.HeartbeatInterval) {
			return
		}
	}
}
func Run(ctx context.Context, c config.Config) error {
	wal, e := OpenWAL(c.StatePath, c.TenantID, c.SensorID, c.RegistrationID, c.WALBytes)
	if e != nil {
		return e
	}
	defer wal.Close()
	tlsConfig, e := transport.TLS(c.TLSCA, c.TLSCert, c.TLSKey, false)
	if e != nil {
		return e
	}
	data, e := grpc.NewClient(c.IngestAddr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)), grpc.WithDefaultCallOptions(grpc.MaxCallSendMsgSize(4*1024*1024)))
	if e != nil {
		return e
	}
	defer data.Close()
	control, e := grpc.NewClient(c.PlatformAddr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig.Clone())))
	if e != nil {
		return e
	}
	defer control.Close()
	client := sensorv1.NewSensorServiceClient(data)
	var routeMu sync.Mutex
	routes := map[string]*sensorv1.Route{}
	reader := &EVEReader{WAL: wal, Path: c.EVEPath, Route: func(ctx context.Context, stream string) (string, error) {
		routeMu.Lock()
		defer routeMu.Unlock()
		day := time.Now().UTC().Format("2006-01-02")
		if r := routes[stream]; r != nil && r.Partition == day && r.ExpiresAt.AsTime().After(time.Now()) {
			return r.Token, nil
		}
		call, cancel := context.WithTimeout(ctx, 8*time.Second)
		defer cancel()
		r, e := client.GetRoute(call, &sensorv1.RouteRequest{StreamId: stream})
		if e != nil {
			return "", e
		}
		if r.TenantId != c.TenantID || r.StreamId != stream {
			return "", context.Canceled
		}
		routes[stream] = r
		return r.Token, nil
	}}
	defer reader.Close()
	local, e := NewLocalIdentity(wal, c.LocalPassword)
	if e != nil {
		return e
	}
	auth := httpapi.NewAuth(local, nil, c.AllowedOrigin, c.CookieName, c.Mode == "production")
	group, run := errgroup.WithContext(ctx)
	group.Go(func() error {
		last := ""
		for run.Err() == nil {
			before := reader.source
			e := reader.Poll(run)
			wal.setFailure("eve_source_unavailable", e != nil)
			if e != nil && e.Error() != last {
				slog.Warn("EVE 读取等待恢复", "error", e)
				last = e.Error()
			} else if e == nil {
				last = ""
			}
			if e == nil && reader.source != before {
				continue
			}
			if !pause(run, 200*time.Millisecond) {
				break
			}
		}
		return nil
	})
	for _, stream := range []string{"alerts", "context"} {
		group.Go(func() error { upload(run, client, wal, stream); return nil })
	}
	group.Go(func() error { heartbeat(run, sensorv1.NewSensorServiceClient(control), wal, c); return nil })
	group.Go(func() error {
		cert, key := "", ""
		if c.Mode == "production" {
			cert, key = c.TLSCert, c.TLSKey
		}
		return httpapi.Serve(run, c.HTTPAddr, LocalHandler(wal, auth, c.StatePath), cert, key)
	})
	return group.Wait()
}
