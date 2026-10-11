package agent

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"sync"
	"time"

	sensorv1 "github.com/kkx600/StarBeacon/api/sensor/v1"
	"github.com/kkx600/StarBeacon/internal/config"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/replay"
	"github.com/kkx600/StarBeacon/internal/transport"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
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
func Run(ctx context.Context, c config.Config) error {
	wal, e := OpenWAL(c.StatePath, c.TenantID, c.SensorID, c.RegistrationID, c.WALBytes)
	if e != nil {
		return e
	}
	defer wal.Close()
	publicKey, e := control.PublicKey(c.CommandPublicKey)
	if e != nil {
		return e
	}
	engine := &Engine{Config: c, WAL: wal}
	if c.ResponseConnectorsFile != "" {
		engine.Response, e = NewResponseService(wal, c.ResponseConnectorsFile, c.PlatformAddr, c.IngestAddr)
		if e != nil {
			return e
		}
		defer engine.Response.Close()
		wal.responseHealth = engine.Response.Health
	}
	var capture *CaptureSupervisor
	var packets *PacketArchiveController
	if c.CaptureManaged {
		capture, e = NewCaptureSupervisor(engine)
		if e != nil {
			return e
		}
		defer func() {
			stop, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			capture.Close(stop)
		}()
		if c.PacketCapture {
			packets, e = NewPacketArchiveController(c, wal, capture)
			if e != nil {
				return e
			}
			wal.packetArchives = packets
			packets.Start(ctx)
			defer packets.Close()
		}
		start, stop := context.WithTimeout(ctx, 20*time.Second)
		capture.Start(start)
		stop()
		c = engine.Config
		wal.captureSnapshot = capture.Snapshot
	}
	recovery, recoveryStop := context.WithTimeout(ctx, 40*time.Second)
	e = engine.Recover(recovery)
	recoveryStop()
	if e != nil {
		return fmt.Errorf("规则恢复未完成: %w", e)
	}
	tasks, e := NewTaskManager(wal, publicKey, engine)
	if e != nil {
		return e
	}
	tasks.RetentionDays = c.TaskRetentionDays
	storage, e := replay.NewLocal(c.ReplayDir, c.ReplayBytes)
	if e != nil {
		return e
	}
	samples := &ReplayService{WAL: wal, Storage: storage, Tasks: tasks, Engine: engine, RetentionDays: c.ReplayRetentionDays}
	engine.LocalReplay = samples
	tasks.Replay = samples
	tasks.Capture = capture
	wal.registeredRulesAvailable = c.SuricataRulesPath != ""
	wal.registeredRulesPath = c.SuricataRulesPath
	if len(publicKey) > 0 {
		wal.taskCapabilities = engine.Capabilities()
		wal.capabilities = engine.Capabilities
		wal.commandSignerSHA256 = control.Digest(publicKey)
	}
	tlsConfig, e := transport.TLS(c.TLSCA, c.TLSCert, c.TLSKey, false)
	if e != nil {
		return e
	}
	data, e := grpc.NewClient(c.IngestAddr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)), grpc.WithDefaultCallOptions(grpc.MaxCallSendMsgSize(4*1024*1024)))
	if e != nil {
		return e
	}
	defer data.Close()
	controlConnection, e := grpc.NewClient(c.PlatformAddr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig.Clone())))
	if e != nil {
		return e
	}
	defer controlConnection.Close()
	var packetConnection *grpc.ClientConn
	if packets != nil {
		packetConnection, e = grpc.NewClient(c.PlatformAddr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig.Clone())), grpc.WithDefaultCallOptions(grpc.MaxCallSendMsgSize(1024*1024)))
		if e != nil {
			return e
		}
		defer packetConnection.Close()
	}
	engine.ReplayClient = sensorv1.NewSensorServiceClient(controlConnection)
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
	if capture != nil {
		reader.CanSwitch = capture.CanSwitchSource
	}
	defer reader.Close()
	local, e := NewLocalIdentity(wal, c.LocalPassword)
	if e != nil {
		return e
	}
	auth := httpapi.NewAuth(local, nil, c.AllowedOrigin, c.CookieName, c.Mode == "production")
	group, run := errgroup.WithContext(ctx)
	if engine.Response != nil {
		group.Go(func() error { return engine.Response.Run(run) })
	}
	if packets != nil {
		group.Go(func() error { return packets.Upload(run, sensorv1.NewSensorServiceClient(packetConnection)) })
	}
	if capture != nil {
		group.Go(func() error { return capture.Run(run) })
	}
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
	group.Go(func() error { return tasks.Run(run) })
	group.Go(func() error {
		return tasks.RunRetention(run)
	})
	group.Go(func() error {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-run.Done():
				return nil
			case <-ticker.C:
				ctx, cancel := context.WithTimeout(run, 10*time.Second)
				e := samples.Sweep(ctx)
				cancel()
				if e != nil && run.Err() == nil {
					slog.Warn("本地重放样本清理未完成")
				}
			}
		}
	})
	group.Go(func() error {
		return controlLoop(run, sensorv1.NewSensorServiceClient(controlConnection), wal, tasks, c)
	})
	group.Go(func() error {
		cert, key := "", ""
		if c.Mode == "production" {
			cert, key = c.TLSCert, c.TLSKey
		}
		return httpapi.ServeWithClientIP(run, c.HTTPAddr, LocalHandler(wal, auth, c.StatePath, tasks), cert, key, c.HTTPClientIPs)
	})
	return group.Wait()
}
