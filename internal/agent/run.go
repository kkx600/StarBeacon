package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"sync"
	"time"

	sensorv1 "github.com/kkx600/StarBeacon/api/sensor/v1"
	"github.com/kkx600/StarBeacon/internal/config"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/probepki"
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
	var identity *probepki.Local
	if c.IdentityDir != "" {
		var err error
		identity, err = probepki.OpenLocal(c.IdentityDir, c.IdentityRoot, transport.SensorIdentity{TenantID: c.TenantID, SensorID: c.SensorID, RegistrationID: c.RegistrationID})
		if err != nil {
			return err
		}
		defer identity.Close()
		if identity.Status().Fingerprint == "" {
			return fmt.Errorf("探针尚未完成 CSR 注册")
		}
	}
	wal, e := OpenWAL(c.StatePath, c.TenantID, c.SensorID, c.RegistrationID, c.WALBytes)
	if e != nil {
		return e
	}
	defer wal.Close()
	if identity != nil {
		wal.certificateStatus = identity.Status
	}
	publicKey, e := control.PublicKey(c.CommandPublicKey)
	if e != nil {
		return e
	}
	engine := &Engine{Config: c, WAL: wal}
	engine.Applications, e = NewApplicationService(wal)
	if e != nil {
		// 附加分类不可用不应停止基础采集；保留损坏配置供核对，不宣称空快照已生效。
		engine.Applications = nil
		wal.setFailure("application_state_unavailable", true)
		slog.Error("应用规则状态无法核对，协议数据继续按原始记录上报", "error", e)
	}
	if engine.Applications != nil {
		wal.applicationState = func() json.RawMessage {
			raw, _ := json.Marshal(engine.Applications.Snapshot())
			return raw
		}
	}
	if c.ResponseConnectorsFile != "" {
		engine.Response, e = NewResponseService(wal, c.ResponseConnectorsFile, c.PlatformAddr, c.IngestAddr)
		if e != nil {
			return e
		}
		defer engine.Response.Close()
		wal.responseHealth = engine.Response.Health
		wal.responseConfigCheck = engine.Response.CheckConfiguration
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
	protocols := &ProtocolInspector{Engine: engine}
	wal.protocolSnapshot = protocols.Snapshot
	monitor := &EngineMonitor{Engine: engine}
	wal.engineSnapshot = monitor.Snapshot
	if len(publicKey) > 0 {
		wal.taskCapabilities = engine.Capabilities()
		wal.capabilities = engine.Capabilities
		wal.commandSignerSHA256 = control.Digest(publicKey)
	}
	tlsConfig, e := transport.TLS(c.TLSCA, c.TLSCert, c.TLSKey, false)
	if e != nil {
		return e
	}
	if identity != nil {
		tlsConfig.Certificates = nil
		tlsConfig.GetClientCertificate = identity.ClientCertificate
	}
	rawData, e := grpc.NewClient(c.IngestAddr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)), grpc.WithDefaultCallOptions(grpc.MaxCallSendMsgSize(4*1024*1024)))
	if e != nil {
		return e
	}
	data := transport.NewRotatingConn(rawData)
	defer data.Close()
	rawControl, e := grpc.NewClient(c.PlatformAddr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig.Clone())))
	if e != nil {
		return e
	}
	controlConnection := transport.NewRotatingConn(rawControl)
	defer controlConnection.Close()
	var packetConnection *transport.RotatingConn
	if packets != nil {
		var rawPacket *grpc.ClientConn
		rawPacket, e = grpc.NewClient(c.PlatformAddr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig.Clone())), grpc.WithDefaultCallOptions(grpc.MaxCallSendMsgSize(1024*1024)))
		if e != nil {
			return e
		}
		packetConnection = transport.NewRotatingConn(rawPacket)
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
	if engine.Applications != nil {
		reader.Attribute = engine.Applications.Attribute
	}
	if capture != nil {
		reader.CanSwitch = capture.CanSwitchSource
		reader.ObserveStats = capture.ObserveStats
	}
	defer reader.Close()
	local, e := NewLocalIdentity(wal, c.LocalPassword)
	if e != nil {
		return e
	}
	auth := httpapi.NewAuth(local, nil, c.AllowedOrigin, c.CookieName, c.Mode == "production")
	group, run := errgroup.WithContext(ctx)
	if identity != nil {
		group.Go(func() error {
			return runCertificateRenewal(run, c, identity, tlsConfig, wal, data, controlConnection, packetConnection)
		})
	}
	group.Go(func() error { protocols.Run(run); return nil })
	group.Go(func() error { monitor.Run(run); return nil })
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
			if c.HTTPTLSCert != "" {
				cert, key = c.HTTPTLSCert, c.HTTPTLSKey
			}
		}
		return httpapi.ServeWithClientIP(run, c.HTTPAddr, LocalHandler(wal, auth, c.StatePath, tasks), cert, key, c.HTTPClientIPs)
	})
	return group.Wait()
}
