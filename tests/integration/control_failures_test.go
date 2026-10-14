//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sensorv1 "github.com/kkx600/StarBeacon/api/sensor/v1"
	"github.com/kkx600/StarBeacon/internal/admin"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/ingest"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/protocolcap"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/transport"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

func TestMTLSRejectsInvalidControlAndBatchBeforeAcknowledgment(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	f := newIsolatedDatabase(t, ctx)
	tenant, password := store.RandomID("it_mtls_fault_"), store.Token()
	require(t, admin.Bootstrap(ctx, f.Owner, tenant, "传输边界验收", tenant, password, "admin"))
	dir := t.TempDir()
	ca := filepath.Join(dir, "pki")
	require(t, admin.DevPKI(ca))
	id, err := admin.Provision(ctx, f.Owner, tenant, "sensor_owned", "受控探针", ca, filepath.Join(dir, "identity"))
	require(t, err)
	serverTLS, err := transport.TLS(filepath.Join(ca, "ca.crt"), filepath.Join(ca, "server.crt"), filepath.Join(ca, "server.key"), true)
	require(t, err)
	clientTLS, err := transport.TLS(filepath.Join(ca, "ca.crt"), filepath.Join(dir, "identity", "agent.crt"), filepath.Join(dir, "identity", "agent.key"), false)
	require(t, err)
	connect := func(t *testing.T, service *ingest.Server) sensorv1.SensorServiceClient {
		t.Helper()
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		require(t, err)
		server := grpc.NewServer(grpc.Creds(credentials.NewTLS(serverTLS)))
		sensorv1.RegisterSensorServiceServer(server, service)
		go func() { _ = server.Serve(listener) }()
		t.Cleanup(server.Stop)
		conn, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)))
		require(t, err)
		t.Cleanup(func() { _ = conn.Close() })
		return sensorv1.NewSensorServiceClient(conn)
	}
	controlClient := connect(t, &ingest.Server{DB: f.Runtime, ControlOnly: true})
	health, err := json.Marshal(model.HostHealth{ObservedAt: time.Now().UTC()})
	require(t, err)
	base := &sensorv1.AgentMessage{SensorId: id.SensorID, SensorRegistrationId: id.RegistrationID, Kind: sensorv1.AgentMessageKind_AGENT_MESSAGE_KIND_HEARTBEAT, MessageId: "heartbeat_owned", PayloadSchema: "host.health.v1", PayloadJson: health}
	for _, mode := range []string{"sensor", "registration", "oversized", "schema", "json", "observed_time", "protocol_self_qualification", "receipt_schema", "receipt_json", "receipt_identity", "receipt_invalid", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			message := &sensorv1.AgentMessage{SensorId: base.SensorId, SensorRegistrationId: base.SensorRegistrationId, Kind: base.Kind, MessageId: base.MessageId, PayloadSchema: base.PayloadSchema, PayloadJson: append([]byte(nil), base.PayloadJson...)}
			want := codes.InvalidArgument
			switch mode {
			case "sensor":
				message.SensorId = "other_sensor"
			case "registration":
				message.SensorRegistrationId = "other_registration"
			case "oversized":
				message.PayloadJson = []byte(strings.Repeat("x", 72*1024+1))
			case "schema":
				message.PayloadSchema = "other.schema"
			case "json":
				message.PayloadJson = []byte(`{`)
			case "observed_time":
				message.PayloadJson = []byte(`{}`)
			case "protocol_self_qualification":
				message.PayloadJson, _ = json.Marshal(model.HostHealth{ObservedAt: time.Now().UTC(), ProtocolCapabilities: &protocolcap.Report{SchemaVersion: 1, State: "accepted", ObservedAt: time.Now().UTC()}})
			case "receipt_schema":
				message.Kind = sensorv1.AgentMessageKind_AGENT_MESSAGE_KIND_TASK_RECEIPT
			case "receipt_json":
				message.Kind = sensorv1.AgentMessageKind_AGENT_MESSAGE_KIND_TASK_RECEIPT
				message.PayloadSchema = control.ReceiptSchema
				message.PayloadJson = []byte(`{`)
			case "receipt_identity":
				message.Kind = sensorv1.AgentMessageKind_AGENT_MESSAGE_KIND_TASK_RECEIPT
				message.PayloadSchema = control.ReceiptSchema
				message.CommandId = "task_other"
				message.PayloadJson = []byte(`{"command_id":"task_owned"}`)
			case "receipt_invalid":
				message.Kind = sensorv1.AgentMessageKind_AGENT_MESSAGE_KIND_TASK_RECEIPT
				message.PayloadSchema = control.ReceiptSchema
				message.CommandId = "task_owned"
				message.PayloadJson = []byte(`{"command_id":"task_owned","state":"invalid"}`)
				want = codes.Unavailable
			case "unknown":
				message.Kind = sensorv1.AgentMessageKind(99)
			}
			work, stop := context.WithTimeout(ctx, 3*time.Second)
			defer stop()
			stream, err := controlClient.Control(work)
			require(t, err)
			_ = stream.Send(message)
			_, err = stream.Recv()
			if status.Code(err) != want {
				t.Fatal("非法控制消息得到确认或错误状态", status.Code(err), want)
			}
		})
	}
	client := connect(t, &ingest.Server{DB: f.Runtime})
	if _, err := client.GetRoute(ctx, &sensorv1.RouteRequest{StreamId: "unknown"}); status.Code(err) != codes.InvalidArgument {
		t.Fatal("未知事件流被分配路由", err)
	}
	stream, err := client.UploadEvents(ctx)
	require(t, err)
	_ = stream.Send(&sensorv1.EventBatch{})
	if _, err = stream.Recv(); status.Code(err) != codes.InvalidArgument {
		t.Fatal("非法批次被确认", err)
	}
	if _, err := controlClient.GetRoute(ctx, &sensorv1.RouteRequest{StreamId: "alerts"}); status.Code(err) != codes.Unimplemented {
		t.Fatal("控制进程接受事件路由", err)
	}
	stream, err = controlClient.UploadEvents(ctx)
	require(t, err)
	_ = stream.Send(&sensorv1.EventBatch{})
	if _, err = stream.Recv(); status.Code(err) != codes.Unimplemented {
		t.Fatal("控制进程接受事件上传", err)
	}
	wrongControl, err := client.Control(ctx)
	require(t, err)
	_ = wrongControl.Send(base)
	if _, err = wrongControl.Recv(); status.Code(err) != codes.Unimplemented {
		t.Fatal("接入进程接受控制流", err)
	}
	reader, err := controlClient.DownloadReplaySample(ctx, &sensorv1.ReplaySampleRequest{})
	require(t, err)
	if _, err = reader.Recv(); status.Code(err) != codes.Unimplemented {
		t.Fatal("缺少样本存储仍接受下载", err)
	}
	for _, prefix := range []string{"SELECT EXISTS(SELECT 1 FROM sensors", "INSERT INTO routes"} {
		t.Run("database_route/"+prefix, func(t *testing.T) {
			db, tracer := disconnectedStore(t, ctx, f.RuntimeDSN, prefix)
			fault := connect(t, &ingest.Server{DB: db})
			_, err := fault.GetRoute(ctx, &sensorv1.RouteRequest{StreamId: "alerts"})
			if status.Code(err) != codes.Unavailable || !tracer.fired.Load() {
				t.Fatal("依赖中断仍分配了路由", err)
			}
		})
	}
	t.Run("heartbeat_storage", func(t *testing.T) {
		db, tracer := disconnectedStore(t, ctx, f.RuntimeDSN, "UPDATE sensors")
		fault := connect(t, &ingest.Server{DB: db, ControlOnly: true})
		stream, err := fault.Control(ctx)
		require(t, err)
		_ = stream.Send(base)
		if _, err = stream.Recv(); status.Code(err) != codes.Unavailable || !tracer.fired.Load() {
			t.Fatal("未持久化健康状态仍被确认", err)
		}
	})
	t.Run("task_dispatch_storage", func(t *testing.T) {
		db, tracer := disconnectedStore(t, ctx, f.RuntimeDSN, "WITH picked")
		wake := &control.Wakeup{}
		fault := connect(t, &ingest.Server{DB: db, ControlOnly: true, TasksEnabled: true, Wakeup: wake})
		stream, err := fault.Control(ctx)
		require(t, err)
		require(t, stream.Send(base))
		_, err = stream.Recv()
		require(t, err)
		wake.Notify(tenant, id.SensorID)
		if _, err = stream.Recv(); status.Code(err) != codes.Unavailable || !tracer.fired.Load() {
			t.Fatal("未确认任务状态仍被下发", err)
		}
	})
	// 未提供任何经验证的 TLS 身份时，内部入口也不能回退到调用方字段。
	if _, err := (&ingest.Server{}).GetRoute(ctx, &sensorv1.RouteRequest{StreamId: "alerts"}); status.Code(err) != codes.Unauthenticated {
		t.Fatal("无身份入口没有拒绝", err)
	}
}
