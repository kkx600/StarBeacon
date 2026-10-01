// Package ingest 在身份、来源和路由验证后持久接收数据，控制信号走独立连接。
package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	sensorv1 "github.com/kkx600/StarBeacon/api/sensor/v1"
	"github.com/kkx600/StarBeacon/internal/bus"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/telemetry"
	"github.com/kkx600/StarBeacon/internal/transport"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type Server struct {
	sensorv1.UnimplementedSensorServiceServer
	DB          *store.Postgres
	Bus         *bus.Bus
	ControlOnly bool
}

func (s *Server) identity(ctx context.Context) (transport.SensorIdentity, error) {
	id, e := transport.PeerIdentity(ctx)
	if e != nil {
		return id, status.Error(codes.Unauthenticated, "未验证采集器身份")
	}
	if e = s.DB.SensorActive(ctx, id); e != nil {
		if errors.Is(e, store.ErrSensorInactive) {
			return id, status.Error(codes.PermissionDenied, "采集器未注册或已停用")
		}
		return id, status.Error(codes.Unavailable, "无法核验采集器状态，请保留本地数据重试")
	}
	return id, nil
}
func (s *Server) GetRoute(ctx context.Context, request *sensorv1.RouteRequest) (*sensorv1.Route, error) {
	if s.ControlOnly {
		return nil, status.Error(codes.Unimplemented, "路由由接入进程提供")
	}
	id, e := s.identity(ctx)
	if e != nil {
		return nil, e
	}
	if request.StreamId != "alerts" && request.StreamId != "context" {
		return nil, status.Error(codes.InvalidArgument, "未知数据流")
	}
	r, e := s.DB.Route(ctx, id, request.StreamId)
	if e != nil {
		return nil, status.Error(codes.Unavailable, "无法分配数据路由")
	}
	return &sensorv1.Route{Token: r.Token, TenantId: r.TenantID, Partition: r.Partition, StreamId: r.StreamID, ExpiresAt: timestamppb.New(r.ExpiresAt)}, nil
}
func (s *Server) UploadEvents(stream grpc.BidiStreamingServer[sensorv1.EventBatch, sensorv1.IngestAck]) error {
	if s.ControlOnly {
		return status.Error(codes.Unimplemented, "事件由接入进程提供")
	}
	for {
		b, e := stream.Recv()
		if e == io.EOF {
			return nil
		}
		if e != nil {
			return e
		}
		ctx, cancel := context.WithTimeout(stream.Context(), 15*time.Second)
		id, e := s.identity(ctx)
		if e != nil {
			cancel()
			return e
		}
		if e = contract.Validate(id.TenantID, id.SensorID, id.RegistrationID, b); e != nil {
			cancel()
			return status.Error(codes.InvalidArgument, "批次校验失败")
		}
		r, e := s.DB.ResolveRoute(ctx, id, b.RouteToken, b.StreamId)
		if e != nil {
			cancel()
			return status.Error(codes.FailedPrecondition, "数据路由无效或超出保留窗口")
		}
		raw, e := proto.Marshal(b)
		if e != nil {
			cancel()
			return status.Error(codes.InvalidArgument, "批次编码失败")
		}
		e = s.Bus.Publish(ctx, "sb.events."+b.StreamId, b.BatchId, bus.Envelope{TenantID: id.TenantID, Partition: r.Partition, ReceivedAt: time.Now().UTC(), Batch: raw})
		cancel()
		if e != nil {
			return status.Error(codes.Unavailable, "持久队列暂时不可用，请保留本地数据重试")
		}
		telemetry.Accepted.WithLabelValues(b.StreamId).Add(float64(len(b.Records)))
		a := &sensorv1.IngestAck{BatchId: b.BatchId, ProducerEpoch: b.ProducerEpoch, AcceptedRanges: contract.Ranges(b.Records), Status: sensorv1.AckStatus_ACK_STATUS_ACCEPTED, SensorRegistrationId: b.SensorRegistrationId, StreamId: b.StreamId, BatchSha256: b.BatchSha256}
		if e = stream.Send(a); e != nil {
			return e
		}
	}
}
func (s *Server) Control(stream grpc.BidiStreamingServer[sensorv1.AgentMessage, sensorv1.PlatformCommand]) error {
	if !s.ControlOnly {
		return status.Error(codes.Unimplemented, "控制流由平台进程提供")
	}
	for {
		m, e := stream.Recv()
		if e == io.EOF {
			return nil
		}
		if e != nil {
			return e
		}
		ctx, cancel := context.WithTimeout(stream.Context(), 10*time.Second)
		id, e := s.identity(ctx)
		if e != nil {
			cancel()
			return e
		}
		if m.SensorId != id.SensorID || m.SensorRegistrationId != id.RegistrationID || m.Kind != sensorv1.AgentMessageKind_AGENT_MESSAGE_KIND_HEARTBEAT || m.PayloadSchema != "host.health.v1" || len(m.PayloadJson) > 64*1024 {
			cancel()
			return status.Error(codes.InvalidArgument, "控制消息不合法")
		}
		var h model.HostHealth
		if e = json.Unmarshal(m.PayloadJson, &h); e != nil {
			cancel()
			return status.Error(codes.InvalidArgument, "健康消息不合法")
		}
		if h.ObservedAt.IsZero() {
			cancel()
			return status.Error(codes.InvalidArgument, "健康消息缺少观察时间")
		}
		if e = s.DB.Heartbeat(ctx, id, h); e != nil {
			cancel()
			return status.Error(codes.Unavailable, "无法保存健康状态")
		}
		cancel()
		if e = stream.Send(&sensorv1.PlatformCommand{CommandId: m.MessageId, Kind: sensorv1.CommandKind_COMMAND_KIND_HEARTBEAT_ACK, ExpiresAt: timestamppb.New(time.Now().Add(time.Minute))}); e != nil {
			return e
		}
	}
}
