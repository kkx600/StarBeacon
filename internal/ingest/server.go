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
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/replay"
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
	DB           *store.Postgres
	Bus          *bus.Bus
	ControlOnly  bool
	TasksEnabled bool
	Wakeup       *control.Wakeup
	Samples      replay.Storage
}

// 单进程最多四个样本传输，避免大文件读取挤占控制信号和事件接入。
var replayTransfers = make(chan struct{}, 4)

func (s *Server) DownloadReplaySample(request *sensorv1.ReplaySampleRequest, stream grpc.ServerStreamingServer[sensorv1.ReplaySampleChunk]) error {
	if !s.ControlOnly || s.Samples == nil {
		return status.Error(codes.Unimplemented, "样本传输未配置")
	}
	ctx, cancel := context.WithTimeout(stream.Context(), 90*time.Second)
	defer cancel()
	select {
	case replayTransfers <- struct{}{}:
	default:
		return status.Error(codes.ResourceExhausted, "样本传输额度已满，请稍后重试")
	}
	handedOff := false
	defer func() {
		if !handedOff {
			<-replayTransfers
		}
	}()
	id, e := s.identity(ctx)
	if e != nil {
		return e
	}
	sample, e := s.DB.SampleForTask(ctx, id, request.CommandId, request.SampleId)
	if e != nil {
		return status.Error(codes.PermissionDenied, "样本不属于当前设备执行任务")
	}
	source, e := s.Samples.Open(ctx, replay.Key(id.TenantID, sample.ID))
	if e != nil {
		return status.Error(codes.Unavailable, "样本存储不可用")
	}
	done := make(chan error, 1)
	handedOff = true
	// 超时后处理器返回，gRPC 关闭流并使阻塞的 Send 退出；额度在发送协程退出后释放。
	go func() {
		defer func() { <-replayTransfers }()
		defer source.Close()
		done <- s.sendReplaySample(ctx, stream, source, sample.Size)
	}()
	select {
	case e = <-done:
		return e
	case <-ctx.Done():
		return status.Error(codes.DeadlineExceeded, "样本传输超时或已取消")
	}
}
func (s *Server) sendReplaySample(ctx context.Context, stream grpc.ServerStreamingServer[sensorv1.ReplaySampleChunk], source io.Reader, size int64) error {
	buffer := make([]byte, 128*1024)
	var offset uint64
	var checked uint64
	for {
		if ctx.Err() != nil {
			return status.Error(codes.DeadlineExceeded, "样本传输超时")
		}
		n, e := source.Read(buffer)
		if n > 0 {
			if offset+uint64(n) > uint64(size) {
				return status.Error(codes.DataLoss, "样本长度不一致")
			}
			if offset == 0 || offset-checked >= 4*1024*1024 {
				if _, err := s.identity(ctx); err != nil {
					return err
				}
				checked = offset
			}
			if err := stream.Send(&sensorv1.ReplaySampleChunk{Offset: offset, Data: buffer[:n]}); err != nil {
				return err
			}
			offset += uint64(n)
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			return status.Error(codes.Unavailable, "样本读取中断")
		}
	}
	if offset != uint64(size) {
		return status.Error(codes.DataLoss, "样本长度不一致")
	}
	_, e := s.identity(ctx)
	return e
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
	id, e := s.identity(stream.Context())
	if e != nil {
		return e
	}
	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()
	telemetry.ControlConnections.Inc()
	defer telemetry.ControlConnections.Dec()
	type received struct {
		message *sensorv1.AgentMessage
		err     error
	}
	incoming := make(chan received, 1)
	// 每条流只有一个读取者和一个写入者；返回后 gRPC 取消传输并解除 Recv。
	go func() {
		for {
			m, e := stream.Recv()
			select {
			case incoming <- received{m, e}:
			case <-ctx.Done():
				return
			}
			if e != nil {
				return
			}
		}
	}()
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	var wake <-chan struct{}
	if s.Wakeup != nil {
		var stop func()
		wake, stop = s.Wakeup.Watch(id.TenantID, id.SensorID)
		defer stop()
	}
	dispatch := func() error {
		if !s.TasksEnabled {
			return nil
		}
		call, stop := context.WithTimeout(ctx, 3*time.Second)
		defer stop()
		v, err := s.DB.NextTask(call, id)
		if err != nil {
			return status.Error(codes.Unavailable, "任务状态暂时不可读取")
		}
		if v == nil {
			return nil
		}
		if _, err = s.identity(call); err != nil {
			return err
		}
		var command control.Command
		if e := json.Unmarshal(v.Command, &command); e != nil {
			return status.Error(codes.Internal, "持久任务编码不符合契约")
		}
		telemetry.CommandDeliveries.WithLabelValues(command.Kind).Inc()
		return stream.Send(&sensorv1.PlatformCommand{CommandId: v.ID, Kind: sensorv1.CommandKind_COMMAND_KIND_TASK, PayloadSchema: control.Schema, PayloadJson: v.Command, PayloadSha256: control.HashBytes(v.Command), Signature: v.Signature, ExpiresAt: timestamppb.New(command.ExpiresAt)})
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case item := <-incoming:
			if item.err == io.EOF {
				return nil
			}
			if item.err != nil {
				return item.err
			}
			m := item.message
			call, stop := context.WithTimeout(ctx, 10*time.Second)
			_, e = s.identity(call)
			if e != nil {
				stop()
				return e
			}
			if m.SensorId != id.SensorID || m.SensorRegistrationId != id.RegistrationID || len(m.PayloadJson) > 72*1024 {
				stop()
				return status.Error(codes.InvalidArgument, "控制消息身份或大小无效")
			}
			ack := &sensorv1.PlatformCommand{CommandId: m.MessageId, ExpiresAt: timestamppb.New(time.Now().Add(time.Minute))}
			switch m.Kind {
			case sensorv1.AgentMessageKind_AGENT_MESSAGE_KIND_HEARTBEAT:
				var h model.HostHealth
				if m.PayloadSchema != "host.health.v1" || json.Unmarshal(m.PayloadJson, &h) != nil || h.ObservedAt.IsZero() {
					stop()
					return status.Error(codes.InvalidArgument, "健康消息无效")
				}
				e = s.DB.Heartbeat(call, id, h)
				ack.Kind = sensorv1.CommandKind_COMMAND_KIND_HEARTBEAT_ACK
			case sensorv1.AgentMessageKind_AGENT_MESSAGE_KIND_TASK_RECEIPT:
				var receipt control.Receipt
				if m.PayloadSchema != control.ReceiptSchema || json.Unmarshal(m.PayloadJson, &receipt) != nil || m.CommandId != receipt.CommandID {
					stop()
					return status.Error(codes.InvalidArgument, "执行回执无效")
				}
				e = s.DB.SaveReceipt(call, id, receipt)
				ack.Kind = sensorv1.CommandKind_COMMAND_KIND_RECEIPT_ACK
				ack.CommandId = receipt.CommandID
				ack.PayloadSha256 = control.HashBytes(m.PayloadJson)
			default:
				stop()
				return status.Error(codes.InvalidArgument, "未知控制消息")
			}
			stop()
			if e != nil {
				return status.Error(codes.Unavailable, "控制状态未持久保存，请重试")
			}
			if e = stream.Send(ack); e != nil {
				return e
			}
		case <-tick.C:
			if e = dispatch(); e != nil {
				return e
			}
		case <-wake:
			if e = dispatch(); e != nil {
				return e
			}
		}
	}
}
