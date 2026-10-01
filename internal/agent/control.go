package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sync/atomic"
	"time"

	sensorv1 "github.com/kkx600/StarBeacon/api/sensor/v1"
	"github.com/kkx600/StarBeacon/internal/config"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/store"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func controlLoop(ctx context.Context, client sensorv1.SensorServiceClient, wal *WAL, tasks *TaskManager, c config.Config) error {
	backoff := time.Second
	for ctx.Err() == nil {
		started := time.Now()
		e := controlSession(ctx, client, wal, tasks, c)
		if time.Since(started) > 30*time.Second {
			backoff = time.Second
		}
		wal.setFailure("control_unavailable", e != nil && ctx.Err() == nil)
		if ctx.Err() != nil {
			return nil
		}
		if e != nil {
			slog.Warn("控制连接等待恢复", "error", e)
		}
		if !pause(ctx, backoff) {
			return nil
		}
		backoff = min(backoff*2, 10*time.Second)
	}
	return nil
}
func controlSession(ctx context.Context, client sensorv1.SensorServiceClient, wal *WAL, tasks *TaskManager, c config.Config) error {
	group, run := errgroup.WithContext(ctx)
	var lastACK atomic.Int64
	lastACK.Store(time.Now().UnixNano())
	stream, e := client.Control(run)
	if e != nil {
		return e
	}
	group.Go(func() error {
		for {
			m, e := stream.Recv()
			if e != nil {
				return e
			}
			switch m.Kind {
			case sensorv1.CommandKind_COMMAND_KIND_HEARTBEAT_ACK:
				lastACK.Store(time.Now().UnixNano())
				wal.setFailure("control_unavailable", false)
			case sensorv1.CommandKind_COMMAND_KIND_RECEIPT_ACK:
				if e = tasks.Confirm(m.CommandId, m.PayloadSha256); e != nil {
					return e
				}
			case sensorv1.CommandKind_COMMAND_KIND_TASK:
				if m.PayloadSchema != control.Schema || !bytes.Equal(m.PayloadSha256, control.HashBytes(m.PayloadJson)) {
					return errors.New("控制任务契约无效")
				}
				if e = tasks.Accept(m.PayloadJson, m.Signature); e != nil {
					wal.setFailure("task_rejected", true)
					return e
				}
				wal.setFailure("task_rejected", false)
			default:
				return errors.New("未知平台控制消息")
			}
		}
	})
	group.Go(func() error {
		defer stream.CloseSend()
		heartbeat := time.NewTicker(c.HeartbeatInterval)
		defer heartbeat.Stop()
		receipts := time.NewTicker(500 * time.Millisecond)
		defer receipts.Stop()
		sendHealth := func() error {
			h := wal.Health(run, c.StatePath)
			raw, e := json.Marshal(h)
			if e != nil {
				return e
			}
			return stream.Send(&sensorv1.AgentMessage{SensorId: c.SensorID, SensorRegistrationId: c.RegistrationID, MessageId: store.RandomID("hb_"), Kind: sensorv1.AgentMessageKind_AGENT_MESSAGE_KIND_HEARTBEAT, PayloadSchema: "host.health.v1", PayloadJson: raw, ObservedAt: timestamppb.New(h.ObservedAt)})
		}
		if e := sendHealth(); e != nil {
			return e
		}
		for {
			select {
			case <-run.Done():
				return run.Err()
			case <-heartbeat.C:
				if time.Since(time.Unix(0, lastACK.Load())) > 3*c.HeartbeatInterval {
					return errors.New("平台心跳确认超时")
				}
				if e := sendHealth(); e != nil {
					return e
				}
			case <-receipts.C:
				pending, e := tasks.Pending()
				if e != nil {
					return e
				}
				for _, raw := range pending {
					var receipt control.Receipt
					if e = json.Unmarshal(raw, &receipt); e != nil {
						return e
					}
					if e = stream.Send(&sensorv1.AgentMessage{SensorId: c.SensorID, SensorRegistrationId: c.RegistrationID, MessageId: store.RandomID("receipt_"), CommandId: receipt.CommandID, Kind: sensorv1.AgentMessageKind_AGENT_MESSAGE_KIND_TASK_RECEIPT, PayloadSchema: control.ReceiptSchema, PayloadJson: raw, ObservedAt: timestamppb.Now()}); e != nil {
						return e
					}
				}
			}
		}
	})
	return group.Wait()
}
