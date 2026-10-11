package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sensorv1 "github.com/kkx600/StarBeacon/api/sensor/v1"
	"github.com/kkx600/StarBeacon/internal/config"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/testpcap"
	bolt "go.etcd.io/bbolt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

type streamFixture struct {
	sensorv1.UnimplementedSensorServiceServer
	control  func(grpc.BidiStreamingServer[sensorv1.AgentMessage, sensorv1.PlatformCommand]) error
	download func(*sensorv1.ReplaySampleRequest, grpc.ServerStreamingServer[sensorv1.ReplaySampleChunk]) error
	upload   func(grpc.BidiStreamingServer[sensorv1.EventBatch, sensorv1.IngestAck]) error
}

func (s streamFixture) Control(stream grpc.BidiStreamingServer[sensorv1.AgentMessage, sensorv1.PlatformCommand]) error {
	return s.control(stream)
}
func (s streamFixture) DownloadReplaySample(r *sensorv1.ReplaySampleRequest, stream grpc.ServerStreamingServer[sensorv1.ReplaySampleChunk]) error {
	return s.download(r, stream)
}
func (s streamFixture) UploadEvents(stream grpc.BidiStreamingServer[sensorv1.EventBatch, sensorv1.IngestAck]) error {
	return s.upload(stream)
}

func fixtureStreamClient(t *testing.T, s *streamFixture) sensorv1.SensorServiceClient {
	t.Helper()
	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	sensorv1.RegisterSensorServiceServer(server, s)
	go func() { _ = server.Serve(listener) }()
	connection, err := grpc.NewClient("passthrough:///owned-fixture", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return listener.DialContext(ctx) }))
	if err != nil {
		server.Stop()
		t.Fatal(err)
	}
	t.Cleanup(func() { connection.Close(); server.Stop(); listener.Close() })
	return sensorv1.NewSensorServiceClient(connection)
}

// 本组用例使用真实 gRPC 编解码与取消行为；mTLS 身份边界由独立集成用例验收。
func TestControlStreamRejectsBadCommandsAndMissingReceiptACK(t *testing.T) {
	for _, mode := range []string{"unknown", "schema", "digest", "signature", "receipt_missing", "heartbeat_timeout", "pending_corrupt"} {
		t.Run(mode, func(t *testing.T) {
			m, priv := taskFixture(t, terminalRunner{})
			raw, sig := signedFixtureCommand(t, m, priv, "task_stream", time.Now().UTC())
			client := fixtureStreamClient(t, &streamFixture{control: func(stream grpc.BidiStreamingServer[sensorv1.AgentMessage, sensorv1.PlatformCommand]) error {
				if _, err := stream.Recv(); err != nil {
					return err
				}
				message := &sensorv1.PlatformCommand{Kind: sensorv1.CommandKind_COMMAND_KIND_TASK, PayloadSchema: control.Schema, PayloadJson: raw, PayloadSha256: control.HashBytes(raw), Signature: sig}
				switch mode {
				case "unknown":
					message.Kind = sensorv1.CommandKind_COMMAND_KIND_UNSPECIFIED
				case "schema":
					message.PayloadSchema = "invalid"
				case "digest":
					message.PayloadSha256 = []byte("bad")
				case "signature":
					message.Signature = []byte("bad")
				case "receipt_missing":
					message.Kind = sensorv1.CommandKind_COMMAND_KIND_RECEIPT_ACK
					message.CommandId = "task_missing"
				case "heartbeat_timeout", "pending_corrupt":
					<-stream.Context().Done()
					return stream.Context().Err()
				}
				if err := stream.Send(message); err != nil {
					return err
				}
				<-stream.Context().Done()
				return stream.Context().Err()
			}})
			if mode == "pending_corrupt" {
				if err := m.Accept(raw, sig); err != nil {
					t.Fatal(err)
				}
				if err := m.WAL.DB.Update(func(tx *bolt.Tx) error {
					return tx.Bucket([]byte("sensor_tasks")).Put([]byte("task_stream"), []byte("{"))
				}); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			interval := time.Second
			if mode == "heartbeat_timeout" {
				interval = 100 * time.Millisecond
			}
			err := controlSession(ctx, client, m.WAL, m, config.Config{SensorID: m.WAL.SensorID, RegistrationID: m.WAL.RegistrationID, StatePath: m.WAL.DB.Path(), HeartbeatInterval: interval})
			if err == nil || errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("控制异常没有及时结束会话", err)
			}
			if mode == "heartbeat_timeout" && !strings.Contains(err.Error(), "心跳确认超时") {
				t.Fatal("缺少确认的心跳未识别", err)
			}
			if mode == "signature" {
				m.WAL.mu.RLock()
				rejected := m.WAL.failures["task_rejected"]
				m.WAL.mu.RUnlock()
				if !rejected {
					t.Fatal("无效签名未进入健康错误状态")
				}
			}
			if mode != "pending_corrupt" && len(m.queue) != 0 {
				t.Fatal("非法控制命令进入执行队列")
			}
		})
	}
}

func TestUploadFailureRetainsWALAndCancellationStopsRetry(t *testing.T) {
	for _, mode := range []string{"peer_error", "bad_ack", "closed_wal", "empty_wal"} {
		t.Run(mode, func(t *testing.T) {
			w, r, _ := readerFor(t, 1024*1024)
			if mode != "empty_wal" {
				if err := r.Poll(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			seen := make(chan struct{}, 1)
			client := fixtureStreamClient(t, &streamFixture{upload: func(stream grpc.BidiStreamingServer[sensorv1.EventBatch, sensorv1.IngestAck]) error {
				batch, err := stream.Recv()
				if err != nil {
					return err
				}
				seen <- struct{}{}
				if mode == "peer_error" {
					return status.Error(codes.Unavailable, "owned failure")
				}
				ack := acceptedBatch(batch)
				ack.BatchSha256 = []byte("bad")
				return stream.Send(ack)
			}})
			if mode == "closed_wal" {
				w.Close()
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() { upload(ctx, client, w, "alerts"); close(done) }()
			if mode == "peer_error" || mode == "bad_ack" {
				select {
				case <-seen:
				case <-time.After(2 * time.Second):
					cancel()
					t.Fatal("未执行上传")
				}
				eventuallyAgent(t, func() bool { w.mu.RLock(); defer w.mu.RUnlock(); return w.failures["upload_alerts_unavailable"] })
			} else {
				time.Sleep(30 * time.Millisecond)
			}
			cancel()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("重试循环未响应取消")
			}
			if mode == "peer_error" || mode == "bad_ack" {
				n, _, err := w.Stats()
				if err != nil || n != 1 {
					t.Fatal("失败上传回收了未确认的队列", n, err)
				}
			}
		})
	}
}
func eventuallyAgent(t *testing.T, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("未在期限内进入预期状态")
}

func TestReplayDownloadChecksStreamingOrderLengthAndDigest(t *testing.T) {
	data, err := testpcap.HTTP(false)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"valid", "out_of_order", "empty", "oversized_chunk", "oversized_total", "short", "digest", "interrupted", "unavailable", "missing_client", "missing_output"} {
		t.Run(mode, func(t *testing.T) {
			client := fixtureStreamClient(t, &streamFixture{download: func(request *sensorv1.ReplaySampleRequest, stream grpc.ServerStreamingServer[sensorv1.ReplaySampleChunk]) error {
				if request.CommandId != "task_download" || request.SampleId != "sample_download" {
					return status.Error(codes.InvalidArgument, "fixture identity mismatch")
				}
				if mode == "unavailable" {
					return status.Error(codes.Unavailable, "fixture unavailable")
				}
				chunk := &sensorv1.ReplaySampleChunk{Data: data}
				switch mode {
				case "out_of_order":
					chunk.Offset = 1
				case "empty":
					chunk.Data = nil
				case "oversized_chunk":
					chunk.Data = make([]byte, 128*1024+1)
				case "oversized_total":
					chunk.Data = append(append([]byte(nil), data...), 0)
				case "short":
					chunk.Data = data[:len(data)-1]
				}
				if err := stream.Send(chunk); err != nil {
					return err
				}
				if mode == "interrupted" {
					return status.Error(codes.Unavailable, "fixture interrupted")
				}
				return nil
			}})
			engine := &Engine{ReplayClient: client}
			if mode == "missing_client" {
				engine.ReplayClient = nil
			}
			p := control.Replay{SampleID: "sample_download", SampleSHA256: control.Digest(data), SampleSize: int64(len(data))}
			if mode == "digest" {
				p.SampleSHA256 = control.Digest([]byte("different"))
			}
			path := filepath.Join(t.TempDir(), "download.pcap")
			if mode == "missing_output" {
				path = filepath.Join(t.TempDir(), "missing", "download.pcap")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			err := engine.downloadSample(ctx, control.Command{ID: "task_download"}, p, path)
			if mode == "valid" {
				if err != nil {
					t.Fatal(err)
				}
				raw, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(raw, data) {
					t.Fatal("下载样本字节改变", err)
				}
			} else if err == nil {
				t.Fatal("损坏、不完整或不可用样本被接受")
			}
		})
	}
	engine := &Engine{}
	p := control.Replay{SampleID: "sample_missing", SampleSize: 24, SampleSHA256: control.Digest(data)}
	if err := engine.downloadSample(context.Background(), control.Command{ID: "localtask_missing", TenantID: "tenant_test"}, p, filepath.Join(t.TempDir(), "sample.pcap")); err == nil {
		t.Fatal("缺少本地样本服务仍完成下载")
	}
}

func TestReplayResultRejectsIncompleteOutputAndBoundsSummaries(t *testing.T) {
	for _, body := range []string{"{", "", `{"event_type":"flow"}`, `{"event_type":"stats","stats":{"decoder":{"pkts":0}}}`, `{"event_type":"stats","stats":{"decoder":{"pkts":"unknown"}}}`, strings.Repeat("x", 1024*1024+1)} {
		path := filepath.Join(t.TempDir(), "eve.json")
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := readReplayEvents(path); err == nil {
			t.Fatal("不完整或超限的引擎输出被接受")
		}
	}
	if _, err := readReplayEvents(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("不存在的结果被接受")
	}
	path := filepath.Join(t.TempDir(), "eve.json")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	encoder := json.NewEncoder(f)
	for i := 0; i < 201; i++ {
		if err = encoder.Encode(map[string]any{"event_type": "alert", "timestamp": "2026-10-03T00:00:00Z", "alert": map[string]any{"signature_id": i + 1, "signature": strings.Repeat("名", 1100)}}); err != nil {
			f.Close()
			t.Fatal(err)
		}
	}
	for i := 0; i < 12; i++ {
		if err = encoder.Encode(map[string]any{"event_type": "flow", "flow": map[string]any{"bytes_toserver": i}}); err != nil {
			f.Close()
			t.Fatal(err)
		}
	}
	for i := 0; i < 2; i++ {
		encoder.Encode(map[string]any{"event_type": "anomaly"})
	}
	encoder.Encode(map[string]any{"event_type": "stats", "stats": map[string]any{"decoder": map[string]any{"pkts": uint64(18446744073709551614)}}})
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	result, err := readReplayEvents(path)
	if err != nil {
		t.Fatal(err)
	}
	if result["alert_count"] != 201 || result["anomaly_count"] != 2 || result["alerts_truncated"] != true || result["rule_hits_truncated"] != true || len(result["alerts"].([]map[string]any)) != 30 || len(result["flow_samples"].([]map[string]any)) != 10 || result["packets_processed"] != "18446744073709551614" {
		t.Fatal("结果截断或大数精度不正确")
	}
	if text := result["alerts"].([]map[string]any)[0]["signature"].(string); len(text) > 1024+len("…") || !strings.HasSuffix(text, "…") {
		t.Fatal("结果文本没有遵守显示边界")
	}
	if boundedReplayText("短文本", 1024) != "短文本" {
		t.Fatal("正常文本被截断")
	}
}
