//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	sensorv1 "github.com/kkx600/StarBeacon/api/sensor/v1"
	"github.com/kkx600/StarBeacon/internal/admin"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/ingest"
	"github.com/kkx600/StarBeacon/internal/replay"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/testpcap"
	"github.com/kkx600/StarBeacon/internal/transport"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

type interruptedObject struct{ replay.Storage }

func (s interruptedObject) Open(context.Context, string) (io.ReadCloser, error) {
	return interruptedRead{}, nil
}

type interruptedRead struct{}

func (interruptedRead) Read([]byte) (int, error) { return 0, errors.New("受控存储读取中断") }
func (interruptedRead) Close() error             { return nil }

type waitingObjects struct {
	replay.Storage
	started chan struct{}
	closed  atomic.Int32
}
type waitingRead struct {
	ctx   context.Context
	owner *waitingObjects
}

func (s *waitingObjects) Open(ctx context.Context, key string) (io.ReadCloser, error) {
	s.started <- struct{}{}
	return waitingRead{ctx, s}, nil
}
func (r waitingRead) Read([]byte) (int, error) { <-r.ctx.Done(); return 0, r.ctx.Err() }
func (r waitingRead) Close() error             { r.owner.closed.Add(1); return nil }

func TestReplayDownloadMTLSObjectIntegrityLimitsAndCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f := newIsolatedDatabase(t, ctx)
	tenant := store.RandomID("it_download_")
	require(t, admin.Bootstrap(ctx, f.Owner, tenant, "样本传输验收", tenant, store.Token(), "admin"))
	u, _, err := f.Runtime.Password(ctx, tenant)
	require(t, err)
	dir := t.TempDir()
	ca := filepath.Join(dir, "pki")
	require(t, admin.DevPKI(ca))
	id, err := admin.Provision(ctx, f.Owner, tenant, "sensor_owned", "样本验证探针", ca, filepath.Join(dir, "identity"))
	require(t, err)
	serverTLS, err := transport.TLS(filepath.Join(ca, "ca.crt"), filepath.Join(ca, "server.crt"), filepath.Join(ca, "server.key"), true)
	require(t, err)
	clientTLS, err := transport.TLS(filepath.Join(ca, "ca.crt"), filepath.Join(dir, "identity", "agent.crt"), filepath.Join(dir, "identity", "agent.key"), false)
	require(t, err)
	connect := func(t *testing.T, service *ingest.Server) sensorv1.SensorServiceClient {
		t.Helper()
		listener, e := net.Listen("tcp", "127.0.0.1:0")
		require(t, e)
		server := grpc.NewServer(grpc.Creds(credentials.NewTLS(serverTLS)))
		sensorv1.RegisterSensorServiceServer(server, service)
		go func() { _ = server.Serve(listener) }()
		t.Cleanup(server.Stop)
		conn, e := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)))
		require(t, e)
		t.Cleanup(func() { _ = conn.Close() })
		return sensorv1.NewSensorServiceClient(conn)
	}
	objects, err := replay.NewLocal(filepath.Join(dir, "samples"), replay.MaxSampleBytes)
	require(t, err)
	data, err := testpcap.HTTP(false)
	require(t, err)
	sample := replay.Sample{ID: "sample_owned", Name: "握手验证.pcap", Size: int64(len(data))}
	require(t, f.Runtime.ReserveSample(ctx, u, sample, replay.MaxSampleBytes))
	sample.SHA256, sample.Format, err = objects.Put(ctx, replay.Key(tenant, sample.ID), bytes.NewReader(data), sample.Size)
	require(t, err)
	require(t, f.Runtime.CompleteSample(ctx, u, sample.ID, sample.SHA256, sample.Format, "import_sample"))
	_, signer, err := ed25519.GenerateKey(rand.Reader)
	require(t, err)
	payload, err := control.ReplayPayload(control.Replay{SampleID: sample.ID, SampleSHA256: sample.SHA256, SampleSize: sample.Size, RuleMode: "registered"})
	require(t, err)
	task, err := f.Runtime.CreateTask(ctx, u, id.SensorID, "rules.replay", "download_task", payload, signer)
	require(t, err)
	delivery, err := f.Runtime.NextTask(ctx, id)
	require(t, err)
	if delivery == nil || delivery.ID != task {
		t.Fatal("任务未绑定到传输设备")
	}
	client := connect(t, &ingest.Server{DB: f.Runtime, ControlOnly: true, Samples: objects})
	request := &sensorv1.ReplaySampleRequest{CommandId: task, SampleId: sample.ID}
	read := func(t *testing.T, client sensorv1.SensorServiceClient) ([]byte, error) {
		t.Helper()
		work, stop := context.WithTimeout(ctx, 3*time.Second)
		defer stop()
		stream, e := client.DownloadReplaySample(work, request)
		if e != nil {
			return nil, e
		}
		var received []byte
		for {
			chunk, e := stream.Recv()
			if e == io.EOF {
				return received, nil
			}
			if e != nil {
				return received, e
			}
			if chunk.Offset != uint64(len(received)) {
				t.Fatal("分块偏移不连续")
			}
			received = append(received, chunk.Data...)
		}
	}
	if received, e := read(t, client); e != nil || !bytes.Equal(received, data) {
		t.Fatal("健康样本传输不完整", e)
	}
	files, err := os.ReadDir(objects.Dir)
	require(t, err)
	if len(files) != 1 {
		t.Fatal("独立对象目录不是单一验收样本")
	}
	path := filepath.Join(objects.Dir, files[0].Name())
	for _, mode := range []string{"missing", "short", "long", "read_failure"} {
		t.Run(mode, func(t *testing.T) {
			want, testClient := codes.DataLoss, client
			switch mode {
			case "missing":
				require(t, os.Remove(path))
				want = codes.Unavailable
			case "short":
				require(t, os.WriteFile(path, data[:len(data)-1], 0600))
			case "long":
				require(t, os.WriteFile(path, append(append([]byte(nil), data...), 0), 0600))
			case "read_failure":
				testClient = connect(t, &ingest.Server{DB: f.Runtime, ControlOnly: true, Samples: interruptedObject{objects}})
				want = codes.Unavailable
			}
			_, e := read(t, testClient)
			if status.Code(e) != want {
				t.Fatal("损坏样本被视为正常传输", status.Code(e), want)
			}
			require(t, os.WriteFile(path, data, 0600))
		})
	}
	// 存储记录或任务损坏不能回退到调用方提供的摘要、长度或样本 ID。
	var command control.Command
	require(t, json.Unmarshal(delivery.Command, &command))
	for _, mode := range []string{"command_json", "payload_json", "sample_id", "sample_size"} {
		t.Run("invalid_task/"+mode, func(t *testing.T) {
			changed := command
			payload := control.Replay{SampleID: sample.ID, SampleSHA256: sample.SHA256, SampleSize: sample.Size, RuleMode: "registered"}
			if mode == "sample_id" {
				payload.SampleID = "sample_other"
			}
			if mode == "sample_size" {
				payload.SampleSize = 1
			}
			changed.Payload, err = json.Marshal(payload)
			require(t, err)
			if mode == "payload_json" {
				changed.Payload = json.RawMessage(`[]`)
			}
			raw, err := json.Marshal(changed)
			require(t, err)
			if mode == "command_json" {
				raw = []byte(`[]`)
			}
			require(t, f.Owner.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
				_, e := tx.Exec(ctx, `UPDATE sensor_tasks SET command=$3 WHERE tenant_id=$1 AND id=$2`, tenant, task, raw)
				return e
			}))
			if _, e := read(t, client); status.Code(e) != codes.PermissionDenied {
				t.Fatal("损坏任务获得样本下载权限", e)
			}
			require(t, f.Owner.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
				_, e := tx.Exec(ctx, `UPDATE sensor_tasks SET command=$3 WHERE tenant_id=$1 AND id=$2`, tenant, task, delivery.Command)
				return e
			}))
		})
	}
	waiting := &waitingObjects{Storage: objects, started: make(chan struct{}, 4)}
	limited := connect(t, &ingest.Server{DB: f.Runtime, ControlOnly: true, Samples: waiting})
	cancellations := []context.CancelFunc{}
	for i := 0; i < 4; i++ {
		work, stop := context.WithTimeout(ctx, 5*time.Second)
		cancellations = append(cancellations, stop)
		_, e := limited.DownloadReplaySample(work, request)
		require(t, e)
		select {
		case <-waiting.started:
		case <-work.Done():
			t.Fatal("传输额度测试未取得独立读取")
		}
	}
	if _, e := read(t, limited); status.Code(e) != codes.ResourceExhausted {
		t.Fatal("样本并发传输超过四个额度", e)
	}
	for _, stop := range cancellations {
		stop()
	}
	deadline := time.Now().Add(3 * time.Second)
	for waiting.closed.Load() != 4 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if waiting.closed.Load() != 4 {
		t.Fatal("传输取消未关闭源或归还额度")
	}
	if received, e := read(t, client); e != nil || !bytes.Equal(received, data) {
		t.Fatal("取消后未恢复健康样本传输", e)
	}
}
