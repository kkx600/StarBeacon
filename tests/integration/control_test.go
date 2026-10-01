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
	"github.com/kkx600/StarBeacon/internal/agent"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/ingest"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/replay"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/testpcap"
	"github.com/kkx600/StarBeacon/internal/transport"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

type diagnosticRunner struct{ calls atomic.Int32 }

func (r *diagnosticRunner) Execute(context.Context, control.Command) (json.RawMessage, string, error) {
	r.calls.Add(1)
	return json.RawMessage(`{"flow_id":"18446744073709551614","ok":true}`), "", nil
}

func TestPersistentControlTaskReceiptReplayAndRLS(t *testing.T) {
	if os.Getenv("SB_MODE") != "development" {
		t.Skip("使用独立开发依赖运行")
	}
	ctx, stop := context.WithTimeout(context.Background(), 30*time.Second)
	defer stop()
	owner, e := store.Open(ctx, os.Getenv("SB_MIGRATION_DATABASE_URL"))
	require(t, e)
	defer owner.Close()
	db, e := store.Open(ctx, os.Getenv("SB_DATABASE_URL"))
	require(t, e)
	defer db.Close()
	require(t, db.VerifyRuntimeRole(ctx))
	dir := t.TempDir()
	ca := filepath.Join(dir, "pki")
	require(t, admin.DevPKI(ca))
	tenants := []string{store.RandomID("it_ctrl_a_"), store.RandomID("it_ctrl_b_")}
	identities := make([]transport.SensorIdentity, 2)
	for i, tenant := range tenants {
		require(t, admin.Bootstrap(ctx, owner, tenant, "控制链路验收", tenant, store.Token(), "admin"))
		defer func() {
			clean, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			require(t, owner.TenantTx(clean, tenant, func(tx pgx.Tx) error {
				for _, q := range []string{"DELETE FROM sensor_tasks WHERE tenant_id=$1", "DELETE FROM replay_samples WHERE tenant_id=$1", "DELETE FROM rule_packages WHERE tenant_id=$1", "DELETE FROM operation_audits WHERE tenant_id=$1", "DELETE FROM login_audits WHERE tenant_id=$1", "DELETE FROM retention_policies WHERE tenant_id=$1", "DELETE FROM routes WHERE tenant_id=$1", "DELETE FROM sensors WHERE tenant_id=$1", "DELETE FROM users WHERE tenant_id=$1", "DELETE FROM tenants WHERE id=$1"} {
					if _, e := tx.Exec(clean, q, tenant); e != nil {
						return e
					}
				}
				return nil
			}))
		}()
		identities[i], e = admin.Provision(ctx, owner, tenant, "sensor_test", "控制验收探针", ca, filepath.Join(dir, tenant))
		require(t, e)
	}
	pub, priv, e := ed25519.GenerateKey(rand.Reader)
	require(t, e)
	u := model.Principal{TenantID: tenants[0], ID: "integration_admin", Role: "admin"}
	rule := `alert http any any -> any any (msg:"StarBeacon validation"; flow:established,to_server; http.uri; content:"/starbeacon/validation"; sid:1000001; rev:1;)`
	pkg, e := db.SaveRulePackage(ctx, u, "rules_test", "规则验收", rule, 0, "rules_create")
	require(t, e)
	_, e = db.SaveRulePackage(ctx, u, "rules_test", "规则验收", rule, 0, "rules_stale")
	if !errors.Is(e, store.ErrConflict) {
		t.Fatal("过期修订未拒绝", e)
	}
	_, e = db.RulePackage(ctx, tenants[1], pkg.ID, pkg.Revision)
	if !errors.Is(e, pgx.ErrNoRows) {
		t.Fatal("规则包跨租户可读", e)
	}
	wake := &control.Wakeup{}
	tls, e := transport.TLS(filepath.Join(ca, "ca.crt"), filepath.Join(ca, "server.crt"), filepath.Join(ca, "server.key"), true)
	require(t, e)
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	require(t, e)
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(tls)))
	objects, e := replay.NewLocal(filepath.Join(dir, "samples"), replay.MaxSampleBytes)
	require(t, e)
	sensorv1.RegisterSensorServiceServer(server, &ingest.Server{Samples: objects, DB: db, ControlOnly: true, TasksEnabled: true, Wakeup: wake})
	go server.Serve(listener)
	defer server.Stop()
	clients := make([]sensorv1.SensorServiceClient, 2)
	for i, tenant := range tenants {
		tls, e := transport.TLS(filepath.Join(ca, "ca.crt"), filepath.Join(dir, tenant, "agent.crt"), filepath.Join(dir, tenant, "agent.key"), false)
		require(t, e)
		conn, e := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(tls)))
		require(t, e)
		defer conn.Close()
		clients[i] = sensorv1.NewSensorServiceClient(conn)
	}
	stream, e := clients[0].Control(ctx)
	require(t, e)
	heartbeat := func() *sensorv1.AgentMessage {
		raw, _ := json.Marshal(model.HostHealth{ObservedAt: time.Now().UTC(), TaskCapabilities: []string{"diagnostics"}, CommandSignerSHA256: control.Digest(pub)})
		return &sensorv1.AgentMessage{SensorId: identities[0].SensorID, SensorRegistrationId: identities[0].RegistrationID, Kind: sensorv1.AgentMessageKind_AGENT_MESSAGE_KIND_HEARTBEAT, MessageId: store.RandomID("hb_"), PayloadSchema: "host.health.v1", PayloadJson: raw}
	}
	require(t, stream.Send(heartbeat()))
	ack, e := stream.Recv()
	require(t, e)
	if ack.Kind != sensorv1.CommandKind_COMMAND_KIND_HEARTBEAT_ACK {
		t.Fatal("心跳未确认")
	}
	ids := make([]string, 8)
	group, _ := errgroup.WithContext(ctx)
	for i := range ids {
		group.Go(func() error {
			var err error
			ids[i], err = db.CreateTask(ctx, u, "sensor_test", "diagnostics", "integration_same_key", json.RawMessage(`{}`), priv)
			return err
		})
	}
	require(t, group.Wait())
	for _, id := range ids {
		if id != ids[0] {
			t.Fatal("并发幂等请求创建多个任务")
		}
	}
	_, e = db.CreateTask(ctx, u, "sensor_test", "diagnostics", "integration_other_key", json.RawMessage(`{}`), priv)
	if !errors.Is(e, store.ErrConflict) {
		t.Fatal("同一设备并发任务未拒绝", e)
	}
	sent := time.Now()
	wake.Notify(tenants[0], "sensor_test")
	command, e := stream.Recv()
	require(t, e)
	if command.Kind != sensorv1.CommandKind_COMMAND_KIND_TASK || command.CommandId != ids[0] {
		t.Fatal("任务未准确投递")
	}
	if time.Since(sent) > 2*time.Second {
		t.Fatal("本进程任务唤醒未及时生效")
	}
	wal, e := agent.OpenWAL(filepath.Join(dir, "agent.db"), tenants[0], "sensor_test", identities[0].RegistrationID, 4*1024*1024)
	require(t, e)
	defer wal.Close()
	runner := &diagnosticRunner{}
	manager, e := agent.NewTaskManager(wal, pub, runner)
	require(t, e)
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- manager.Run(runCtx) }()
	require(t, manager.Accept(command.PayloadJson, command.Signature))
	require(t, manager.Accept(command.PayloadJson, command.Signature))
	var receipts [][]byte
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		receipts, e = manager.Pending()
		require(t, e)
		if len(receipts) == 1 {
			var receipt control.Receipt
			require(t, json.Unmarshal(receipts[0], &receipt))
			if receipt.State == "succeeded" {
				break
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	if len(receipts) != 1 || runner.calls.Load() != 1 {
		t.Fatal("任务执行或回执持久化异常")
	}
	var receipt control.Receipt
	require(t, json.Unmarshal(receipts[0], &receipt))
	if receipt.State != "succeeded" {
		t.Fatal("没有完成回执")
	}
	sendReceipt := func(s grpc.BidiStreamingClient[sensorv1.AgentMessage, sensorv1.PlatformCommand]) error {
		return s.Send(&sensorv1.AgentMessage{SensorId: "sensor_test", SensorRegistrationId: identities[0].RegistrationID, Kind: sensorv1.AgentMessageKind_AGENT_MESSAGE_KIND_TASK_RECEIPT, MessageId: store.RandomID("receipt_"), CommandId: receipt.CommandID, PayloadSchema: control.ReceiptSchema, PayloadJson: receipts[0]})
	}
	require(t, sendReceipt(stream))
	ack, e = stream.Recv()
	require(t, e)
	if ack.Kind != sensorv1.CommandKind_COMMAND_KIND_RECEIPT_ACK || ack.CommandId != receipt.CommandID {
		t.Fatal("回执未准确确认")
	}
	require(t, manager.Confirm(ack.CommandId, ack.PayloadSha256))
	records, e := db.Tasks(ctx, tenants[0], "sensor_test")
	require(t, e)
	if len(records) != 1 || records[0].State != "succeeded" {
		t.Fatal("ACK 前未持久保存执行结果")
	}
	var persisted control.Receipt
	require(t, json.Unmarshal(records[0].Receipt, &persisted))
	if persisted.Result == nil {
		t.Fatal("JSONB 回执未保存")
	}
	records, e = db.Tasks(ctx, tenants[1], "sensor_test")
	require(t, e)
	if len(records) != 0 {
		t.Fatal("任务跨租户可读")
	}
	require(t, stream.CloseSend())
	stream, e = clients[0].Control(ctx)
	require(t, e)
	require(t, sendReceipt(stream))
	ack, e = stream.Recv()
	require(t, e)
	require(t, manager.Confirm(ack.CommandId, ack.PayloadSha256))
	if runner.calls.Load() != 1 {
		t.Fatal("回执重放重复执行命令")
	}
	altered := receipt
	timeChanged := receipt.FinishedAt.Add(time.Second)
	altered.FinishedAt = &timeChanged
	if e = db.SaveReceipt(ctx, identities[0], altered); !errors.Is(e, store.ErrConflict) {
		t.Fatal("完成回执被不同结果覆盖", e)
	}
	id, e := db.CreateTask(ctx, u, "sensor_test", "diagnostics", "integration_cancel_key", json.RawMessage(`{}`), priv)
	require(t, e)
	require(t, db.CancelTask(ctx, u, id, "cancel_test"))
	if e = db.CancelTask(ctx, u, id, "cancel_again"); !errors.Is(e, store.ErrConflict) {
		t.Fatal("重复取消不应覆盖终态")
	}

	// 此处验证传输授权与摘要；原生规则命中另由 TestNativeReplay 验收。
	sampleBytes, e := testpcap.HTTP(false)
	require(t, e)
	sample := replay.Sample{ID: "sample_transport", Name: "transport.pcap", Size: int64(len(sampleBytes))}
	require(t, db.ReserveSample(ctx, u, sample, replay.MaxSampleBytes))
	sample.SHA256, sample.Format, e = objects.Put(ctx, replay.Key(u.TenantID, sample.ID), bytes.NewReader(sampleBytes), sample.Size)
	require(t, e)
	require(t, db.CompleteSample(ctx, u, sample.ID, sample.SHA256, sample.Format, "sample_import"))
	stored, e := db.Sample(ctx, u.TenantID, sample.ID)
	require(t, e)
	if stored.ExpiresAt.Sub(stored.CreatedAt) < 179*24*time.Hour {
		t.Fatal("样本默认留存不足 180 天")
	}
	if _, e = db.Sample(ctx, tenants[1], sample.ID); !errors.Is(e, pgx.ErrNoRows) {
		t.Fatal("样本索引跨租户可读", e)
	}
	payload, e := control.ReplayPayload(control.Replay{SampleID: sample.ID, SampleSHA256: sample.SHA256, SampleSize: sample.Size, RuleMode: "registered"})
	require(t, e)
	replayID, e := db.CreateTask(ctx, u, "sensor_test", "rules.replay", "transport_replay_key", payload, priv)
	require(t, e)
	delivery, e := db.NextTask(ctx, identities[0])
	require(t, e)
	if delivery == nil || delivery.ID != replayID {
		t.Fatal("重放任务未绑定目标设备")
	}
	for _, client := range clients[1:] {
		transfer, e := client.DownloadReplaySample(ctx, &sensorv1.ReplaySampleRequest{CommandId: replayID, SampleId: sample.ID})
		if e == nil {
			_, e = transfer.Recv()
		}
		if status.Code(e) != codes.PermissionDenied {
			t.Fatal("其他租户可下载重放样本", e)
		}
	}
	transfer, e := clients[0].DownloadReplaySample(ctx, &sensorv1.ReplaySampleRequest{CommandId: replayID, SampleId: sample.ID})
	require(t, e)
	received := []byte{}
	for {
		chunk, e := transfer.Recv()
		if e == io.EOF {
			break
		}
		require(t, e)
		if chunk.Offset != uint64(len(received)) {
			t.Fatal("样本分块偏移不连续")
		}
		received = append(received, chunk.Data...)
	}
	if !bytes.Equal(sampleBytes, received) || control.Digest(received) != sample.SHA256 {
		t.Fatal("下载改变了样本字节或摘要")
	}
	finished := time.Now().UTC()
	require(t, db.SaveReceipt(ctx, identities[0], control.Receipt{CommandID: replayID, CommandSHA256: control.Digest(delivery.Command), State: "succeeded", StartedAt: finished, FinishedAt: &finished, Result: json.RawMessage(`{"transport_test":true}`)}))
	after, e := clients[0].DownloadReplaySample(ctx, &sensorv1.ReplaySampleRequest{CommandId: replayID, SampleId: sample.ID})
	if e == nil {
		_, e = after.Recv()
	}
	if status.Code(e) != codes.PermissionDenied {
		t.Fatal("终态任务仍允许下载样本", e)
	}
	audits, e := db.Audits(ctx, u.TenantID, "operations", store.AuditQuery{Start: time.Now().Add(-time.Hour), End: time.Now().Add(time.Minute), Limit: 1})
	require(t, e)
	if len(audits.Items) != 1 || audits.NextCursor == "" {
		t.Fatal("审计游标未返回")
	}
	other, e := db.Audits(ctx, tenants[1], "operations", store.AuditQuery{Start: time.Now().Add(-time.Hour), End: time.Now().Add(time.Minute), Limit: 100})
	require(t, e)
	if len(other.Items) != 0 {
		t.Fatal("审计跨租户可读")
	}

	require(t, owner.TenantTx(ctx, tenants[0], func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, "UPDATE sensors SET active=false WHERE tenant_id=$1", tenants[0])
		return e
	}))
	require(t, stream.Send(heartbeat()))
	_, e = stream.Recv()
	if status.Code(e) != codes.PermissionDenied {
		t.Fatal("停用设备的持续控制连接仍有效", e)
	}
	cancel()
	require(t, <-done)
}
