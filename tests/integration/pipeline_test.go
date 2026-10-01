//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	sensorv1 "github.com/kkx600/StarBeacon/api/sensor/v1"
	"github.com/kkx600/StarBeacon/internal/admin"
	"github.com/kkx600/StarBeacon/internal/agent"
	"github.com/kkx600/StarBeacon/internal/bus"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/ingest"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/transport"
	"github.com/kkx600/StarBeacon/internal/worker"
	"github.com/nats-io/nats.go/jetstream"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

func require(t *testing.T, e error) {
	t.Helper()
	if e != nil {
		t.Fatal(e)
	}
}

func TestMTLSDurableIngestIndexReplayAndTenantIsolation(t *testing.T) {
	if os.Getenv("SB_MODE") != "development" || os.Getenv("SB_MIGRATION_DATABASE_URL") == "" {
		t.Skip("仅在独立开发依赖中运行；使用 make integration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	owner, e := store.Open(ctx, os.Getenv("SB_MIGRATION_DATABASE_URL"))
	require(t, e)
	defer owner.Close()
	db, e := store.Open(ctx, os.Getenv("SB_DATABASE_URL"))
	require(t, e)
	defer db.Close()
	require(t, db.VerifyRuntimeRole(ctx))
	queue, e := bus.OpenNamespace(ctx, os.Getenv("SB_NATS_URL"), store.RandomID("it_"))
	require(t, e)
	defer queue.Close()
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for _, name := range []string{bus.Alerts, bus.Context, bus.Quarantine, bus.Indexed} {
			_ = queue.JS.DeleteStream(cleanup, queue.StreamName(name))
		}
	}()
	require(t, queue.Ensure(ctx, 1, 16*1024*1024))
	es, e := store.OpenES(os.Getenv("SB_ES_URL"), "")
	require(t, e)
	require(t, es.EnsurePolicy(ctx))
	dir := t.TempDir()
	ca := filepath.Join(dir, "pki")
	require(t, admin.DevPKI(ca))
	tenants := []string{store.RandomID("it_a_"), store.RandomID("it_b_")}
	for _, tenant := range tenants {
		require(t, admin.Bootstrap(ctx, owner, tenant, "工程集成验收", tenant, store.Token(), "admin"))
		defer func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			e := owner.TenantTx(cleanup, tenant, func(tx pgx.Tx) error {
				for _, query := range []string{"DELETE FROM operation_audits WHERE tenant_id=$1", "DELETE FROM login_audits WHERE tenant_id=$1", "DELETE FROM retention_policies WHERE tenant_id=$1", "DELETE FROM routes WHERE tenant_id=$1", "DELETE FROM sensors WHERE tenant_id=$1", "DELETE FROM sessions WHERE user_id IN(SELECT id FROM users WHERE tenant_id=$1)", "DELETE FROM users WHERE tenant_id=$1", "DELETE FROM tenants WHERE id=$1"} {
					if _, e := tx.Exec(cleanup, query, tenant); e != nil {
						return e
					}
				}
				return nil
			})
			if e != nil {
				t.Error("清理验收租户失败", e)
			}
		}()
	}
	identities := make([]transport.SensorIdentity, 2)
	for i, tenant := range tenants {
		identities[i], e = admin.Provision(ctx, owner, tenant, "sensor_test", "验收探针", ca, filepath.Join(dir, tenant))
		require(t, e)
	}
	tlsServer, e := transport.TLS(filepath.Join(ca, "ca.crt"), filepath.Join(ca, "server.crt"), filepath.Join(ca, "server.key"), true)
	require(t, e)
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	require(t, e)
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsServer)))
	sensorv1.RegisterSensorServiceServer(server, &ingest.Server{DB: db, Bus: queue})
	go func() { _ = server.Serve(listener) }()
	defer server.Stop()
	clients := make([]sensorv1.SensorServiceClient, 2)
	for i, tenant := range tenants {
		tlsClient, e := transport.TLS(filepath.Join(ca, "ca.crt"), filepath.Join(dir, tenant, "agent.crt"), filepath.Join(dir, tenant, "agent.key"), false)
		require(t, e)
		connection, e := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(tlsClient)))
		require(t, e)
		defer connection.Close()
		clients[i] = sensorv1.NewSensorServiceClient(connection)
	}
	route, e := clients[0].GetRoute(ctx, &sensorv1.RouteRequest{StreamId: "alerts"})
	require(t, e)
	if route.TenantId != tenants[0] {
		t.Fatal("路由没有绑定证书租户")
	}
	w, e := agent.OpenWAL(filepath.Join(dir, "agent.db"), tenants[0], "sensor_test", identities[0].RegistrationID, 8192)
	require(t, e)
	defer w.Close()
	evePath := filepath.Join(dir, "eve.json")
	raw := `{"timestamp":"` + time.Now().UTC().Format(time.RFC3339Nano) + `","event_type":"alert","flow_id":18446744073709551614,"src_ip":"192.0.2.10","dest_ip":"198.51.100.20","proto":"TCP","app_proto":"http","ether":{"src_mac":"02:00:00:00:00:10"},"http":{"http_method":"POST","url":"/integration"},"alert":{"signature_id":9100002,"severity":1,"signature":"StarBeacon 工程集成验收样本"}}`
	require(t, os.WriteFile(evePath, []byte(raw+"\n"), 0600))
	reader := &agent.EVEReader{WAL: w, Path: evePath, Route: func(context.Context, string) (string, error) { return route.Token, nil }}
	defer reader.Close()
	require(t, reader.Poll(ctx))
	batch, e := w.Next("alerts")
	require(t, e)
	stream, e := clients[0].UploadEvents(ctx)
	require(t, e)
	require(t, stream.Send(batch))
	ack, e := stream.Recv()
	require(t, e)
	require(t, contract.ValidateAck(batch, ack))
	require(t, stream.CloseSend())
	// ACK 后从真实持久流读取，不能用内存中自行构造的信封代替交付证据。
	alertStream, e := queue.JS.Stream(ctx, queue.StreamName(bus.Alerts))
	require(t, e)
	message, e := alertStream.GetLastMsgForSubject(ctx, queue.Subject("sb.events.alerts"))
	require(t, e)
	var envelope bus.Envelope
	require(t, json.Unmarshal(message.Data, &envelope))
	if envelope.TenantID != tenants[0] {
		t.Fatal("持久流中的租户来源错误")
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = alertStream.DeleteMsg(cleanup, message.Sequence)
	}()
	index, e := contract.IndexName(tenants[0], "alerts", route.Partition)
	require(t, e)
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		res, e := es.API.Indices.Delete([]string{index}, es.API.Indices.Delete.WithContext(cleanup))
		if e == nil {
			res.Body.Close()
		}
	}()
	indexer := &worker.Indexer{Bus: queue, ES: es}
	require(t, indexer.Process(ctx, message.Data))
	require(t, indexer.Process(ctx, message.Data))
	consumer, e := queue.Consumer(ctx, bus.Alerts)
	require(t, e)
	delivery, e := consumer.Fetch(1, jetstream.FetchMaxWait(3*time.Second))
	require(t, e)
	delivered := 0
	for msg := range delivery.Messages() {
		require(t, msg.DoubleAck(ctx))
		delivered++
	}
	require(t, delivery.Error())
	info, e := alertStream.Info(ctx)
	require(t, e)
	if delivered != 1 || info.State.Msgs != 0 {
		t.Fatal("完成索引的消息未按消费确认回收")
	}
	require(t, w.Confirm(batch, ack))
	count, _, e := w.Stats()
	require(t, e)
	if count != 0 {
		t.Fatal("合法持久确认没有回收本地队列")
	}
	res, e := es.API.Indices.Refresh(es.API.Indices.Refresh.WithIndex(index), es.API.Indices.Refresh.WithContext(ctx))
	require(t, e)
	res.Body.Close()
	query := model.SearchRequest{Start: time.Now().Add(-time.Hour), End: time.Now().Add(time.Minute), Protocol: "tcp"}
	a, e := es.Search(ctx, tenants[0], query)
	require(t, e)
	if a.Total != 1 || a.Items[0].Suricata.FlowID != "18446744073709551614" || a.Items[0].Source.MAC != "02:00:00:00:00:10" {
		t.Fatal("重放不幂等或字段精度丢失")
	}
	b, e := es.Search(ctx, tenants[1], query)
	require(t, e)
	if b.Total != 0 {
		t.Fatal("ES 检索穿透租户")
	}
	// 永久坏记录必须保全并回收接入消息，不能无限阻塞后续批次。
	for _, tc := range []struct{ raw, reason string }{
		{`{"timestamp":"9999-01-01T00:00:00Z","event_type":"alert","alert":{"signature":"时间超出 date_nanos 范围"}}`, "index_mapping_rejected"},
		{"{\"timestamp\":\"2026-10-01T00:00:00Z\",\"event_type\":\"alert\",\"alert\":{\"signature\":\"\xff\"}}", "normalize_failed"},
	} {
		file, e := os.OpenFile(evePath, os.O_WRONLY|os.O_APPEND, 0600)
		require(t, e)
		_, e = file.WriteString(tc.raw + "\n")
		require(t, e)
		require(t, file.Close())
		require(t, reader.Poll(ctx))
		batch, e := w.Next("alerts")
		require(t, e)
		if batch == nil || len(batch.Records) != 1 {
			t.Fatal("坏记录未保留在持久队列")
		}
		stream, e := clients[0].UploadEvents(ctx)
		require(t, e)
		require(t, stream.Send(batch))
		ack, e := stream.Recv()
		require(t, e)
		require(t, stream.CloseSend())
		message, e := alertStream.GetLastMsgForSubject(ctx, queue.Subject("sb.events.alerts"))
		require(t, e)
		require(t, indexer.Process(ctx, message.Data))
		quarantine, e := queue.JS.Stream(ctx, queue.StreamName(bus.Quarantine))
		require(t, e)
		stored, e := quarantine.GetLastMsgForSubject(ctx, queue.Subject("sb.quarantine"))
		require(t, e)
		var record struct {
			Reason  string `json:"reason"`
			EventID string `json:"event_id"`
		}
		require(t, json.Unmarshal(stored.Data, &record))
		if record.Reason != tc.reason || record.EventID != batch.Records[0].EventId {
			t.Fatalf("异常隔离丢失来源或错误分类：%+v", record)
		}
		delivery, e := consumer.Fetch(1, jetstream.FetchMaxWait(3*time.Second))
		require(t, e)
		for msg := range delivery.Messages() {
			require(t, msg.DoubleAck(ctx))
		}
		require(t, delivery.Error())
		require(t, w.Confirm(batch, ack))
		count, _, e := w.Stats()
		require(t, e)
		if count != 0 {
			t.Fatal("持久隔离后的本地批次未回收")
		}
	}
	require(t, db.TenantTx(ctx, tenants[1], func(tx pgx.Tx) error {
		var count int
		e := tx.QueryRow(ctx, "SELECT count(*) FROM sensors WHERE tenant_id=$1", tenants[0]).Scan(&count)
		if count != 0 {
			t.Error("RLS 暴露其他租户探针")
		}
		return e
	}))
	// 同一条证书连接在停用后也不能继续获取路由。
	var principal model.Principal
	require(t, owner.Pool.QueryRow(ctx, "SELECT id,tenant_id,username,role FROM users WHERE username=$1", tenants[0]).Scan(&principal.ID, &principal.TenantID, &principal.Username, &principal.Role))
	require(t, db.SetSensorActive(ctx, principal, "sensor_test", false, "integration_disable"))
	_, e = clients[0].GetRoute(ctx, &sensorv1.RouteRequest{StreamId: "alerts"})
	if status.Code(e) != codes.PermissionDenied {
		t.Fatal("存量连接绕过了停用状态", e)
	}
	_, e = clients[1].GetRoute(ctx, &sensorv1.RouteRequest{StreamId: "alerts"})
	require(t, e)
	var days int
	require(t, db.TenantTx(ctx, tenants[1], func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT days FROM retention_policies WHERE category='alerts'").Scan(&days)
	}))
	if days != 180 {
		t.Fatal("默认业务留存不是 180 天")
	}
}

func TestWorkQueueBackpressurePreservesUnprocessedMessages(t *testing.T) {
	if os.Getenv("SB_MODE") != "development" || os.Getenv("SB_NATS_URL") == "" {
		t.Skip("使用 make integration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	queue, e := bus.OpenNamespace(ctx, os.Getenv("SB_NATS_URL"), store.RandomID("it_"))
	require(t, e)
	defer queue.Close()
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for _, name := range []string{bus.Alerts, bus.Context, bus.Quarantine, bus.Indexed} {
			_ = queue.JS.DeleteStream(cleanup, queue.StreamName(name))
		}
	}()
	require(t, queue.Ensure(ctx, 1, 4096))
	payload := map[string]string{"payload": strings.Repeat("x", 3000)}
	require(t, queue.Publish(ctx, "sb.events.alerts", "one", payload))
	if queue.Publish(ctx, "sb.events.alerts", "two", payload) == nil {
		t.Fatal("队列已满仍确认新消息")
	}
	stream, e := queue.JS.Stream(ctx, queue.StreamName(bus.Alerts))
	require(t, e)
	info, e := stream.Info(ctx)
	require(t, e)
	if info.State.Msgs != 1 || info.Config.MaxAge != 0 || info.Config.Retention != jetstream.WorkQueuePolicy || info.Config.Discard != jetstream.DiscardNew {
		t.Fatal("未完成消息可能被时间或容量淘汰")
	}
	consumer, e := queue.Consumer(ctx, bus.Alerts)
	require(t, e)
	delivery, e := consumer.Fetch(1, jetstream.FetchMaxWait(3*time.Second))
	require(t, e)
	for msg := range delivery.Messages() {
		require(t, msg.DoubleAck(ctx))
	}
	require(t, delivery.Error())
	require(t, queue.Publish(ctx, "sb.events.alerts", "three", payload))
}
