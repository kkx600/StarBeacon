//go:build integration

package integration

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"fmt"
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
	"github.com/kkx600/StarBeacon/internal/platform"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/syslogdata"
	"github.com/kkx600/StarBeacon/internal/transport"
	"github.com/kkx600/StarBeacon/internal/worker"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func TestSyslogTLSWALMTLSIndexSearchAndRawAudit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f, u, other, password := accountFixture(t, ctx)
	dir := t.TempDir()
	ca := filepath.Join(dir, "pki")
	require(t, admin.DevPKI(ca))
	sensorDir := filepath.Join(dir, "sensor")
	identity, err := admin.Provision(ctx, f.Owner, u.TenantID, "sensor_syslog", "日志接入探针", ca, sensorDir)
	require(t, err)
	queue, err := bus.OpenNamespace(ctx, os.Getenv("SB_NATS_URL"), store.RandomID("it_syslog_"))
	require(t, err)
	defer queue.Close()
	require(t, queue.Ensure(ctx, 1, 8<<20))
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		for _, name := range []string{bus.Alerts, bus.Context, bus.Logs, bus.Quarantine, bus.Indexed} {
			_ = queue.JS.DeleteStream(cleanup, queue.StreamName(name))
		}
	})
	es, err := store.OpenES(os.Getenv("SB_ES_URL"), os.Getenv("SB_ES_API_KEY"))
	require(t, err)
	serverTLS, err := transport.TLS(filepath.Join(ca, "ca.crt"), filepath.Join(ca, "server.crt"), filepath.Join(ca, "server.key"), true)
	require(t, err)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require(t, err)
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(serverTLS)))
	sensorv1.RegisterSensorServiceServer(server, &ingest.Server{DB: f.Runtime, Bus: queue})
	go func() { _ = server.Serve(listener) }()
	defer server.Stop()
	controlListener, err := net.Listen("tcp", "127.0.0.1:0")
	require(t, err)
	controlServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(serverTLS.Clone())))
	sensorv1.RegisterSensorServiceServer(controlServer, &ingest.Server{DB: f.Runtime, ControlOnly: true})
	go func() { _ = controlServer.Serve(controlListener) }()
	defer controlServer.Stop()

	clientTLS, err := transport.TLS(filepath.Join(ca, "ca.crt"), filepath.Join(sensorDir, "agent.crt"), filepath.Join(sensorDir, "agent.key"), false)
	require(t, err)
	connection, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)))
	require(t, err)
	defer connection.Close()
	client := sensorv1.NewSensorServiceClient(connection)
	controlConnection, err := grpc.NewClient(controlListener.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(clientTLS.Clone())))
	require(t, err)
	defer controlConnection.Close()
	controlClient := sensorv1.NewSensorServiceClient(controlConnection)

	certPEM, err := os.ReadFile(filepath.Join(sensorDir, "agent.crt"))
	require(t, err)
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("测试证书无效")
	}
	free, err := net.Listen("tcp", "127.0.0.1:0")
	require(t, err)
	endpoint := free.Addr().String()
	free.Close()
	source := syslogdata.Source{ID: "firewall_syslog", Name: "TLS 设备日志", NetworkDomain: "edge", Listen: endpoint, Transport: "tls", Format: "rfc5424", AllowedPeers: []string{"127.0.0.1/32"}, MaxMessageBytes: 4096, MaxConnections: 4, MaxEventsPerSecond: 100, TLS: syslogdata.TLSFiles{CertificateFile: filepath.Join(ca, "server.crt"), PrivateKeyFile: filepath.Join(ca, "server.key"), ClientCAFile: filepath.Join(ca, "ca.crt"), ClientFingerprints: []string{syslogdata.Hash(block.Bytes)}}}
	// Syslog TLS 材料为接收器独立私有文件，不改动平台证书或外部监听。
	for _, path := range []string{source.TLS.CertificateFile, source.TLS.PrivateKeyFile, source.TLS.ClientCAFile} {
		require(t, os.Chmod(path, 0600))
	}
	configRaw, _ := json.Marshal(syslogdata.File{SchemaVersion: "syslog.sources.v1", Sources: []syslogdata.Source{source}})
	configPath := filepath.Join(dir, "syslog.json")
	require(t, os.WriteFile(configPath, configRaw, 0600))
	walPath := filepath.Join(dir, "logs.db")
	wal, err := agent.OpenWAL(walPath, u.TenantID, identity.SensorID, identity.RegistrationID, 1<<20)
	require(t, err)
	receiver, err := agent.NewSyslogService(wal, configPath)
	require(t, err)
	receiveCtx, stopReceive := context.WithCancel(ctx)
	stopped := make(chan error, 1)
	go func() { stopped <- receiver.Run(receiveCtx) }()
	receiverStopped := false
	t.Cleanup(func() {
		if !receiverStopped {
			stopReceive()
			<-stopped
		}
		wal.Close()
	})
	for receiver.Health()[0].State != "listening" {
		select {
		case <-ctx.Done():
			t.Fatal("接收器未就绪")
		case <-time.After(5 * time.Millisecond):
		}
	}
	secure, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", endpoint, clientTLS.Clone())
	require(t, err)
	message := []byte("<13>1 " + time.Now().UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano) + " claimed-other-tenant firewall 8 audit [event@32473 kind=\"test\"] 防火墙访问拒绝\n第二行")
	for _, raw := range [][]byte{message, message, []byte("bad syslog body")} {
		_, err = fmt.Fprintf(secure, "%d %s", len(raw), raw)
		require(t, err)
	}
	for receiver.Health()[0].Persisted != "3" {
		select {
		case <-ctx.Done():
			t.Fatal("日志没有进入持久队列")
		case <-time.After(5 * time.Millisecond):
		}
	}
	secure.Close()
	// TLS 1.3 客户端可能先完成本侧握手，读取时仍必须收到接收器的认证拒绝。
	anonymous := clientTLS.Clone()
	anonymous.Certificates = nil
	denied, denyErr := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", endpoint, anonymous)
	if denyErr == nil {
		_ = denied.SetDeadline(time.Now().Add(2 * time.Second))
		_, _ = fmt.Fprint(denied, "1 x")
		buffer := make([]byte, 1)
		_, denyErr = denied.Read(buffer)
		denied.Close()
	}
	if denyErr == nil {
		t.Fatal("没有客户端证书的连接未拒绝")
	}
	otherDir := filepath.Join(dir, "unbound")
	_, err = admin.Provision(ctx, f.Owner, other.TenantID, "sensor_unbound", "未绑定日志来源", ca, otherDir)
	require(t, err)
	unbound, err := transport.TLS(filepath.Join(ca, "ca.crt"), filepath.Join(otherDir, "agent.crt"), filepath.Join(otherDir, "agent.key"), false)
	require(t, err)
	denied, denyErr = tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", endpoint, unbound)
	if denyErr == nil {
		_ = denied.SetDeadline(time.Now().Add(2 * time.Second))
		_, _ = fmt.Fprint(denied, "1 x")
		buffer := make([]byte, 1)
		_, denyErr = denied.Read(buffer)
		denied.Close()
	}
	if denyErr == nil {
		t.Fatal("同 CA 未登记指纹的设备被接受")
	}

	stopReceive()
	require(t, <-stopped)
	receiverStopped = true
	health := model.HostHealth{ObservedAt: time.Now().UTC(), SyslogSources: receiver.Health()}
	healthRaw, _ := json.Marshal(health)
	controlStream, err := controlClient.Control(ctx)
	require(t, err)
	require(t, controlStream.Send(&sensorv1.AgentMessage{SensorId: identity.SensorID, SensorRegistrationId: identity.RegistrationID, MessageId: "heartbeat_syslog", Kind: sensorv1.AgentMessageKind_AGENT_MESSAGE_KIND_HEARTBEAT, PayloadSchema: "host.health.v1", PayloadJson: healthRaw}))
	heartbeatAck, err := controlStream.Recv()
	require(t, err)
	if heartbeatAck.Kind != sensorv1.CommandKind_COMMAND_KIND_HEARTBEAT_ACK {
		t.Fatal("来源心跳未持久确认")
	}
	require(t, controlStream.CloseSend())

	first, err := wal.Next("logs")
	require(t, err)
	if first == nil || len(first.Records) != 3 || first.RouteToken != "" {
		t.Fatal("断网接收没有持久事实")
	}
	firstID := first.Records[0].EventId
	wal.Close()
	wal, err = agent.OpenWAL(walPath, u.TenantID, identity.SensorID, identity.RegistrationID, 1<<20)
	require(t, err)
	batch, err := wal.Next("logs")
	require(t, err)
	if batch.Records[0].EventId != firstID || batch.Records[0].EventId == batch.Records[1].EventId {
		t.Fatal("重启或同文事件身份不正确")
	}
	route, err := client.GetRoute(ctx, &sensorv1.RouteRequest{StreamId: "logs"})
	require(t, err)
	if route.TenantId != u.TenantID {
		t.Fatal("路由租户没有绑定证书")
	}
	require(t, wal.BindSyslogRoute(batch, route.Token))
	upload, err := client.UploadEvents(ctx)
	require(t, err)
	require(t, upload.Send(batch))
	ack, err := upload.Recv()
	require(t, err)
	require(t, contract.ValidateAck(batch, ack))
	require(t, upload.CloseSend())
	stream, err := queue.JS.Stream(ctx, queue.StreamName(bus.Logs))
	require(t, err)
	stored, err := stream.GetLastMsgForSubject(ctx, queue.Subject("sb.events.logs"))
	require(t, err)
	indexer := worker.Indexer{DB: f.Runtime, Bus: queue, ES: es}
	require(t, indexer.Process(ctx, stored.Data))
	// 冷启动回读既有映射与首次生命周期，重复投递只校验原事实。
	restartedES, err := store.OpenES(os.Getenv("SB_ES_URL"), os.Getenv("SB_ES_API_KEY"))
	require(t, err)
	restartedIndexer := worker.Indexer{DB: f.Runtime, Bus: queue, ES: restartedES}
	require(t, restartedIndexer.Process(ctx, stored.Data))
	var retryEnvelope bus.Envelope
	require(t, json.Unmarshal(stored.Data, &retryEnvelope))
	retryEnvelope.ReceivedAt = retryEnvelope.ReceivedAt.Add(time.Second)
	retryRaw, _ := json.Marshal(retryEnvelope)
	require(t, restartedIndexer.Process(ctx, retryRaw))
	index, err := contract.IndexName(u.TenantID, "logs", route.Partition)
	require(t, err)
	t.Cleanup(func() {
		res, e := es.API.Indices.Delete([]string{index})
		if e == nil {
			res.Body.Close()
		}
	})
	res, err := es.API.Indices.Refresh(es.API.Indices.Refresh.WithIndex(index))
	require(t, err)
	res.Body.Close()
	q := syslogdata.SearchQuery{Start: time.Now().Add(-time.Hour), End: time.Now().Add(time.Minute), Limit: 1}
	seen := map[string]bool{}
	for {
		page, err := es.SearchLogs(ctx, u.TenantID, q)
		require(t, err)
		if len(page.Items) != 1 || page.Items[0].Record.RawBase64 != "" {
			t.Fatal("分页不完整或列表泄漏原文")
		}
		if seen[page.Items[0].EventID] {
			t.Fatal("日志续页重复")
		}
		seen[page.Items[0].EventID] = true
		if page.NextCursor == "" {
			break
		}
		q.Cursor = page.NextCursor
	}
	if len(seen) != 3 {
		t.Fatal("同文日志或隔离记录丢失")
	}
	q.Cursor = ""
	q.Keyword = "防火墙访问拒绝"
	q.State = "parsed"
	q.Limit = 20
	page, err := es.SearchLogs(ctx, u.TenantID, q)
	require(t, err)
	if len(page.Items) != 2 {
		t.Fatal("中文分词检索未匹配")
	}
	isolated, err := es.SearchLogs(ctx, other.TenantID, q)
	require(t, err)
	if len(isolated.Items) != 0 {
		t.Fatal("跨租户日志可见")
	}
	http := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime, ES: es}, u.Username, password)
	var apiPage store.SyslogSearchPage
	http.request("POST", "/logs/search", "", q, &apiPage, 200)
	var document syslogdata.Document
	http.request("GET", "/logs/"+firstID+"?partition="+route.Partition, "", nil, &document, 200)
	if document.Record.Peer.CertificateSHA256 != source.TLS.ClientFingerprints[0] || document.Parsed.Hostname != "claimed-other-tenant" || document.TenantID != u.TenantID {
		t.Fatal("来源身份或租户被正文覆盖")
	}
	require(t, wal.Confirm(batch, ack))
	count, _, err := wal.Stats()
	require(t, err)
	if count != 0 {
		t.Fatal("确认后队列没有释放")
	}
	require(t, f.Owner.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		var count int
		err := tx.QueryRow(ctx, "SELECT count(*) FROM operation_audits WHERE tenant_id=$1 AND action='syslog.raw.read' AND object_id=$2", u.TenantID, firstID).Scan(&count)
		if err == nil && count != 1 {
			return fmt.Errorf("原文审计缺失")
		}
		return err
	}))
	var sourcePage store.SyslogSourcePage
	http.request("GET", "/syslog/sources", "", nil, &sourcePage, 200)
	if len(sourcePage.Items) != 1 || sourcePage.Items[0].State != "stopped" {
		t.Fatal("来源目录没有反映真实停止状态")
	}

}

func TestSyslogSourcePagingBeyondTwoHundredAndSessionRecheck(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
	defer cancel()
	f, u, _, password := accountFixture(t, ctx)
	now := time.Now().UTC()
	binding := syslogdata.ReceiverBinding{SourceID: "edge", SourceName: "边界日志", NetworkDomain: "dmz", ConfigSHA256: strings.Repeat("a", 64), Transport: "tcp", Format: "rfc5424"}
	h := syslogdata.Health{ReceiverBinding: binding, State: "listening", ObservedAt: now, StartedAt: now.Add(-time.Second), Received: "1", Persisted: "1", Dropped: "0", Rejected: "0", FramingErrors: "0", MaxMessageBytes: 4096, IdentityQuality: "network_allowlist", UpstreamLoss: "unknown"}
	require(t, f.Owner.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		for i := 0; i < 205; i++ {
			raw, _ := json.Marshal(model.HostHealth{ObservedAt: now, SyslogSources: []syslogdata.Health{h}})
			id := fmt.Sprintf("sensor_log_%03d", i)
			if _, err := tx.Exec(ctx, "INSERT INTO sensors(tenant_id,id,name,registration_id,last_seen,health) VALUES($1,$2,'日志探针',$3,now(),$4)", u.TenantID, id, "registration_"+id, raw); err != nil {
				return err
			}
		}
		return nil
	}))
	q := syslogdata.SourceQuery{Limit: 20}
	seen := map[string]bool{}
	for {
		page, err := f.Runtime.SyslogSources(ctx, u, q)
		require(t, err)
		for _, v := range page.Items {
			if seen[v.SensorID] || v.Observation != "fresh" || v.SensorStatus != "online" {
				t.Fatal("目录重复或状态不正确")
			}
			seen[v.SensorID] = true
		}
		if page.NextCursor == "" {
			break
		}
		q.Cursor = page.NextCursor
	}
	if len(seen) != 205 {
		t.Fatal("目录被最近两百项截断")
	}
	client := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime}, u.Username, password)
	for _, path := range []string{"/syslog/sources?unknown=1", "/syslog/sources?limit=020", "/syslog/sources?limit=1&limit=2", "/syslog/sources?sensor_id=UPPER", "/syslog/sources?cursor=bad"} {
		client.request("GET", path, "", nil, nil, 400)
	}
	require(t, f.Owner.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "UPDATE users SET active=false,revision=revision+1 WHERE tenant_id=$1 AND id=$2", u.TenantID, u.ID)
		return err
	}))
	if f.Runtime.AuthorizeSyslog(ctx, u, "", "") == nil {
		t.Fatal("停用账号仍可读日志")
	}
	client.request("GET", "/syslog/sources", "", nil, nil, 401)
}
