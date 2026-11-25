//go:build integration

package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	sensorv1 "github.com/kkx600/StarBeacon/api/sensor/v1"
	"github.com/kkx600/StarBeacon/internal/admin"
	"github.com/kkx600/StarBeacon/internal/agent"
	"github.com/kkx600/StarBeacon/internal/bus"
	"github.com/kkx600/StarBeacon/internal/config"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/ingest"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/notify"
	"github.com/kkx600/StarBeacon/internal/platform"
	"github.com/kkx600/StarBeacon/internal/response"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/transport"
	"github.com/kkx600/StarBeacon/internal/worker"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func TestPluginReleaseQualificationRollbackAndDurableDeviceAlerts(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 120*time.Second)
	defer cancel()
	f, owner, foreign, password := accountFixture(t, ctx)
	public, signer, err := ed25519.GenerateKey(rand.Reader)
	require(t, err)
	dir := t.TempDir()
	observed := time.Now().UTC().Truncate(time.Second)
	var calls atomic.Int32
	var failRead atomic.Bool
	token := store.Token()
	device := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if req.Header.Get("Authorization") != "Bearer "+token || req.Method != http.MethodGet {
			t.Error("只读设备收到了越界请求或缺少本地认证")
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if failRead.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		switch req.URL.Path {
		case "/health":
			fmt.Fprint(w, `{"healthy":true}`)
		case "/alerts":
			cursor := req.URL.Query().Get("after")
			item := func(id, priority string) map[string]any {
				return map[string]any{"vendor_id": id, "time": observed, "priority": priority, "title": "受控设备告警", "source": "192.0.2.29",
					"details": map[string]any{"preserved": "<原始记录>"}}
			}
			next, items := "cursor_2", []map[string]any{}
			switch cursor {
			case "":
				next, items = "cursor_1", []map[string]any{item("device-1", "严重")}
			case "cursor_1":
				items = []map[string]any{item("device-1", "严重"), item("device-2", "中危")}
			case "cursor_2":
			default:
				t.Error("设备收到了未知的游标")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"next": next, "items": items})
		default:
			t.Error("设备收到了未登记的路径")
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer device.Close()
	settings := response.Configuration{ID: "connector_owned", DeviceID: "device_owned", DeviceVersion: "fixture/1", Origin: device.URL,
		CAFile: filepath.Join(dir, "ca.pem"), TokenFile: filepath.Join(dir, "token"), MaxTTLSeconds: 3600}
	require(t, os.WriteFile(settings.CAFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: device.Certificate().Raw}), 0600))
	require(t, os.WriteFile(settings.TokenFile, []byte(token), 0600))
	pluginID := "plugin_owned"
	path := filepath.Join(dir, "bindings.json")
	profile, err := json.Marshal(map[string]any{"schema_version": "response.plugin-bindings.v1",
		"profiles": []any{map[string]any{"plugin_id": pluginID, "device": settings}}})
	require(t, err)
	require(t, os.WriteFile(path, profile, 0600))

	identity := verifyPluginProbeControl(t, ctx, f, owner, path, public, pluginID)
	walFile := filepath.Join(dir, "agent.db")
	wal, err := agent.OpenWAL(walFile, identity.TenantID, identity.SensorID, identity.RegistrationID, 8*1024*1024)
	require(t, err)
	t.Cleanup(func() { require(t, wal.Close()) })
	service, err := agent.NewPluginService(wal, path, "", public)
	require(t, err)
	t.Cleanup(func() { service.Close() })
	engine := &agent.Engine{WAL: wal, Plugins: service}
	manager, err := agent.NewTaskManager(wal, public, engine)
	require(t, err)
	manager.Plugins = service
	running, stop := context.WithCancel(ctx)
	finished := make(chan error, 1)
	go func() { finished <- manager.Run(running) }()
	t.Cleanup(func() { stop(); require(t, <-finished) })
	health := func() model.HostHealth {
		return model.HostHealth{ObservedAt: time.Now().UTC(), CommandSignerSHA256: control.Digest(public),
			TaskCapabilities: engine.Capabilities(), PluginBindings: service.Bindings()}
	}
	forbidden := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime, Signer: signer}, foreign.Username, password)
	user := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime, Signer: signer}, owner.Username, password)
	draft := response.PluginDraft{ID: pluginID, Name: "设备告警夹具", Device: "受控 HTTPS",
		Template: response.Template{SchemaVersion: response.TemplateSchema,
			Health: response.TemplateStep{Method: "GET", Path: "/health", Accept: response.TemplateCheck{Status: []int{200}, Field: "healthy", Equals: json.RawMessage("true")}},
			Pull: &response.TemplatePull{Path: "/alerts", CursorParam: "after", ItemsField: "items", CursorField: "next",
				Fields: []response.TemplateField{{Name: "id", Value: "vendor_id"}, {Name: "time", Value: "time"}, {Name: "severity", Value: "priority"},
					{Name: "name", Value: "title"}, {Name: "source_ip", Value: "source"}}}},
		Examples: []response.PluginExample{{Method: "GET", Path: "/health", Status: 200, Response: `{"healthy":true}`},
			{Method: "GET", Path: "/alerts", Query: "after=", Status: 200, Response: `{"items":[],"next":"mock_cursor"}`}},
	}
	const catalogue = "/response-plugins"
	operations := catalogue + "/" + pluginID + "/operations"
	var v1 response.PluginVersion
	user.request("POST", catalogue, "owned_draft_v1", draft, &v1, 201)
	if v1.TrialMode() != "read_only" {
		t.Fatal("只读模板被认作变更插件")
	}
	forbidden.request("GET", operations+"?sensor_id=sensor_plugin", "", nil, nil, 404)
	makeOp := func(action string, version int, generation int64) response.PluginOperation {
		return response.PluginOperation{SensorID: identity.SensorID, Version: version, Action: action, ExpectedGeneration: generation}
	}
	unavailable := health()
	unavailable.CommandSignerSHA256 = control.Digest([]byte("different-signer"))
	require(t, f.Runtime.Heartbeat(ctx, identity, unavailable))
	user.request("POST", operations, "untrusted_heartbeat", makeOp("simulate", 1, 0), nil, 503)
	unavailable = health()
	unavailable.PluginBindings = nil
	require(t, f.Runtime.Heartbeat(ctx, identity, unavailable))
	user.request("POST", operations, "missing_binding", makeOp("simulate", 1, 0), nil, 503)
	require(t, f.Runtime.Heartbeat(ctx, identity, health()))
	bad := health()
	bad.PluginBindings = append(bad.PluginBindings, bad.PluginBindings[0])
	require(t, f.Runtime.Heartbeat(ctx, identity, bad))
	user.request("POST", operations, "duplicate_binding", makeOp("simulate", 1, 0), nil, 503)
	require(t, f.Runtime.Heartbeat(ctx, identity, health()))
	if _, err := f.Runtime.SubmitPluginOperation(ctx, owner, pluginID, "missing_signer", makeOp("simulate", 1, 0), nil); !errors.Is(err, response.ErrUnavailable) {
		t.Fatal("缺失签名配置时操作仍可进入任务队列", err)
	}
	if _, err := f.Runtime.SubmitPluginOperation(ctx, owner, pluginID, "bad_operation", makeOp("apply_unqualified", 1, 0), signer); !errors.Is(err, response.ErrInput) {
		t.Fatal("存储层接受了非法操作类型", err)
	}
	if _, err := f.Runtime.ListPluginOperations(ctx, owner, "", identity.SensorID); !errors.Is(err, response.ErrInput) {
		t.Fatal("存储层接受未绑定插件身份的操作目录", err)
	}
	for _, action := range []string{"publish", "read", "capability", "rollback", "disable"} {
		user.request("POST", operations, "unqualified_"+action, makeOp(action, 1, 0), nil, 409)
	}
	user.request("GET", operations+"?sensor_id=sensor_plugin&other=1", "", nil, nil, 400)

	run := func(action, requestID string, version int, generation int64, want string) control.Receipt {
		t.Helper()
		require(t, f.Runtime.Heartbeat(ctx, identity, health()))
		op := makeOp(action, version, generation)
		var responseID, repeated struct {
			TaskID string `json:"task_id"`
		}
		user.request("POST", operations, requestID, op, &responseID, 202)
		user.request("POST", operations, requestID, op, &repeated, 202)
		if responseID.TaskID != repeated.TaskID {
			t.Fatal("任务提交失去幂等性")
		}
		task, err := f.Runtime.NextTask(ctx, identity)
		require(t, err)
		if task == nil || task.ID != responseID.TaskID {
			t.Fatal("签名任务未进入原有采集器控制队列")
		}
		require(t, manager.Accept(task.Command, task.Signature))
		result := waitPluginReceipt(t, ctx, manager, task.ID)
		if result.State != want {
			t.Fatalf("%s 返回 %s/%s，预期 %s", action, result.State, result.Code, want)
		}
		if action == "simulate" && want == "succeeded" {
			forged := result
			forged.Code = "device_rejected"
			if err = f.Runtime.SaveReceipt(ctx, identity, forged); err == nil {
				t.Fatal("包含错误代码的成功回执被接受")
			}
			forged.Code = ""
			forged.Result = json.RawMessage(`{}`)
			if err = f.Runtime.SaveReceipt(ctx, identity, forged); err == nil {
				t.Fatal("缺少试运行证明的成功回执被接受")
			}
		}
		require(t, f.Runtime.SaveReceipt(ctx, identity, result))
		require(t, f.Runtime.SaveReceipt(ctx, identity, result))
		reencoded, _ := json.Marshal(result)
		require(t, manager.Confirm(task.ID, control.HashBytes(reencoded)))
		return result
	}

	run("simulate", "owned_simulate_v1", 1, 0, "succeeded")
	user.request("POST", operations, "owned_simulate_v1", makeOp("read", 1, 0), nil, 409)
	if calls.Load() != 0 {
		t.Fatal("模拟设备试运行访问了真实 TLS 夹具")
	}
	failRead.Store(true)
	failed := run("read", "owned_read_fail", 1, 0, "failed")
	if !hasPluginRequest(failed.Result, http.MethodGet, http.StatusServiceUnavailable) {
		t.Fatal("设备失败未在脱敏回执中显示")
	}
	user.request("POST", operations, "failed_read_gate", makeOp("capability", 1, 0), nil, 409)
	failRead.Store(false)
	read := run("read", "owned_read_v1", 1, 0, "succeeded")
	if !hasPluginRequest(read.Result, http.MethodGet, http.StatusOK) {
		t.Fatal("实际设备只读请求缺少回执")
	}
	before := calls.Load()
	proof := run("capability", "owned_policy_v1", 1, 0, "succeeded")
	if calls.Load() != before || !containsCheck(proof.Result, "writes_denied") {
		t.Fatal("只读版本的第三档没有独立核对写入边界")
	}
	changedBinding := health()
	changedBinding.PluginBindings[0].BindingSHA256 = control.Digest([]byte("updated-local-profile"))
	require(t, f.Runtime.Heartbeat(ctx, identity, changedBinding))
	user.request("POST", operations, "changed_local_binding", makeOp("publish", 1, 0), nil, 409)
	run("publish", "owned_publish_v1", 1, 0, "succeeded")
	user.request("POST", operations, "stale_generation", makeOp("disable", 1, 0), nil, 409)

	route, err := f.Runtime.Route(ctx, identity, "alerts")
	require(t, err)
	// 设备中断时游标留在上次成功页。恢复后先补齐这页，再观察重复页。
	func() {
		failRead.Store(true)
		polling, stopPolling := context.WithCancel(ctx)
		pollFinished := make(chan error, 1)
		go func() {
			pollFinished <- service.Run(polling, func(context.Context, string) (string, error) { return route.Token, nil })
		}()
		defer func() { stopPolling(); require(t, <-pollFinished) }()
		unavailable := func() bool {
			return slices.Contains(wal.Health(ctx, walFile).Errors, "plugin_"+pluginID+"_unavailable")
		}
		for until := time.Now().Add(3 * time.Second); !unavailable() && time.Now().Before(until); {
			time.Sleep(50 * time.Millisecond)
		}
		if !unavailable() {
			t.Fatal("设备中断没有回报等待重试")
		}
		if pending, _, err := wal.Stats(); err != nil || pending != 0 {
			t.Fatal("失败的设备页推进了队列和游标", pending, err)
		}
		failRead.Store(false)
		for until := time.Now().Add(8 * time.Second); time.Now().Before(until); {
			if pending, _, err := wal.Stats(); err == nil && pending == 1 && !unavailable() {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatal("设备恢复后未续拉原页或保留了错误状态")
	}()
	runPoll := func(s *agent.PluginService, count uint64) {
		t.Helper()
		run, stopRun := context.WithCancel(ctx)
		done := make(chan error, 1)
		go func() { done <- s.Run(run, func(context.Context, string) (string, error) { return route.Token, nil }) }()
		defer func() { stopRun(); require(t, <-done) }()
		limit := time.Now().Add(5 * time.Second)
		for time.Now().Before(limit) {
			current, _, err := wal.Stats()
			require(t, err)
			if current == count {
				return
			}
			time.Sleep(15 * time.Millisecond)
		}
		t.Fatalf("设备拉取未在预算内写入 %d 条", count)
	}
	draft.ExpectedVersion, draft.Name = 1, "设备告警夹具修订"
	var v2 response.PluginVersion
	user.request("POST", catalogue, "owned_draft_v2", draft, &v2, 201)
	user.request("POST", operations, "isolated_version", makeOp("publish", 2, 1), nil, 409)
	for i, stage := range []string{"simulate", "read", "capability", "publish"} {
		run(stage, fmt.Sprintf("owned_v2_step_%d", i), 2, 1, "succeeded")
	}
	run("rollback", "owned_rollback", 1, 2, "succeeded")
	var latest response.PluginOperations
	user.request("GET", operations+"?sensor_id=sensor_plugin", "", nil, &latest, 200)
	if latest.Deployment.Generation != 3 || latest.Deployment.Version != 1 || latest.Deployment.PreviousVersion != 2 || len(latest.Operations) != 10 {
		t.Fatalf("试运行和回退记录不全，生成 %d，操作 %d", latest.Deployment.Generation, len(latest.Operations))
	}
	report := health()
	report.Errors = []string{"plugin_" + pluginID + "_unavailable"}
	require(t, f.Runtime.Heartbeat(ctx, identity, report))
	user.request("GET", operations+"?sensor_id=sensor_plugin", "", nil, &latest, 200)
	if !latest.Deployment.Unavailable {
		t.Fatal("设备告警拉取异常没有反映在此采集器的操作视图")
	}
	var cataloguePage response.PluginPage
	user.request("GET", catalogue, "", nil, &cataloguePage, 200)
	if len(cataloguePage.Deployments) != 1 || !cataloguePage.Deployments[0].Unavailable ||
		len(cataloguePage.Executions) != 1 || cataloguePage.Executions[0].PluginID != pluginID ||
		!cataloguePage.Executions[0].UpdatedAt.Equal(latest.Operations[0].UpdatedAt) {
		t.Fatal("插件目录未展示真实执行记录和设备异常")
	}
	// 新运行实例从同一 WAL 恢复签名版本；重叠设备页只新增后一条告警。
	resumed, err := agent.NewPluginService(wal, path, "", public)
	require(t, err)
	defer resumed.Close()
	runPoll(resumed, 2)
	batch, err := wal.Next("alerts")
	require(t, err)
	require(t, contract.Validate(identity.TenantID, identity.SensorID, identity.RegistrationID, batch))
	if len(batch.Records) != 2 || batch.Records[0].EventId == batch.Records[1].EventId {
		t.Fatal("重叠、重启与回退破坏了设备告警身份")
	}
	checkPluginIndexedAlerts(t, ctx, f.Runtime, identity, route.Index, route.Partition, batch, observed)
	ack := &sensorv1.IngestAck{BatchId: batch.BatchId, ProducerEpoch: batch.ProducerEpoch, AcceptedRanges: contract.Ranges(batch.Records),
		Status: sensorv1.AckStatus_ACK_STATUS_ACCEPTED, SensorRegistrationId: batch.SensorRegistrationId, StreamId: batch.StreamId, BatchSha256: batch.BatchSha256}
	require(t, wal.Confirm(batch, ack))
	run("disable", "owned_disable", 1, 3, "succeeded")
	user.request("GET", catalogue, "", nil, &cataloguePage, 200)
	if len(cataloguePage.Deployments) != 1 || cataloguePage.Deployments[0].Version != 0 || cataloguePage.Deployments[0].PreviousVersion != 1 || cataloguePage.Deployments[0].Unavailable {
		t.Fatal("目录停用状态不一致")
	}
}

func verifyPluginProbeControl(t *testing.T, ctx context.Context, f *isolatedDatabase, owner model.Principal, bindings string, key ed25519.PublicKey, plugin string) transport.SensorIdentity {
	t.Helper()
	dir := t.TempDir()
	pki, probeDir := filepath.Join(dir, "pki"), filepath.Join(dir, "sensor")
	require(t, admin.DevPKI(pki, nil))
	identity, err := admin.Provision(ctx, f.Owner, owner.TenantID, "sensor_plugin", "插件验收探针", pki, probeDir)
	require(t, err)
	root := filepath.Join(pki, "ca.crt")
	auth, err := transport.TLS(root, filepath.Join(pki, "server.crt"), filepath.Join(pki, "server.key"), true)
	require(t, err)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require(t, err)
	service := grpc.NewServer(grpc.Creds(credentials.NewTLS(auth)))
	sensorv1.RegisterSensorServiceServer(service, &ingest.Server{DB: f.Runtime, ControlOnly: true})
	go func() { _ = service.Serve(listener) }()
	defer service.Stop()

	eve, pub := filepath.Join(dir, "eve.json"), filepath.Join(dir, "command.pub")
	require(t, os.WriteFile(eve, nil, 0600))
	encoded, err := x509.MarshalPKIXPublicKey(key)
	require(t, err)
	require(t, os.WriteFile(pub, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: encoded}), 0600))
	cfg := config.Config{Mode: "development", HTTPAddr: "127.0.0.1:0", AllowedOrigin: "http://127.0.0.1",
		TenantID: identity.TenantID, SensorID: identity.SensorID, RegistrationID: identity.RegistrationID, TLSCA: root,
		TLSCert: filepath.Join(probeDir, "agent.crt"), TLSKey: filepath.Join(probeDir, "agent.key"), CommandPublicKey: pub,
		LocalPassword: store.Token(), CookieName: "plugin_local_session", StatePath: filepath.Join(dir, "agent.db"), EVEPath: eve,
		IngestAddr: listener.Addr().String(), PlatformAddr: listener.Addr().String(), WALBytes: 8 << 20, HeartbeatInterval: time.Second,
		ReplayDir: filepath.Join(dir, "replay"), ReplayBytes: 100 << 20, ReplayRetentionDays: 180, TaskRetentionDays: 180, ResponsePluginBindings: bindings}
	active, stop := context.WithCancel(ctx)
	finished := make(chan error, 1)
	go func() { finished <- agent.Run(active, cfg) }()
	defer func() { stop(); require(t, <-finished) }()
	var announced response.PluginBinding
	for limit := time.Now().Add(8 * time.Second); announced.PluginID == "" && time.Now().Before(limit); {
		items, err := f.Runtime.Sensors(ctx, identity.TenantID)
		require(t, err)
		for _, item := range items {
			var health model.HostHealth
			if item.ID == identity.SensorID && json.Unmarshal(item.Health, &health) == nil &&
				len(health.PluginBindings) == 1 && health.CommandSignerSHA256 == control.Digest(key) {
				announced = health.PluginBindings[0]
				break
			}
		}
		if announced.PluginID == "" {
			time.Sleep(25 * time.Millisecond)
		}
	}
	if announced.PluginID != plugin || announced.Validate() != nil {
		t.Fatal("采集器未在双向认证控制流登记本地绑定")
	}
	creds, err := transport.TLS(root, cfg.TLSCert, cfg.TLSKey, false)
	require(t, err)
	conn, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(creds)))
	require(t, err)
	defer conn.Close()
	for _, invalid := range [][]response.PluginBinding{{announced, announced}, make([]response.PluginBinding, 9), {{PluginID: plugin}}} {
		test, cancel := context.WithTimeout(ctx, 3*time.Second)
		stream, err := sensorv1.NewSensorServiceClient(conn).Control(test)
		require(t, err)
		body, _ := json.Marshal(model.HostHealth{ObservedAt: time.Now().UTC(), PluginBindings: invalid})
		require(t, stream.Send(&sensorv1.AgentMessage{SensorId: identity.SensorID, SensorRegistrationId: identity.RegistrationID,
			Kind: sensorv1.AgentMessageKind_AGENT_MESSAGE_KIND_HEARTBEAT, MessageId: "invalid_plugin_binding",
			PayloadSchema: "host.health.v1", PayloadJson: body}))
		_, err = stream.Recv()
		cancel()
		if status.Code(err) != codes.InvalidArgument {
			t.Fatal("双向认证控制流接受了坏绑定目录", err)
		}
	}
	return identity
}

func waitPluginReceipt(t *testing.T, ctx context.Context, manager *agent.TaskManager, id string) control.Receipt {
	t.Helper()
	limit := time.Now().Add(12 * time.Second)
	for ctx.Err() == nil && time.Now().Before(limit) {
		items, err := manager.Pending()
		require(t, err)
		for _, raw := range items {
			var r control.Receipt
			require(t, json.Unmarshal(raw, &r))
			if r.CommandID == id && r.State != "running" {
				return r
			}
		}
		time.Sleep(15 * time.Millisecond)
	}
	t.Fatal("未收到插件任务最终回执")
	return control.Receipt{}
}

func containsCheck(raw []byte, check string) bool {
	var out response.PluginTrialResult
	if json.Unmarshal(raw, &out) != nil {
		return false
	}
	for _, key := range out.Checks {
		if key == check {
			return true
		}
	}
	return false
}

func hasPluginRequest(raw []byte, method string, status int) bool {
	var report response.PluginTrialResult
	if json.Unmarshal(raw, &report) != nil {
		return false
	}
	for _, check := range report.Events {
		for _, req := range check.Requests {
			if req.Method == method && req.Status == status {
				return true
			}
		}
	}
	return false
}

func checkPluginIndexedAlerts(t *testing.T, ctx context.Context, db *store.Postgres, identity transport.SensorIdentity, index, partition string, batch *sensorv1.EventBatch, observed time.Time) {
	t.Helper()
	queue, err := bus.OpenNamespace(ctx, os.Getenv("SB_NATS_URL"), store.RandomID("it_plugin_"))
	require(t, err)
	defer queue.Close()
	require(t, queue.Ensure(ctx, 1, 16*1024*1024))
	defer func() {
		clean, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for _, stream := range []string{bus.Alerts, bus.Context, bus.Logs, bus.Quarantine, bus.Indexed} {
			require(t, queue.JS.DeleteStream(clean, queue.StreamName(stream)))
		}
	}()
	es, err := store.OpenES(os.Getenv("SB_ES_URL"), "")
	require(t, err)
	defer deleteTenantEvents(t, es, identity.TenantID)
	raw, err := proto.Marshal(batch)
	require(t, err)
	require(t, queue.Publish(ctx, "sb.events.alerts", batch.BatchId,
		bus.Envelope{TenantID: identity.TenantID, Partition: partition, Index: index, ReceivedAt: time.Now().UTC(), Batch: raw}))
	alerts, err := queue.JS.Stream(ctx, queue.StreamName(bus.Alerts))
	require(t, err)
	msg, err := alerts.GetLastMsgForSubject(ctx, queue.Subject("sb.events.alerts"))
	require(t, err)
	indexer := &worker.Indexer{Bus: queue, DB: db, ES: es}
	for range 2 {
		require(t, indexer.Process(ctx, msg.Data))
	}
	resp, err := es.API.Indices.Refresh(es.API.Indices.Refresh.WithIndex(index), es.API.Indices.Refresh.WithContext(ctx))
	require(t, err)
	defer resp.Body.Close()
	got, err := es.Search(ctx, identity.TenantID, model.SearchRequest{Start: observed.Add(-time.Minute), End: time.Now().UTC().Add(time.Minute)})
	require(t, err)
	if got.Total != 2 {
		t.Fatalf("真实索引重复或丢失设备告警 %d", got.Total)
	}
	for _, item := range got.Items {
		if item.Event.Dataset != "设备告警 · 设备告警夹具" || item.Event.Kind != "alert" || item.Source.IP != "192.0.2.29" {
			t.Fatal("告警转换丢失来源或 IP")
		}
		record, err := contract.ReadDeviceAlertRecord([]byte(item.Event.Original))
		require(t, err)
		if record.Alert.Name != item.Rule.Name {
			t.Fatal("设备原始记录无法复核")
		}
	}
	require(t, notify.ValidateBatch(identity.TenantID, batch.BatchId, notify.Summaries(got.Items)))
	critical, err := es.Search(ctx, identity.TenantID, model.SearchRequest{Start: observed.Add(-time.Minute), End: time.Now().UTC().Add(time.Minute), Severity: "critical"})
	require(t, err)
	if critical.Total != 1 {
		t.Fatal("严重设备告警无法筛选")
	}
}
