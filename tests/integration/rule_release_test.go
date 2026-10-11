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
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	sensorv1 "github.com/kkx600/StarBeacon/api/sensor/v1"
	"github.com/kkx600/StarBeacon/internal/admin"
	"github.com/kkx600/StarBeacon/internal/agent"
	"github.com/kkx600/StarBeacon/internal/config"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/ingest"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/platform"
	"github.com/kkx600/StarBeacon/internal/replay"
	"github.com/kkx600/StarBeacon/internal/rulerelease"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/testpcap"
	"github.com/kkx600/StarBeacon/internal/transport"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// 使用实际引擎、PG、HTTP 会话、签名、设备队列及双向 mTLS 回执；不向网卡发送样本流量。
func TestQualifiedRuleReleaseNativeMTLSPersistenceAndAtomicFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f := newIsolatedDatabase(t, ctx)
	binary := os.Getenv("SB_TEST_SURICATA_BINARY")
	if binary == "" {
		t.Fatal("发布验收必须提供实际 Suricata 二进制")
	}
	tenant := store.RandomID("it_release_")
	password := store.Token()
	require(t, admin.Bootstrap(ctx, f.Owner, tenant, "规则发布验收", tenant, password, "admin"))
	u, _, err := f.Runtime.Password(ctx, tenant)
	require(t, err)
	dir, err := os.MkdirTemp("", "sb-release-")
	require(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	pki := filepath.Join(dir, "pki")
	require(t, admin.DevPKI(pki))
	id, err := admin.Provision(ctx, f.Owner, tenant, "sensor_release", "发布验证探针", pki, filepath.Join(dir, "identity"))
	require(t, err)
	pub, signer, err := ed25519.GenerateKey(rand.Reader)
	require(t, err)
	wal, err := agent.OpenWAL(filepath.Join(dir, "agent.db"), tenant, id.SensorID, id.RegistrationID, 4<<20)
	require(t, err)
	t.Cleanup(func() { require(t, wal.Close()) })
	objects, err := replay.NewLocal(filepath.Join(dir, "samples"), 100<<20)
	require(t, err)
	configuration := config.Config{Mode: "development", StatePath: filepath.Join(dir, "agent.db"), SuricataBinary: binary, SuricataConfig: filepath.Join(dir, "suricata.yaml"), SuricataSocket: filepath.Join(dir, "engine.sock"), SuricataRulesPath: filepath.Join(dir, "active.rules"), SuricataPIDFile: filepath.Join(dir, "engine.pid"), AllowRuleApply: true}
	previous := `alert tcp any any -> any any (msg:"StarBeacon previous"; content:"never-present"; sid:1000999; rev:1;)`
	require(t, os.WriteFile(configuration.SuricataRulesPath, []byte(previous), 0600))
	settings := map[string]any{
		"vars":              map[string]any{"address-groups": map[string]string{"HOME_NET": "any", "EXTERNAL_NET": "any"}, "port-groups": map[string]string{"HTTP_PORTS": "80"}},
		"default-rule-path": dir, "rule-files": []string{"active.rules"}, "run-as": map[string]any{},
		"unix-command": map[string]any{"enabled": true, "filename": configuration.SuricataSocket}, "outputs": []any{},
		"logging": map[string]any{"default-log-level": "notice", "outputs": []any{}},
		"flow":    map[string]any{"memcap": "16mb", "hash-size": 1024, "prealloc": 1024}, "stream": map[string]any{"memcap": "32mb", "reassembly": map[string]any{"memcap": "64mb"}},
	}
	raw, err := json.Marshal(settings)
	require(t, err)
	require(t, os.WriteFile(configuration.SuricataConfig, append([]byte("%YAML 1.1\n---\n"), raw...), 0600))
	processCtx, stopProcess := context.WithCancel(ctx)
	native := exec.CommandContext(processCtx, binary, "-c", configuration.SuricataConfig, "--unix-socket="+configuration.SuricataSocket, "-l", dir)
	native.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
	native.Stdout, native.Stderr = io.Discard, io.Discard
	native.WaitDelay = 2 * time.Second
	require(t, native.Start())
	processDone := make(chan error, 1)
	go func() { processDone <- native.Wait() }()
	t.Cleanup(func() { stopProcess(); <-processDone })
	require(t, os.WriteFile(configuration.SuricataPIDFile, []byte(strconv.Itoa(native.Process.Pid)), 0600))
	eventually(t, ctx, "原生规则进程未就绪", func() bool {
		connection, err := net.DialTimeout("unix", configuration.SuricataSocket, 100*time.Millisecond)
		if err != nil {
			return false
		}
		_ = connection.Close()
		return true
	})
	wake := &control.Wakeup{}
	serverTLS, err := transport.TLS(filepath.Join(pki, "ca.crt"), filepath.Join(pki, "server.crt"), filepath.Join(pki, "server.key"), true)
	require(t, err)
	clientTLS, err := transport.TLS(filepath.Join(pki, "ca.crt"), filepath.Join(dir, "identity", "agent.crt"), filepath.Join(dir, "identity", "agent.key"), false)
	require(t, err)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require(t, err)
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(serverTLS)))
	sensorv1.RegisterSensorServiceServer(server, &ingest.Server{DB: f.Runtime, ControlOnly: true, TasksEnabled: true, Samples: objects, Wakeup: wake})
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	connection, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)))
	require(t, err)
	t.Cleanup(func() { _ = connection.Close() })
	client := sensorv1.NewSensorServiceClient(connection)
	engine := &agent.Engine{Config: configuration, WAL: wal, ReplayClient: client}
	manager, err := agent.NewTaskManager(wal, pub, engine)
	require(t, err)
	runCtx, stopTasks := context.WithCancel(ctx)
	taskDone := make(chan error, 1)
	go func() { taskDone <- manager.Run(runCtx) }()
	tasksStopped := false
	t.Cleanup(func() {
		if !tasksStopped {
			stopTasks()
			require(t, <-taskDone)
		}
	})
	stream, err := client.Control(ctx)
	require(t, err)
	t.Cleanup(func() { _ = stream.CloseSend() })
	health := func(hash string) {
		value, _ := json.Marshal(model.HostHealth{ObservedAt: time.Now().UTC(), TaskCapabilities: engine.Capabilities(), CommandSignerSHA256: control.Digest(pub), RegisteredRulesAvailable: true, RegisteredRulesSHA256: hash})
		require(t, stream.Send(&sensorv1.AgentMessage{SensorId: id.SensorID, SensorRegistrationId: id.RegistrationID, Kind: sensorv1.AgentMessageKind_AGENT_MESSAGE_KIND_HEARTBEAT, MessageId: store.RandomID("hb_"), PayloadSchema: "host.health.v1", PayloadJson: value}))
		ack, err := stream.Recv()
		require(t, err)
		if ack.Kind != sensorv1.CommandKind_COMMAND_KIND_HEARTBEAT_ACK {
			t.Fatal("心跳没有准确确认")
		}
	}
	health(control.Digest([]byte(previous)))
	auth := httpapi.NewAuth(f.Runtime, nil, "http://127.0.0.1", "release_session", false)
	api := &platform.API{DB: f.Runtime, Auth: auth, Signer: signer, Wakeup: wake, Samples: objects, SampleQuota: 100 << 20}
	httpServer := httptest.NewServer(httpapi.Middleware(api.Handler()))
	t.Cleanup(httpServer.Close)
	auth.Origin = httpServer.URL
	jar, err := cookiejar.New(nil)
	require(t, err)
	httpClient := &liveHTTP{t: t, ctx: ctx, origin: httpServer.URL, prefix: "/api/v1", client: &http.Client{Jar: jar, Timeout: 5 * time.Second}}
	httpClient.login(tenant, password)
	text := `alert http any any -> any any (msg:"StarBeacon qualified"; flow:established,to_server; http.uri; content:"/starbeacon/validation"; sid:1001003; rev:1;)`
	rules, err := f.Runtime.SaveRulePackage(ctx, u, "rules_release", "发布验收规则", text, 0, "save_rules")
	require(t, err)
	p := control.RulePackage{PackageID: rules.ID, Revision: rules.Revision, EngineVersion: rules.EngineVersion, Text: rules.Text, SHA256: rules.SHA256}
	path := "/sensors/" + id.SensorID + "/tasks"
	// 缺少正反样本时仍拒绝发布，不把已有设备安装能力当作平台资格。
	httpClient.request("POST", path, "release_no_evidence", map[string]any{"kind": "rules.apply", "package_id": p.PackageID, "revision": p.Revision}, nil, 409)
	var beforeReceipt func(control.Receipt)
	execute := func(taskID string) control.Receipt {
		t.Helper()
		message, err := stream.Recv()
		require(t, err)
		if message.Kind != sensorv1.CommandKind_COMMAND_KIND_TASK || message.CommandId != taskID {
			t.Fatal("投递了其他设备任务")
		}
		require(t, manager.Accept(message.PayloadJson, message.Signature))
		var final []byte
		var receipt control.Receipt
		eventually(t, ctx, "原生任务没有终态回执", func() bool {
			pending, err := manager.Pending()
			require(t, err)
			for _, candidate := range pending {
				var r control.Receipt
				require(t, json.Unmarshal(candidate, &r))
				if r.CommandID == taskID && r.FinishedAt != nil {
					receipt = r
					final = candidate
					return true
				}
			}
			return false
		})
		if receipt.State != "succeeded" {
			t.Fatal("原生任务执行失败", receipt.Code, string(receipt.Result))
		}
		if beforeReceipt != nil {
			beforeReceipt(receipt)
		}
		require(t, stream.Send(&sensorv1.AgentMessage{SensorId: id.SensorID, SensorRegistrationId: id.RegistrationID, Kind: sensorv1.AgentMessageKind_AGENT_MESSAGE_KIND_TASK_RECEIPT, MessageId: store.RandomID("receipt_"), CommandId: taskID, PayloadSchema: control.ReceiptSchema, PayloadJson: final}))
		ack, err := stream.Recv()
		require(t, err)
		if ack.Kind != sensorv1.CommandKind_COMMAND_KIND_RECEIPT_ACK || ack.CommandId != taskID {
			t.Fatal("回执没有准确确认")
		}
		require(t, manager.Confirm(taskID, ack.PayloadSha256))
		return receipt
	}
	create := func(body map[string]any, key string) (string, control.Receipt) {
		t.Helper()
		var out struct {
			ID string `json:"id"`
		}
		httpClient.request("POST", path, key, body, &out, 202)
		return out.ID, execute(out.ID)
	}
	validation, _ := create(map[string]any{"kind": "rules.validate", "package_id": p.PackageID, "revision": p.Revision}, "release_validation")
	var replayTasks [2]string
	var sampleIDs [2]string
	for i, samplePath := range []string{"/starbeacon/validation", "/starbeacon/allowed"} {
		data, err := testpcap.HTTPPath(false, samplePath)
		require(t, err)
		sample := replay.Sample{ID: store.RandomID("sample_"), Name: "规则验收.pcap", Size: int64(len(data))}
		sampleIDs[i] = sample.ID
		require(t, f.Runtime.ReserveSample(ctx, u, sample, 100<<20))
		sample.SHA256, sample.Format, err = objects.Put(ctx, replay.Key(tenant, sample.ID), bytes.NewReader(data), sample.Size)
		require(t, err)
		require(t, f.Runtime.CompleteSample(ctx, u, sample.ID, sample.SHA256, sample.Format, "import_sample"))
		var receipt control.Receipt
		replayTasks[i], receipt = create(map[string]any{"kind": "rules.replay", "package_id": p.PackageID, "revision": p.Revision, "sample_id": sample.ID, "rule_mode": "package"}, "release_replay_"+strconv.Itoa(i))
		var result struct {
			Alerts int `json:"alert_count"`
		}
		require(t, json.Unmarshal(receipt.Result, &result))
		if result.Alerts != 1-i {
			t.Fatal("正反样本没有得到预期原生结果", result.Alerts)
		}
	}
	grant := &control.RuleAuthorization{ValidationTaskID: validation, PositiveReplayTaskID: replayTasks[0], NegativeReplayTaskID: replayTasks[1], ExpectedRulesSHA256: control.Digest([]byte(previous))}
	p.Authorization = grant
	qualifiedPayload, err := control.RulePayload(p)
	require(t, err)
	before := ownedBusinessSnapshot(t, ctx, f.Owner, tenant)
	for _, prefix := range []string{"SELECT COALESCE(health->>'registered_rules_sha256'", "SELECT rules_text,sha256,engine_version", "SELECT command,signature,command_sha256,receipt", "INSERT INTO sensor_tasks", "INSERT INTO operation_audits"} {
		t.Run("database interruption "+prefix, func(t *testing.T) {
			broken, tracer := disconnectedStore(t, ctx, f.RuntimeDSN, prefix)
			_, err := broken.CreateTask(ctx, u, id.SensorID, "rules.apply", store.RandomID("key_"), qualifiedPayload, signer)
			if err == nil || !tracer.fired.Load() {
				t.Fatal("发布没有触发真实数据库中断", err)
			}
			if actual := ownedBusinessSnapshot(t, ctx, f.Owner, tenant); actual != before {
				t.Fatal("失败发布留下业务或审计残留")
			}
		})
	}
	for _, change := range []func(*control.RuleAuthorization){
		func(g *control.RuleAuthorization) { g.PositiveReplayTaskID = "task_missing" },
		func(g *control.RuleAuthorization) { g.NegativeReplayTaskID = g.PositiveReplayTaskID },
		func(g *control.RuleAuthorization) {
			g.PositiveReplayTaskID, g.NegativeReplayTaskID = g.NegativeReplayTaskID, g.PositiveReplayTaskID
		},
		func(g *control.RuleAuthorization) { g.ExpectedRulesSHA256 = control.Digest([]byte("foreign rules")) },
	} {
		copy := *grant
		change(&copy)
		candidate := p
		candidate.Authorization = &copy
		payload, err := control.RulePayload(candidate)
		require(t, err)
		_, err = f.Runtime.CreateTask(ctx, u, id.SensorID, "rules.apply", store.RandomID("key_"), payload, signer)
		if !errors.Is(err, rulerelease.ErrQualification) {
			t.Fatal("不符合资格的发布没有拒绝", err)
		}
		if actual := ownedBusinessSnapshot(t, ctx, f.Owner, tenant); actual != before {
			t.Fatal("拒绝的发布留下业务变更")
		}
	}
	body := map[string]any{"kind": "rules.apply", "package_id": p.PackageID, "revision": p.Revision, "validation_task_id": validation, "positive_replay_task_id": replayTasks[0], "negative_replay_task_id": replayTasks[1], "expected_rules_sha256": grant.ExpectedRulesSHA256}
	deployed, receipt := create(body, "release_apply")
	var installed struct {
		Active        string                     `json:"active_sha256"`
		Previous      string                     `json:"previous_sha256"`
		Authorization *control.RuleAuthorization `json:"authorization"`
	}
	require(t, json.Unmarshal(receipt.Result, &installed))
	if installed.Active != p.SHA256 || installed.Previous != grant.ExpectedRulesSHA256 || installed.Authorization == nil || installed.Authorization.Validate() != nil {
		t.Fatal("原生生效回执缺少规则和资格摘要")
	}
	actual, err := os.ReadFile(configuration.SuricataRulesPath)
	require(t, err)
	if string(actual) != p.Text {
		t.Fatal("原生安装文件与发布修订不一致")
	}
	if _, err = os.Lstat(filepath.Join(dir, "rule-transaction.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("成功安装留下未知事务")
	}
	var duplicate struct {
		ID string `json:"id"`
	}
	httpClient.request("POST", path, "release_apply", body, &duplicate, 202)
	if duplicate.ID != deployed {
		t.Fatal("精确重试创建了重复发布")
	}
	health(p.SHA256)
	httpClient.request("POST", path, "release_stale_state", body, nil, 409)
	var state string
	require(t, f.Runtime.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT state FROM sensor_tasks WHERE tenant_id=$1 AND id=$2`, tenant, deployed).Scan(&state)
	}))
	if state != "succeeded" {
		t.Fatal("实际生效回执没有持久保存")
	}
	// 对第二修订重新执行完整验证；历史修订回滚使用原修订的有效证据和当前摘要。
	secondText := strings.ReplaceAll(strings.ReplaceAll(text, "StarBeacon qualified", "StarBeacon second revision"), "rev:1;", "rev:2;")
	second, err := f.Runtime.SaveRulePackage(ctx, u, p.PackageID, "发布验收规则", secondText, 1, "save_rules_second")
	require(t, err)
	secondValidation, _ := create(map[string]any{"kind": "rules.validate", "package_id": second.ID, "revision": second.Revision}, "release_second_validation")
	var secondReplays [2]string
	for i, sampleID := range sampleIDs {
		secondReplays[i], _ = create(map[string]any{"kind": "rules.replay", "package_id": second.ID, "revision": second.Revision, "sample_id": sampleID, "rule_mode": "package"}, "release_second_replay_"+strconv.Itoa(i))
	}
	secondBody := map[string]any{"kind": "rules.apply", "package_id": second.ID, "revision": second.Revision, "validation_task_id": secondValidation, "positive_replay_task_id": secondReplays[0], "negative_replay_task_id": secondReplays[1], "expected_rules_sha256": p.SHA256}
	_, secondReceipt := create(secondBody, "release_second_apply")
	require(t, json.Unmarshal(secondReceipt.Result, &installed))
	if installed.Active != second.SHA256 || installed.Previous != p.SHA256 {
		t.Fatal("第二修订没有实际装载")
	}
	health(second.SHA256)
	body["expected_rules_sha256"] = second.SHA256
	_, rollbackReceipt := create(body, "release_historical_rollback")
	require(t, json.Unmarshal(rollbackReceipt.Result, &installed))
	if installed.Active != p.SHA256 || installed.Previous != second.SHA256 {
		t.Fatal("历史修订没有实际回滚")
	}
	health(p.SHA256)
	// 实际装载已执行，但设备持久队列仍处于执行中；关闭并重开 WAL 验证中断恢复。
	stopTasks()
	require(t, <-taskDone)
	tasksStopped = true
	var interrupted struct {
		ID string `json:"id"`
	}
	httpClient.request("POST", path, "release_interrupted", secondBody, &interrupted, 202)
	delivery, err := stream.Recv()
	require(t, err)
	if delivery.CommandId != interrupted.ID || delivery.Kind != sensorv1.CommandKind_COMMAND_KIND_TASK {
		t.Fatal("中断测试收到其他任务")
	}
	require(t, manager.Accept(delivery.PayloadJson, delivery.Signature))
	var command control.Command
	require(t, json.Unmarshal(delivery.PayloadJson, &command))
	if _, code, err := engine.Execute(ctx, command); err != nil {
		t.Fatal("真实装载未执行", code, err)
	}
	require(t, wal.Close())
	wal, err = agent.OpenWAL(configuration.StatePath, tenant, id.SensorID, id.RegistrationID, 4<<20)
	require(t, err)
	engine.WAL = wal
	manager, err = agent.NewTaskManager(wal, pub, engine)
	require(t, err)
	runCtx, stopTasks = context.WithCancel(ctx)
	defer stopTasks()
	taskDone = make(chan error, 1)
	tasksStopped = false
	go func() { taskDone <- manager.Run(runCtx) }()
	pending, err := manager.Pending()
	require(t, err)
	var unknown control.Receipt
	var unknownRaw []byte
	for _, raw := range pending {
		var item control.Receipt
		require(t, json.Unmarshal(raw, &item))
		if item.CommandID == interrupted.ID {
			unknown = item
			unknownRaw = raw
		}
	}
	if unknown.State != "unknown" || unknown.Code != "execution_interrupted" || len(unknownRaw) == 0 {
		t.Fatal("重启没有保留实际中断事实")
	}
	require(t, stream.Send(&sensorv1.AgentMessage{SensorId: id.SensorID, SensorRegistrationId: id.RegistrationID, Kind: sensorv1.AgentMessageKind_AGENT_MESSAGE_KIND_TASK_RECEIPT, MessageId: store.RandomID("receipt_"), CommandId: interrupted.ID, PayloadSchema: control.ReceiptSchema, PayloadJson: unknownRaw}))
	ack, err := stream.Recv()
	require(t, err)
	if ack.Kind != sensorv1.CommandKind_COMMAND_KIND_RECEIPT_ACK || ack.CommandId != interrupted.ID {
		t.Fatal("中断回执未确认")
	}
	require(t, manager.Confirm(interrupted.ID, ack.PayloadSha256))
	health(second.SHA256)
	httpClient.request("POST", path, "release_blocked_by_unknown", body, nil, 409)
	resolutionBody := map[string]any{"kind": "rules.reconcile", "unknown_task_id": interrupted.ID, "expected_rules_sha256": second.SHA256}
	for _, candidate := range []map[string]any{
		{"kind": "rules.reconcile", "unknown_task_id": "task_missing", "expected_rules_sha256": second.SHA256},
		{"kind": "rules.reconcile", "unknown_task_id": interrupted.ID, "expected_rules_sha256": p.SHA256},
	} {
		httpClient.request("POST", path, store.RandomID("key_"), candidate, nil, 409)
	}
	beforeReceipt = func(receipt control.Receipt) {
		before := ownedBusinessSnapshot(t, ctx, f.Owner, tenant)
		var nativeProof control.RuleReconcileResult
		require(t, json.Unmarshal(receipt.Result, &nativeProof))
		for _, name := range []string{"核实状态", "原任务", "原命令", "当前规则", "检测配置", "检测剖面", "未回读", "缺少失败数量", "装载失败", "成功回执错误码", "其他注册代次"} {
			t.Run("reconciliation proof "+name, func(t *testing.T) {
				candidate, proof, identity := receipt, nativeProof, id
				switch name {
				case "核实状态":
					proof.Verified = false
				case "原任务":
					proof.UnknownTaskID = "other_task"
				case "原命令":
					proof.UnknownCommandSHA256 = control.Digest([]byte("other command"))
				case "当前规则":
					proof.ActiveSHA256 = p.SHA256
				case "检测配置":
					proof.ConfigSHA256 = control.Digest([]byte("other config"))
				case "检测剖面":
					proof.ProfileSHA256 = control.Digest([]byte("other profile"))
				case "未回读":
					proof.Stats = json.RawMessage(`[]`)
				case "缺少失败数量":
					proof.Stats = json.RawMessage(`[{"rules_loaded":1}]`)
				case "装载失败":
					proof.Stats = json.RawMessage(`[{"rules_loaded":1,"rules_failed":1}]`)
				case "成功回执错误码":
					candidate.Code = "unexpected_failure"
				case "其他注册代次":
					identity.RegistrationID = "other_registration"
				}
				candidate.Result, _ = json.Marshal(proof)
				if err := f.Runtime.SaveReceipt(ctx, identity, candidate); err == nil {
					t.Fatal("不符的核实回执解除规则事务阻塞")
				}
				if actual := ownedBusinessSnapshot(t, ctx, f.Owner, tenant); actual != before {
					t.Fatal("拒绝回执留下核实或审计变更")
				}
			})
		}
		for _, prefix := range []string{"SELECT registration_id FROM sensors", "SELECT state,command_sha256,receipt,kind", "UPDATE sensor_tasks SET rule_resolution", "INSERT INTO operation_audits", "UPDATE sensor_tasks SET state=$3,receipt"} {
			t.Run("reconciliation database interruption "+prefix, func(t *testing.T) {
				broken, tracer := disconnectedStore(t, ctx, f.RuntimeDSN, prefix)
				if err := broken.SaveReceipt(ctx, id, receipt); err == nil || !tracer.fired.Load() {
					t.Fatal("核实持久化没有触发真实连接中断", err)
				}
				if actual := ownedBusinessSnapshot(t, ctx, f.Owner, tenant); actual != before {
					t.Fatal("中断没有回滚核实依据、任务或审计")
				}
			})
		}
	}
	reconciled, reconciledReceipt := create(resolutionBody, "release_reconcile")
	beforeReceipt = nil
	var proof control.RuleReconcileResult
	require(t, json.Unmarshal(reconciledReceipt.Result, &proof))
	if !proof.Verified || proof.ActiveSHA256 != second.SHA256 || proof.UnknownTaskID != interrupted.ID || proof.UnknownCommandSHA256 != control.Digest(delivery.PayloadJson) {
		t.Fatal("设备没有产生准确的原生核实回执")
	}
	rows, err := f.Runtime.Tasks(ctx, tenant, id.SensorID)
	require(t, err)
	var original store.SensorTask
	for _, row := range rows {
		if row.ID == interrupted.ID {
			original = row
		}
	}
	oldHash, err := control.JSONDigest(unknownRaw)
	require(t, err)
	afterHash, err := control.JSONDigest(original.Receipt)
	require(t, err)
	if original.State != "unknown" || oldHash != afterHash || len(original.RuleResolution) == 0 {
		t.Fatal("平台改写中断事实或未保存核实依据")
	}
	var resolution struct {
		TaskID string                      `json:"task_id"`
		Result control.RuleReconcileResult `json:"result"`
	}
	require(t, json.Unmarshal(original.RuleResolution, &resolution))
	if resolution.TaskID != reconciled || resolution.Result.ActiveSHA256 != second.SHA256 {
		t.Fatal("核实依据没有关联实际任务")
	}
	require(t, f.Runtime.SaveReceipt(ctx, id, unknown))
	httpClient.request("POST", path, "release_reconcile", resolutionBody, &duplicate, 202)
	if duplicate.ID != reconciled {
		t.Fatal("核实重试重复创建任务")
	}
	httpClient.request("POST", path, "release_reconcile_resolved", resolutionBody, nil, 409)
	_, afterResolution := create(body, "release_after_reconcile")
	require(t, json.Unmarshal(afterResolution.Result, &installed))
	if installed.Active != p.SHA256 {
		t.Fatal("实际核实后仍无法正常发布")
	}
	local, err := manager.List()
	require(t, err)
	for _, row := range local {
		if row.ID == interrupted.ID && len(row.RuleResolution) == 0 {
			t.Fatal("设备没有保留核实依据")
		}
	}
}
