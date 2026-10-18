//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

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
	"github.com/kkx600/StarBeacon/internal/rulerollout"
	"github.com/kkx600/StarBeacon/internal/rulesync"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/testpcap"
	"github.com/kkx600/StarBeacon/internal/transport"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type nativeRolloutProbe struct {
	id      transport.SensorIdentity
	engine  *agent.Engine
	manager *agent.TaskManager
	stream  sensorv1.SensorService_ControlClient
}

func newNativeRolloutProbe(t *testing.T, ctx context.Context, f *isolatedDatabase, tenant, pki, base, address, name string, pub ed25519.PublicKey) *nativeRolloutProbe {
	t.Helper()
	dir := filepath.Join(base, name)
	require(t, os.Mkdir(dir, 0700))
	identityDir := filepath.Join(dir, "id")
	id, err := admin.Provision(ctx, f.Owner, tenant, name, "分批发布验证探针", pki, identityDir)
	require(t, err)
	wal, err := agent.OpenWAL(filepath.Join(dir, "agent.db"), tenant, id.SensorID, id.RegistrationID, 4<<20)
	require(t, err)
	t.Cleanup(func() { require(t, wal.Close()) })
	cfg := config.Config{Mode: "development", StatePath: filepath.Join(dir, "agent.db"), SuricataBinary: os.Getenv("SB_TEST_SURICATA_BINARY"), SuricataConfig: filepath.Join(dir, "suricata.yaml"), SuricataSocket: filepath.Join(dir, "engine.sock"), SuricataRulesPath: filepath.Join(dir, "active.rules"), SuricataPIDFile: filepath.Join(dir, "engine.pid"), AllowRuleApply: true}
	if cfg.SuricataBinary == "" {
		t.Fatal("双探针规则发布必须提供实际 Suricata 二进制")
	}
	require(t, os.WriteFile(cfg.SuricataRulesPath, []byte(`alert tcp any any -> any any (msg:"previous"; content:"never-present"; sid:1001998; rev:1;)`), 0600))
	settings := map[string]any{"vars": map[string]any{"address-groups": map[string]string{"HOME_NET": "any", "EXTERNAL_NET": "any"}, "port-groups": map[string]string{"HTTP_PORTS": "80"}}, "default-rule-path": dir, "rule-files": []string{"active.rules"}, "run-as": map[string]any{}, "unix-command": map[string]any{"enabled": true, "filename": cfg.SuricataSocket}, "outputs": []any{}, "logging": map[string]any{"default-log-level": "notice", "outputs": []any{}}, "flow": map[string]any{"memcap": "16mb", "hash-size": 1024, "prealloc": 1024}, "stream": map[string]any{"memcap": "32mb", "reassembly": map[string]any{"memcap": "64mb"}}}
	raw, err := json.Marshal(settings)
	require(t, err)
	require(t, os.WriteFile(cfg.SuricataConfig, append([]byte("%YAML 1.1\n---\n"), raw...), 0600))
	processCtx, stopProcess := context.WithCancel(ctx)
	native := exec.CommandContext(processCtx, cfg.SuricataBinary, "-c", cfg.SuricataConfig, "--unix-socket="+cfg.SuricataSocket, "-l", dir)
	native.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
	native.Stdout, native.Stderr = io.Discard, io.Discard
	native.WaitDelay = 2 * time.Second
	require(t, native.Start())
	done := make(chan error, 1)
	go func() { done <- native.Wait() }()
	t.Cleanup(func() { stopProcess(); <-done })
	require(t, os.WriteFile(cfg.SuricataPIDFile, []byte(strconv.Itoa(native.Process.Pid)), 0600))
	eventually(t, ctx, "原生发布探针未就绪", func() bool {
		c, err := net.DialTimeout("unix", cfg.SuricataSocket, 100*time.Millisecond)
		if err != nil {
			return false
		}
		_ = c.Close()
		return true
	})
	clientTLS, err := transport.TLS(filepath.Join(pki, "ca.crt"), filepath.Join(identityDir, "agent.crt"), filepath.Join(identityDir, "agent.key"), false)
	require(t, err)
	connection, err := grpc.NewClient(address, grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)))
	require(t, err)
	t.Cleanup(func() { _ = connection.Close() })
	client := sensorv1.NewSensorServiceClient(connection)
	engine := &agent.Engine{Config: cfg, WAL: wal, ReplayClient: client}
	manager, err := agent.NewTaskManager(wal, pub, engine)
	require(t, err)
	taskCtx, stopTasks := context.WithCancel(ctx)
	taskDone := make(chan error, 1)
	go func() { taskDone <- manager.Run(taskCtx) }()
	t.Cleanup(func() { stopTasks(); require(t, <-taskDone) })
	stream, err := client.Control(ctx)
	require(t, err)
	t.Cleanup(func() { _ = stream.CloseSend() })
	return &nativeRolloutProbe{id, engine, manager, stream}
}
func TestRuleRolloutTwoNativeProbesMTLSAndRealObservation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 220*time.Second)
	defer cancel()
	f := newIsolatedDatabase(t, ctx)
	tenant := store.RandomID("it_rollout_live_")
	password := store.Token()
	require(t, admin.Bootstrap(ctx, f.Owner, tenant, "双探针分批发布", tenant, password, "admin"))
	u, _, err := f.Runtime.Password(ctx, tenant)
	require(t, err)
	base, err := os.MkdirTemp("", "sb-rollout-")
	require(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	pki := filepath.Join(base, "pki")
	require(t, admin.DevPKI(pki))
	pub, signer, err := ed25519.GenerateKey(rand.Reader)
	require(t, err)
	objects, err := replay.NewLocal(filepath.Join(base, "samples"), 100<<20)
	require(t, err)
	serverTLS, err := transport.TLS(filepath.Join(pki, "ca.crt"), filepath.Join(pki, "server.crt"), filepath.Join(pki, "server.key"), true)
	require(t, err)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require(t, err)
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(serverTLS)))
	sensorv1.RegisterSensorServiceServer(server, &ingest.Server{DB: f.Runtime, ControlOnly: true, TasksEnabled: true, Samples: objects, Wakeup: &control.Wakeup{}})
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	probes := []*nativeRolloutProbe{}
	for _, name := range []string{"sensor_canary", "sensor_batch"} {
		probes = append(probes, newNativeRolloutProbe(t, ctx, f, tenant, pki, base, listener.Addr().String(), name, pub))
	}
	heartbeat := func(p *nativeRolloutProbe) {
		t.Helper()
		rules, err := os.ReadFile(p.engine.Config.SuricataRulesPath)
		require(t, err)
		monitor := &agent.EngineMonitor{Engine: p.engine}
		observation := monitor.Observe(ctx)
		if observation.State != "observed" {
			t.Fatal("独立原生引擎观测失败", observation.Code)
		}
		raw, _ := json.Marshal(model.HostHealth{ObservedAt: time.Now().UTC(), TaskCapabilities: p.engine.Capabilities(), CommandSignerSHA256: control.Digest(pub), RegisteredRulesAvailable: true, RegisteredRulesSHA256: control.Digest(rules), EngineHealth: observation})
		require(t, p.stream.Send(&sensorv1.AgentMessage{SensorId: p.id.SensorID, SensorRegistrationId: p.id.RegistrationID, Kind: sensorv1.AgentMessageKind_AGENT_MESSAGE_KIND_HEARTBEAT, MessageId: store.RandomID("hb_"), PayloadSchema: "host.health.v1", PayloadJson: raw}))
		ack, err := p.stream.Recv()
		require(t, err)
		if ack.Kind != sensorv1.CommandKind_COMMAND_KIND_HEARTBEAT_ACK {
			t.Fatal("心跳未独立确认")
		}
	}
	for _, p := range probes {
		heartbeat(p)
	}
	rule, err := f.Runtime.SaveRulePackage(ctx, u, "rollout_rules", "分批验证规则", `alert http any any -> any any (msg:"StarBeacon rollout"; flow:established,to_server; http.uri; content:"/starbeacon/validation"; sid:1001988; rev:1;)`, 0, "rules")
	require(t, err)
	var samples [2]string
	for i, p := range []string{"/starbeacon/validation", "/starbeacon/allowed"} {
		data, err := testpcap.HTTPPath(false, p)
		require(t, err)
		s := replay.Sample{ID: store.RandomID("sample_"), Name: "分批发布样本.pcap", Size: int64(len(data))}
		samples[i] = s.ID
		require(t, f.Runtime.ReserveSample(ctx, u, s, 100<<20))
		s.SHA256, s.Format, err = objects.Put(ctx, replay.Key(tenant, s.ID), bytes.NewReader(data), s.Size)
		require(t, err)
		require(t, f.Runtime.CompleteSample(ctx, u, s.ID, s.SHA256, s.Format, "import"))
	}
	auth := httpapi.NewAuth(f.Runtime, nil, "http://127.0.0.1", "rollout_session", false)
	api := &platform.API{DB: f.Runtime, Auth: auth, Signer: signer, Samples: objects}
	web := httptest.NewServer(httpapi.Middleware(api.Handler()))
	t.Cleanup(web.Close)
	auth.Origin = web.URL
	jar, err := cookiejar.New(nil)
	require(t, err)
	h := &liveHTTP{t: t, ctx: ctx, origin: web.URL, prefix: "/api/v1", client: &http.Client{Jar: jar, Timeout: 5 * time.Second}}
	h.login(tenant, password)
	c := rulerollout.Create{ID: "rollout_native", Spec: rulerollout.Spec{Name: "两个探针分批发布", CanaryCount: 1, BatchSize: 1, ObservationSeconds: 30, TimeoutSeconds: 600}}
	for i, p := range probes {
		s := rulesync.Spec{Name: "原生同步 " + p.id.SensorID, SensorID: p.id.SensorID, RegistrationID: p.id.RegistrationID, PackageID: rule.ID, PackageRevision: rule.Revision, PositiveSampleID: samples[0], NegativeSampleID: samples[1], IntervalSeconds: 30}
		var plan rulesync.Plan
		h.request("POST", "/rule-sync-plans", "plan_"+strconv.Itoa(i), rulesync.Change{ID: "sync_" + strconv.Itoa(i), Spec: s}, &plan, 200)
		c.Spec.Plans = append(c.Spec.Plans, rulerollout.Selection{PlanID: plan.ID, Revision: plan.Revision})
	}
	var rollout rulerollout.Rollout
	h.request("POST", "/rule-rollouts", "rollout", c, &rollout, 200)
	h.request("POST", "/rule-rollouts", "retry", c, &rollout, 200)
	pulse := func() {
		t.Helper()
		_, err := f.Owner.Pool.Exec(ctx, `UPDATE rule_rollouts SET next_at=now()-interval '1 second' WHERE tenant_id=$1 AND id=$2`, tenant, c.ID)
		require(t, err)
		_, err = f.Runtime.SweepRuleRollouts(ctx, tenant)
		require(t, err)
		h.request("GET", "/rule-rollouts/"+c.ID, "", nil, &rollout, 200)
	}
	execute := func(p *nativeRolloutProbe, task string) {
		t.Helper()
		delivery, err := p.stream.Recv()
		require(t, err)
		if delivery.Kind != sensorv1.CommandKind_COMMAND_KIND_TASK || delivery.CommandId != task {
			t.Fatal("任务目标不匹配")
		}
		require(t, p.manager.Accept(delivery.PayloadJson, delivery.Signature))
		var final []byte
		var receipt control.Receipt
		eventually(t, ctx, "分批发布任务无实际终态", func() bool {
			pending, err := p.manager.Pending()
			require(t, err)
			for _, raw := range pending {
				var candidate control.Receipt
				require(t, json.Unmarshal(raw, &candidate))
				if candidate.CommandID == task && candidate.FinishedAt != nil {
					receipt = candidate
					final = raw
					return true
				}
			}
			return false
		})
		if receipt.State != "succeeded" {
			t.Fatal("原生任务失败", receipt.Code, string(receipt.Result))
		}
		require(t, p.stream.Send(&sensorv1.AgentMessage{SensorId: p.id.SensorID, SensorRegistrationId: p.id.RegistrationID, Kind: sensorv1.AgentMessageKind_AGENT_MESSAGE_KIND_TASK_RECEIPT, MessageId: store.RandomID("receipt_"), CommandId: task, PayloadSchema: control.ReceiptSchema, PayloadJson: final}))
		ack, err := p.stream.Recv()
		require(t, err)
		if ack.Kind != sensorv1.CommandKind_COMMAND_KIND_RECEIPT_ACK || ack.CommandId != task {
			t.Fatal("回执错误")
		}
		require(t, p.manager.Confirm(task, ack.PayloadSha256))
	}
	for batch, p := range probes {
		pulse()
		if rollout.Targets[batch].ExecutionRevision != 2 {
			t.Fatal("批次未启用", rollout.State)
		}
		if batch == 0 && rollout.Targets[1].ExecutionRevision != 0 {
			t.Fatal("验证之前启用了后续探针")
		}
		for stage := 0; stage < 4; stage++ {
			_, err = f.Owner.Pool.Exec(ctx, `UPDATE rule_sync_plans SET next_at=now()-interval '1 second' WHERE tenant_id=$1 AND id=$2`, tenant, c.Spec.Plans[batch].PlanID)
			require(t, err)
			_, err = f.Runtime.SweepRuleSync(ctx, tenant, signer)
			require(t, err)
			h.request("GET", "/rule-rollouts/"+c.ID, "", nil, &rollout, 200)
			run := rollout.Targets[batch].Run
			if run == nil || run.Stage != stage || run.Tasks[stage] == "" {
				t.Fatal("设备验证阶段未持久提交")
			}
			execute(p, run.Tasks[stage])
		}
		heartbeat(p)
		_, err = f.Owner.Pool.Exec(ctx, `UPDATE rule_sync_plans SET next_at=now()-interval '1 second' WHERE tenant_id=$1 AND id=$2`, tenant, c.Spec.Plans[batch].PlanID)
		require(t, err)
		_, err = f.Runtime.SweepRuleSync(ctx, tenant, signer)
		require(t, err)
		// 同步运行完成以后再发送心跳；之前的心跳不能满足发布后的观测水位。
		heartbeat(p)
		pulse()
		if rollout.State != "observing" || rollout.ObservationStartedAt == nil {
			t.Fatal("没有进入实际观察窗口", rollout.State, rollout.Code)
		}
		started := *rollout.ObservationStartedAt
		if batch == 0 && rollout.Targets[1].ExecutionRevision != 0 {
			t.Fatal("观察前执行了下一批")
		}
		for time.Since(started) < 31*time.Second {
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-time.After(time.Second):
			}
			for _, probe := range probes {
				heartbeat(probe)
			}
			pulse()
			if time.Since(started) < 30*time.Second && rollout.CurrentBatch != batch {
				t.Fatal("观察窗口提前结束")
			}
		}
		for _, probe := range probes {
			heartbeat(probe)
		}
		pulse()
		if batch == 0 && rollout.CurrentBatch != 1 {
			t.Fatal("实际新心跳未解锁下一批")
		}
	}
	if rollout.State != "succeeded" || rollout.Code != "observed" || rollout.FinishedAt == nil {
		t.Fatal("双探针实际发布没有完成", rollout.State, rollout.Code)
	}
	for i, target := range rollout.Targets {
		if target.State != "succeeded" || target.Run == nil {
			t.Fatal("实际目标证据不完整")
		}
		var result json.RawMessage
		require(t, f.Owner.Pool.QueryRow(ctx, `SELECT receipt->'result' FROM sensor_tasks WHERE tenant_id=$1 AND id=$2`, tenant, target.Run.Tasks[3]).Scan(&result))
		if !rulesync.Applied(result, rule.SHA256) {
			t.Fatal("目标缺少独立实际装载回读")
		}
		actual, err := os.ReadFile(probes[i].engine.Config.SuricataRulesPath)
		require(t, err)
		if control.Digest(actual) != rule.SHA256 {
			t.Fatal("规则文件未实际切换")
		}
	}
	for _, suffix := range []string{"?bad=1", "?cursor=a&cursor=b", "?cursor=bad/id"} {
		h.request("GET", "/rule-rollouts"+suffix, "", nil, nil, 400)
	}
	h.request("GET", "/rule-rollouts/rollout_absent", "", nil, nil, 404)
	h.request("POST", "/rule-rollouts/"+c.ID+"/stop", "finished_stop", rulerollout.Stop{Reason: "完成后停止"}, nil, 409)
	// 原批次释放预留后，管理员重新保存停用修订；第二个批次在派发前停止。
	for i, p := range probes {
		s := rollout.Targets[i].Spec
		var plan rulesync.Plan
		h.request("POST", "/rule-sync-plans", "disable_"+p.id.SensorID, rulesync.Change{ID: c.Spec.Plans[i].PlanID, ExpectedRevision: 2, Spec: s}, &plan, 200)
		c.Spec.Plans[i].Revision = plan.Revision
	}
	c.ID = "rollout_stop_native"
	h.request("POST", "/rule-rollouts", "second", c, &rollout, 200)
	h.request("POST", "/rule-rollouts/"+c.ID+"/stop", "invalid_reason", rulerollout.Stop{}, nil, 400)
	h.request("POST", "/rule-rollouts/"+c.ID+"/stop", "stop", rulerollout.Stop{Reason: "演练结束，停止后续任务"}, &rollout, 200)
	if rollout.State != "stopping" || rollout.StoppedBy != u.ID {
		t.Fatal("停止受理状态错误")
	}
	h.request("POST", "/rule-rollouts/"+c.ID+"/stop", "stop_retry", rulerollout.Stop{Reason: "演练结束，停止后续任务"}, &rollout, 200)
	h.request("POST", "/rule-rollouts/"+c.ID+"/stop", "stop_other", rulerollout.Stop{Reason: "不同原因"}, nil, 409)
	pulse()
	if rollout.State != "stopped" {
		t.Fatal("派发前停止未完成")
	}
	var page store.RuleRolloutPage
	h.request("GET", "/rule-rollouts", "", nil, &page, 200)
	if len(page.Items) != 2 {
		t.Fatal("发布目录缺少独立运行")
	}
}
