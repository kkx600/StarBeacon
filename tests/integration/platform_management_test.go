//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	sensorv1 "github.com/kkx600/StarBeacon/api/sensor/v1"
	"github.com/kkx600/StarBeacon/internal/admin"
	"github.com/kkx600/StarBeacon/internal/config"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/replay"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/testpcap"
	"github.com/kkx600/StarBeacon/internal/transport"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// 原生进程、实际 HTTP 会话和 mTLS 控制消息共同验证管理操作，不以直接调用处理函数替代入口验收。
func TestNativePlatformManagementIsolationCASAuditSampleRecoveryAndLogout(t *testing.T) {
	if os.Getenv("SB_TEST_MANAGEMENT_BINARY") == "" {
		t.Skip("需要平台原生制品")
	}
	ctx, stop := context.WithTimeout(context.Background(), 150*time.Second)
	defer stop()
	fixture := newIsolatedDatabase(t, ctx)
	password := store.Token()
	for _, user := range []struct{ tenant, username, role string }{{"http_a", "http_admin_a", "admin"}, {"http_b", "http_admin_b", "admin"}, {"http_a", "http_viewer", "viewer"}} {
		require(t, admin.Bootstrap(ctx, fixture.Owner, user.tenant, "平台管理验收", user.username, password, user.role))
	}
	directory := t.TempDir()
	pki := filepath.Join(directory, "pki")
	require(t, admin.DevPKI(pki))
	identity, err := admin.Provision(ctx, fixture.Owner, "http_a", "sensor_http", "管理链路探针", pki, filepath.Join(directory, "agent"))
	require(t, err)
	private, public := filepath.Join(directory, "command.key"), filepath.Join(directory, "command.pub")
	require(t, control.GenerateKeys(private, public))
	signer, err := control.PrivateKey(private)
	require(t, err)
	address := availableAddress(t)
	upstream, err := url.Parse("http://" + address)
	require(t, err)
	endpoint := httptest.NewTLSServer(httputil.NewSingleHostReverseProxy(upstream))
	defer endpoint.Close()
	redisEndpoint, err := url.Parse(os.Getenv("SB_REDIS_URL"))
	require(t, err)
	redisEndpoint.Path = "/9"
	configuration := config.Config{
		Mode: "development", HTTPAddr: address, GRPCAddr: availableAddress(t),
		DatabaseURL: fixture.RuntimeDSN, ESURL: os.Getenv("SB_ES_URL"), RedisURL: redisEndpoint.String(),
		AllowedOrigin: endpoint.URL, CommandSigningKey: private,
		TLSCA: filepath.Join(pki, "ca.crt"), TLSCert: filepath.Join(pki, "server.crt"), TLSKey: filepath.Join(pki, "server.key"),
		ReplayBackend: "filesystem", ReplayDir: filepath.Join(directory, "samples"), ReplayBytes: 128 << 20,
	}
	run, cancel := context.WithCancel(ctx)
	command := exec.CommandContext(run, filepath.Join(filepath.Dir(os.Getenv("SB_TEST_MANAGEMENT_BINARY")), "starbeacon"))
	command.Env = roleEnvironment(configuration)
	command.Cancel = func() error { return command.Process.Signal(syscall.SIGTERM) }
	command.WaitDelay = 8 * time.Second
	logPath := filepath.Join(directory, "platform.log")
	output, err := os.OpenFile(logPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	require(t, err)
	command.Stdout, command.Stderr = output, output
	require(t, command.Start())
	require(t, output.Close())
	finished := make(chan error, 1)
	go func() { finished <- command.Wait() }()
	defer func() {
		cancel()
		select {
		case err := <-finished:
			if err != nil && !(errors.Is(err, context.Canceled) && command.ProcessState != nil && command.ProcessState.ExitCode() == 0) {
				t.Error("平台原生进程退出异常", err)
				f, err := os.Open(logPath)
				if err == nil {
					defer f.Close()
					data, _ := io.ReadAll(io.LimitReader(f, 65536))
					message := string(data)
					for _, secret := range []string{fixture.OwnerDSN, fixture.RuntimeDSN, configuration.RedisURL, password} {
						message = strings.ReplaceAll(message, secret, "[凭据隐藏]")
					}
					t.Log(message)
				}
			}
		case <-time.After(10 * time.Second):
			t.Error("平台原生进程没有按时停止")
		}
	}()
	health := *endpoint.Client()
	health.Timeout = time.Second
	eventually(t, ctx, "平台管理入口就绪", func() bool {
		response, err := health.Get(endpoint.URL + "/readyz")
		if err != nil {
			return false
		}
		defer response.Body.Close()
		return response.StatusCode == 200
	})
	client := func() *liveHTTP {
		copy := *endpoint.Client()
		jar, err := cookiejar.New(nil)
		require(t, err)
		copy.Jar, copy.Timeout = jar, 12*time.Second
		return &liveHTTP{t: t, ctx: ctx, client: &copy, origin: endpoint.URL, prefix: "/api/v1"}
	}
	a, b, viewer, anonymous := client(), client(), client(), client()
	anonymous.request("GET", "/sensors", "", nil, nil, 401)
	a.login("http_admin_a", password)
	b.login("http_admin_b", password)
	viewer.login("http_viewer", password)
	var page struct {
		Items []model.Sensor `json:"items"`
	}
	a.request("GET", "/sensors", "", nil, &page, 200)
	if len(page.Items) != 1 || page.Items[0].ID != identity.SensorID {
		t.Fatal("探针列表缺少注册对象")
	}
	b.request("GET", "/sensors", "", nil, &page, 200)
	if len(page.Items) != 0 {
		t.Fatal("探针列表泄漏其他租户对象")
	}
	path := "/sensors/" + identity.SensorID
	viewer.request("PATCH", path, "", map[string]bool{"active": false}, nil, 403)
	b.request("PATCH", path, "", map[string]bool{"active": false}, nil, 404)
	a.request("PATCH", path, "", map[string]any{}, nil, 400)
	a.request("PATCH", path, "", map[string]any{"active": "false"}, nil, 400)
	a.request("PATCH", path, "", map[string]any{"active": true, "tenant_id": "http_b"}, nil, 400)
	csrf := a.csrf
	a.csrf = ""
	a.request("PATCH", path, "", map[string]bool{"active": false}, nil, 403)
	a.csrf = csrf
	a.request("PATCH", path, "", map[string]bool{"active": false}, nil, 200)
	a.request("GET", "/sensors", "", nil, &page, 200)
	if len(page.Items) != 1 || page.Items[0].Status != "disabled" || page.Items[0].Active {
		t.Fatal("停用探针状态没有读回")
	}
	a.request("POST", path+"/tasks", store.RandomID("key_"), map[string]string{"kind": "diagnostics"}, nil, 404)
	a.request("PATCH", path, "", map[string]bool{"active": true}, nil, 200)
	tls, err := transport.TLS(configuration.TLSCA, filepath.Join(directory, "agent", "agent.crt"), filepath.Join(directory, "agent", "agent.key"), false)
	require(t, err)
	connection, err := grpc.NewClient(configuration.GRPCAddr, grpc.WithTransportCredentials(credentials.NewTLS(tls)))
	require(t, err)
	defer connection.Close()
	sensor := sensorv1.NewSensorServiceClient(connection)
	heartbeat := func(h model.HostHealth) {
		t.Helper()
		call, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		stream, err := sensor.Control(call)
		require(t, err)
		raw, err := json.Marshal(h)
		require(t, err)
		require(t, stream.Send(&sensorv1.AgentMessage{SensorId: identity.SensorID, SensorRegistrationId: identity.RegistrationID, Kind: sensorv1.AgentMessageKind_AGENT_MESSAGE_KIND_HEARTBEAT, MessageId: store.RandomID("hb_"), PayloadSchema: "host.health.v1", PayloadJson: raw}))
		ack, err := stream.Recv()
		require(t, err)
		if ack.Kind != sensorv1.CommandKind_COMMAND_KIND_HEARTBEAT_ACK {
			t.Fatal("原生控制入口没有持久确认心跳")
		}
		require(t, stream.CloseSend())
		_, err = stream.Recv()
		if !errors.Is(err, io.EOF) {
			t.Fatal("心跳连接未正常结束", err)
		}
	}
	h := model.HostHealth{ObservedAt: time.Now().UTC(), TaskCapabilities: []string{"diagnostics", "rules.validate", "rules.replay", "rules.apply", "unrecognized"}, RegisteredRulesAvailable: true, CommandSignerSHA256: control.Digest([]byte("different-key"))}
	heartbeat(h)
	a.request("POST", path+"/tasks", store.RandomID("key_"), map[string]string{"kind": "diagnostics"}, nil, 409)
	h.CommandSignerSHA256 = control.Digest(signer.Public().(ed25519.PublicKey))
	heartbeat(h)
	a.request("POST", path+"/tasks", "", map[string]string{"kind": "diagnostics"}, nil, 400)
	a.request("POST", path+"/tasks", store.RandomID("key_"), map[string]string{"kind": "unrecognized"}, nil, 400)
	a.request("POST", path+"/tasks", store.RandomID("key_"), map[string]string{"kind": "diagnostics", "sample_id": "irrelevant"}, nil, 400)
	viewer.request("GET", "/rule-packages", "", nil, nil, 403)
	var packages struct {
		Items []store.RulePackage `json:"items"`
	}
	a.request("GET", "/rule-packages", "", nil, &packages, 200)
	if len(packages.Items) != 0 {
		t.Fatal("规则列表初始状态异常")
	}
	rule := `alert http any any -> any any (msg:"StarBeacon 管理链路验证"; http.uri; content:"/starbeacon-test"; sid:1001001; rev:1;)`
	input := map[string]any{"id": "rules_http", "name": "管理链路规则", "text": rule, "expected_revision": 0}
	var revisionOne, revisionTwo store.RulePackage
	a.request("POST", "/rule-packages", "", input, &revisionOne, 201)
	a.request("POST", "/rule-packages", "", input, nil, 409)
	input["expected_revision"], input["text"] = 1, strings.ReplaceAll(rule, "rev:1", "rev:2")
	a.request("POST", "/rule-packages", "", input, &revisionTwo, 201)
	if revisionOne.Revision != 1 || revisionTwo.Revision != 2 || revisionOne.SHA256 == revisionTwo.SHA256 {
		t.Fatal("规则包修订或不可变摘要异常")
	}
	a.request("GET", "/rule-packages", "", nil, &packages, 200)
	if len(packages.Items) != 1 || packages.Items[0].Revision != 2 || packages.Items[0].Text != "" {
		t.Fatal("规则列表没有返回最新元数据")
	}
	var historical store.RulePackage
	a.request("GET", "/rule-packages/rules_http/1", "", nil, &historical, 200)
	if historical.Text != rule || historical.SHA256 != revisionOne.SHA256 {
		t.Fatal("历史规则修订被覆盖")
	}
	for _, revision := range []string{"0", "invalid", "9223372036854775808"} {
		a.request("GET", "/rule-packages/rules_http/"+revision, "", nil, nil, 400)
	}
	a.request("GET", "/rule-packages/rules_http/3", "", nil, nil, 404)
	b.request("GET", "/rule-packages/rules_http/1", "", nil, nil, 404)
	a.request("POST", path+"/tasks", store.RandomID("key_"), map[string]any{"kind": "rules.apply", "package_id": "rules_http", "revision": 2}, nil, 409)
	a.request("POST", "/replay/samples", "", bytes.Repeat([]byte{0}, 24), nil, 422)
	var reserved int
	require(t, fixture.Owner.Pool.QueryRow(ctx, "SELECT count(*) FROM replay_samples").Scan(&reserved))
	files, err := os.ReadDir(configuration.ReplayDir)
	require(t, err)
	if reserved != 0 || len(files) != 0 {
		t.Fatal("非法 PCAP 导入后遗留对象或预占额度")
	}
	capture, err := testpcap.HTTP(false)
	require(t, err)
	var sample replay.Sample
	a.request("POST", "/replay/samples", "", capture, &sample, 201)
	if sample.SHA256 != control.Digest(capture) || sample.ExpiresAt.Sub(sample.CreatedAt) != 180*24*time.Hour {
		t.Fatal("导入摘要或默认 180 天期限不一致")
	}
	var samples struct {
		Items     []replay.Sample `json:"items"`
		Available bool            `json:"available"`
		MaxBytes  int64           `json:"max_bytes"`
	}
	a.request("GET", "/replay/samples", "", nil, &samples, 200)
	if len(samples.Items) != 1 || !samples.Available || samples.MaxBytes != replay.MaxSampleBytes {
		t.Fatal("样本列表、额度或可用状态异常")
	}
	b.request("GET", "/replay/samples", "", nil, &samples, 200)
	if len(samples.Items) != 0 {
		t.Fatal("样本列表越租户读取")
	}
	viewer.request("GET", "/replay/samples", "", nil, nil, 403)
	var task struct {
		ID string `json:"id"`
	}
	key := store.RandomID("key_")
	replayInput := map[string]any{"kind": "rules.replay", "sample_id": sample.ID, "rule_mode": "package", "package_id": revisionOne.ID, "revision": 1}
	a.request("POST", path+"/tasks", key, replayInput, &task, 202)
	firstID := task.ID
	a.request("POST", path+"/tasks", key, replayInput, &task, 202)
	if firstID == "" || firstID != task.ID {
		t.Fatal("重复提交产生了不同任务")
	}
	replayInput["revision"] = 2
	a.request("POST", path+"/tasks", key, replayInput, nil, 409)
	b.request("POST", "/tasks/"+task.ID+"/cancel", "", nil, nil, 409)
	viewer.request("POST", "/tasks/"+task.ID+"/cancel", "", nil, nil, 403)
	a.request("POST", "/tasks/"+task.ID+"/cancel", "", nil, nil, 200)
	a.request("POST", "/tasks/"+task.ID+"/cancel", "", nil, nil, 409)
	var tasks struct {
		Items []store.SensorTask `json:"items"`
	}
	a.request("GET", "/tasks?sensor_id="+identity.SensorID, "", nil, &tasks, 200)
	if len(tasks.Items) != 1 || tasks.Items[0].State != "cancelled" || tasks.Items[0].DeliveryCount != 0 {
		t.Fatal("取消任务未持久保存或改变了投递计数")
	}
	a.request("POST", path+"/tasks", store.RandomID("key_"), map[string]string{"kind": "diagnostics"}, &task, 202)
	call, cancelDelivery := context.WithTimeout(ctx, 10*time.Second)
	stream, err := sensor.Control(call)
	require(t, err)
	defer cancelDelivery()
	for {
		message, err := stream.Recv()
		require(t, err)
		if message.Kind != sensorv1.CommandKind_COMMAND_KIND_TASK {
			continue
		}
		decoded, err := control.Decode(message.PayloadJson, message.Signature, signer.Public().(ed25519.PublicKey), identity.TenantID, identity.SensorID, identity.RegistrationID, time.Now().UTC())
		require(t, err)
		if decoded.ID != task.ID || decoded.Kind != "diagnostics" {
			t.Fatal("实际投递任务与 HTTP 持久任务不一致")
		}
		break
	}
	a.request("POST", "/tasks/"+task.ID+"/cancel", "", nil, nil, 409)
	require(t, stream.CloseSend())
	cancelDelivery()
	var audit store.AuditResult
	a.request("GET", "/audits/operations?action=rule.package.save&username=http_admin_a", "", nil, &audit, 200)
	if len(audit.Items) != 2 {
		t.Fatal("规则保存审计缺失或重复")
	}
	for _, record := range audit.Items {
		if record.SourceIP == "" || record.UserAgent == "" || !strings.HasPrefix(record.RequestID, "req_") || record.Username != "http_admin_a" {
			t.Fatal("操作日志缺少实际请求元数据")
		}
	}
	a.request("GET", "/audits/operations?limit=1", "", nil, &audit, 200)
	if len(audit.Items) != 1 || audit.NextCursor == "" {
		t.Fatal("操作日志没有返回有界游标")
	}
	newest := audit.Items[0].ID
	a.request("GET", "/audits/operations?limit=1&cursor="+audit.NextCursor, "", nil, &audit, 200)
	if len(audit.Items) != 1 || audit.Items[0].ID == newest {
		t.Fatal("日志游标重复返回同一对象")
	}
	b.request("GET", "/audits/operations", "", nil, &audit, 200)
	if len(audit.Items) != 0 {
		t.Fatal("操作日志越租户读取")
	}
	viewer.request("GET", "/audits/operations", "", nil, nil, 403)
	anonymous.request("POST", "/auth/login", "", map[string]string{"username": "http_admin_a", "password": "incorrect-password"}, nil, 401)
	a.request("GET", "/audits/logins?success=false&username=http_admin_a", "", nil, &audit, 200)
	if len(audit.Items) != 1 || audit.Items[0].Success == nil || *audit.Items[0].Success {
		t.Fatal("已知账号的登录失败未记录")
	}
	a.request("GET", "/audits/logins?success=true&username=http_admin_a", "", nil, &audit, 200)
	if len(audit.Items) != 1 || audit.Items[0].Success == nil || !*audit.Items[0].Success {
		t.Fatal("登录成功记录或结果筛选不一致")
	}
	permissionFailure := func(privilege, table string, check func()) {
		t.Helper()
		name := pgx.Identifier{table}.Sanitize()
		_, err := fixture.Owner.Pool.Exec(ctx, "REVOKE "+privilege+" ON "+name+" FROM starbeacon_app")
		require(t, err)
		defer func() {
			_, err := fixture.Owner.Pool.Exec(ctx, "GRANT "+privilege+" ON "+name+" TO starbeacon_app")
			require(t, err)
		}()
		check()
	}
	// 审计不可用时实际业务必须回滚；故障只注入专属数据库中的表权限。
	permissionFailure("INSERT", "operation_audits", func() {
		a.request("PATCH", path, "", map[string]bool{"active": false}, nil, 503)
		a.request("GET", "/sensors", "", nil, &page, 200)
		if len(page.Items) != 1 || !page.Items[0].Active {
			t.Fatal("审计失败仍提交了探针停用")
		}
		input["expected_revision"], input["text"] = 2, strings.ReplaceAll(rule, "rev:1", "rev:3")
		a.request("POST", "/rule-packages", "", input, nil, 503)
		a.request("GET", "/rule-packages", "", nil, &packages, 200)
		if len(packages.Items) != 1 || packages.Items[0].Revision != 2 {
			t.Fatal("审计失败仍提交了规则修订")
		}
		a.request("POST", "/replay/samples", "", capture, nil, 503)
		require(t, fixture.Owner.Pool.QueryRow(ctx, "SELECT count(*) FROM replay_samples").Scan(&reserved))
		files, err := os.ReadDir(configuration.ReplayDir)
		require(t, err)
		if reserved != 1 || len(files) != 1 {
			t.Fatal("导入审计失败后遗留未发布对象或额度")
		}
	})
	for _, test := range []struct{ table, path string }{
		{"operation_audits", "/audits/operations"},
		{"login_audits", "/audits/logins"},
		{"sensors", "/sensors"},
		{"rule_packages", "/rule-packages"},
		{"replay_samples", "/replay/samples"},
	} {
		permissionFailure("SELECT", test.table, func() {
			a.request("GET", test.path, "", nil, nil, 503)
		})
	}
	var beforeSessions, afterSessions int
	require(t, fixture.Owner.Pool.QueryRow(ctx, "SELECT count(*) FROM sessions").Scan(&beforeSessions))
	permissionFailure("INSERT", "login_audits", func() {
		anonymous.request("POST", "/auth/login", "", map[string]string{"username": "http_admin_a", "password": password}, nil, 503)
	})
	require(t, fixture.Owner.Pool.QueryRow(ctx, "SELECT count(*) FROM sessions").Scan(&afterSessions))
	if beforeSessions != afterSessions {
		t.Fatal("登录审计失败仍签发了会话")
	}
	for _, query := range []string{"start=invalid", "end=invalid", "limit=invalid", "limit=0", "limit=101", "cursor=-1", "cursor=invalid", "success=unknown", "start=2020-01-01T00%3A00%3A00Z&end=2020-03-01T00%3A00%3A00Z"} {
		a.request("GET", "/audits/logins?"+query, "", nil, nil, 400)
	}
	a.request("POST", "/auth/logout", "", nil, nil, 200)
	a.request("GET", "/auth/me", "", nil, nil, 401)
	a.login("http_admin_a", password)
	_, err = fixture.Owner.Pool.Exec(ctx, "UPDATE users SET active=false WHERE tenant_id='http_a' AND username='http_admin_a'")
	require(t, err)
	a.request("GET", "/sensors", "", nil, nil, 401)
	// 只核对本用例专属库，不放宽共享验收库的 RLS 或修改其他租户。
	require(t, fixture.Runtime.TenantTx(ctx, "http_b", func(tx pgx.Tx) error {
		var rows int
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM replay_samples").Scan(&rows); err != nil {
			return err
		}
		if rows != 0 {
			t.Fatal("运行角色的 RLS 读取了其他租户样本")
		}
		return nil
	}))
	// 平台原生进程自己触发回收，不通过测试直接调用 SweepHistory 替代调度路径。
	_, err = fixture.Owner.Pool.Exec(ctx, `INSERT INTO operation_audits(tenant_id,user_id,action,object_id,request_id,expires_at) VALUES('http_a','owner','history.periodic','periodic_expired','test',now()-interval '1 minute')`)
	require(t, err)
	reclaim, stopReclaim := context.WithTimeout(ctx, 75*time.Second)
	defer stopReclaim()
	timer := time.NewTicker(time.Second)
	defer timer.Stop()
	var lastMetrics []byte
	for {
		select {
		case <-reclaim.Done():
			t.Fatalf("平台原生周期任务未同时完成审计回收和指标发布：%v；指标：%.4096s", reclaim.Err(), lastMetrics)
		case <-timer.C:
			var remaining int
			require(t, fixture.Owner.Pool.QueryRow(ctx, `SELECT count(*) FROM operation_audits WHERE object_id='periodic_expired'`).Scan(&remaining))
			if remaining != 0 {
				continue
			}
			// 数据库逐租户提交先于整轮统计发布；两个实际结果都出现才算调度验收通过。
			response, err := health.Get(endpoint.URL + "/metrics")
			require(t, err)
			metrics, readErr := io.ReadAll(io.LimitReader(response.Body, 262145))
			closeErr := response.Body.Close()
			require(t, readErr)
			require(t, closeErr)
			if response.StatusCode != 200 || len(metrics) > 262144 {
				t.Fatal("平台指标响应不可用或超过大小限制")
			}
			lastMetrics = metrics
			deleted, succeeded := false, false
			for line := range strings.SplitSeq(string(metrics), "\n") {
				const deletedLine = `starbeacon_history_deleted_records_total{table="operation_audits"} `
				const succeededLine = `starbeacon_history_cleanup_runs_total{state="succeeded"} `
				if strings.HasPrefix(line, deletedLine) {
					value, err := strconv.ParseFloat(strings.TrimPrefix(line, deletedLine), 64)
					deleted = err == nil && value == 1
				}
				if strings.HasPrefix(line, succeededLine) {
					value, err := strconv.ParseFloat(strings.TrimPrefix(line, succeededLine), 64)
					succeeded = err == nil && value >= 1
				}
			}
			if deleted && succeeded {
				return
			}
		}
	}
}
