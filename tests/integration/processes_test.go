//go:build integration

package integration

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/admin"
	"github.com/kkx600/StarBeacon/internal/agent"
	"github.com/kkx600/StarBeacon/internal/bus"
	"github.com/kkx600/StarBeacon/internal/config"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/hosthealth"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/notify"
	"github.com/kkx600/StarBeacon/internal/replay"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/testpcap"
	"github.com/kkx600/StarBeacon/internal/traffic"
)

type liveHTTP struct {
	t      *testing.T
	ctx    context.Context
	client *http.Client
	origin string
	prefix string
	csrf   string
}

// 验收失败仅记录协议状态和数值计数，不复制报文正文、认证信息或运行环境。
func logCaptureEvidence(t *testing.T, path string) {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Log("原生 EVE 诊断不可读取：", err)
		return
	}
	defer file.Close()
	scanner := bufio.NewScanner(io.LimitReader(file, 4*1024*1024))
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	counts := map[string]int{}
	var latestStats json.RawMessage
	for scanner.Scan() {
		var event struct {
			Type     string `json:"event_type"`
			AppProto string `json:"app_proto"`
			Flow     struct {
				State           string `json:"state"`
				Reason          string `json:"reason"`
				PacketsToServer uint64 `json:"pkts_toserver"`
				PacketsToClient uint64 `json:"pkts_toclient"`
			} `json:"flow"`
			Stats json.RawMessage `json:"stats"`
		}
		if json.Unmarshal(scanner.Bytes(), &event) != nil {
			continue
		}
		counts[event.Type]++
		if event.Type == "flow" && counts["flow"] <= 8 {
			t.Logf("原生会话：协议 %s，状态 %s，结束原因 %s，客户端包 %d，服务端包 %d", event.AppProto, event.Flow.State, event.Flow.Reason, event.Flow.PacketsToServer, event.Flow.PacketsToClient)
		}
		if event.Type == "stats" {
			latestStats = event.Stats
		}
	}
	t.Logf("原生 EVE 类型计数：%v；读取错误：%v", counts, scanner.Err())
	var stats map[string]json.RawMessage
	if json.Unmarshal(latestStats, &stats) == nil {
		for _, name := range []string{"capture.kernel_packets", "capture.kernel_drops", "decoder.pkts", "decoder.bytes", "tcp.reassembly_gap", "app_layer.tx.http", "detect.alert"} {
			value := latestStats
			for _, part := range strings.Split(name, ".") {
				var object map[string]json.RawMessage
				if json.Unmarshal(value, &object) != nil {
					value = nil
					break
				}
				value = object[part]
			}
			var number uint64
			if len(value) > 0 && json.Unmarshal(value, &number) == nil {
				t.Logf("原生计数 %s：%d", name, number)
			}
		}
	}
}

func (c *liveHTTP) request(method, path, key string, body any, result any, status int) {
	c.t.Helper()
	c.requestWithRetry(method, path, key, body, result, status, false)
}

// 原生轮转与配置应用互斥；只有明确未保存的忙碌回执可重试，超时和其他冲突均不重放。
func (c *liveHTTP) configureCapture(body agent.CaptureSettings, result *agent.CaptureState) {
	c.t.Helper()
	c.requestWithRetry("PUT", "/capture-config", "", body, result, http.StatusOK, true)
}

func (c *liveHTTP) requestWithRetry(method, path, key string, body any, result any, status int, captureBusy bool) {
	c.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var input io.Reader
		contentType := "application/json"
		if data, ok := body.([]byte); ok {
			input = bytes.NewReader(data)
			contentType = "application/octet-stream"
		} else if body != nil {
			data, err := json.Marshal(body)
			require(c.t, err)
			input = bytes.NewReader(data)
		}
		r, err := http.NewRequestWithContext(c.ctx, method, c.origin+c.prefix+path, input)
		require(c.t, err)
		r.Header.Set("Content-Type", contentType)
		r.Header.Set("Origin", c.origin)
		r.Header.Set("X-CSRF-Token", c.csrf)
		r.Header.Set("Idempotency-Key", key)
		if contentType == "application/octet-stream" {
			r.Header.Set("X-Filename", "capture.pcap")
		}
		response, err := c.client.Do(r)
		require(c.t, err)
		data, err := io.ReadAll(io.LimitReader(response.Body, 4*1024*1024))
		require(c.t, err)
		_ = response.Body.Close()
		var failure struct {
			Code string `json:"code"`
		}
		if captureBusy && response.StatusCode == http.StatusConflict && json.Unmarshal(data, &failure) == nil && failure.Code == "capture_operation_in_progress" && time.Now().Before(deadline) {
			select {
			case <-c.ctx.Done():
				c.t.Fatal("配置重试已取消", c.ctx.Err())
			case <-time.After(50 * time.Millisecond):
			}
			continue
		}
		if response.StatusCode != status {
			c.t.Fatalf("%s %s：实际状态 %d，预期 %d；%s", method, path, response.StatusCode, status, data)
		}
		if result != nil {
			// HTTP 快照替换整个对象，不能将省略的可选字段沿用为上一次响应值。
			value := reflect.ValueOf(result)
			if value.Kind() != reflect.Pointer || value.IsNil() {
				c.t.Fatal("响应目标必须为非空指针")
			}
			value.Elem().SetZero()
			require(c.t, json.Unmarshal(data, result))
		}
		return
	}
}

func (c *liveHTTP) login(username, password string) {
	c.t.Helper()
	c.request("POST", "/auth/login", "", map[string]string{"username": username, "password": password}, nil, 200)
	var user model.Principal
	c.request("GET", "/auth/me", "", nil, &user, 200)
	c.csrf = user.CSRF
}

func availableAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require(t, err)
	address := listener.Addr().String()
	require(t, listener.Close())
	return address
}

// 同一组服务端口同时保留到分配结束，避免内核再次返回刚释放的端口。
func availableAddresses(t *testing.T, count int) []string {
	t.Helper()
	listeners := make([]net.Listener, 0, count)
	defer func() {
		for _, listener := range listeners {
			require(t, listener.Close())
		}
	}()
	addresses := make([]string, 0, count)
	for range count {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		require(t, err)
		listeners = append(listeners, listener)
		addresses = append(addresses, listener.Addr().String())
	}
	return addresses
}

func eventually(t *testing.T, ctx context.Context, description string, assertion func() bool) {
	t.Helper()
	deadline := time.NewTimer(20 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for !assertion() {
		select {
		case <-ctx.Done():
			t.Fatal(description, ctx.Err())
		case <-deadline.C:
			t.Fatal("等待超时：", description)
		case <-ticker.C:
		}
	}
}

// 角色只获得其运行配置，不继承验收进程的迁移账号或其他探针的凭据。
func roleEnvironment(c config.Config) []string {
	environment := []string{}
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if !strings.HasPrefix(name, "SB_") && name != "GOCOVERDIR" && name != "POSTGRES_PASSWORD" && name != "REDIS_PASSWORD" && name != "NATS_TOKEN" {
			environment = append(environment, entry)
		}
	}
	values := map[string]string{
		"MODE": c.Mode, "HTTP_ADDR": c.HTTPAddr, "GRPC_ADDR": c.GRPCAddr,
		"DATABASE_URL": c.DatabaseURL, "NATS_URL": c.NATSURL, "NATS_NAMESPACE": c.NATSNamespace,
		"ES_URL": c.ESURL, "REDIS_URL": c.RedisURL, "ES_API_KEY": c.ESAPIKey,
		"TLS_CA": c.TLSCA, "TLS_CERT": c.TLSCert, "TLS_KEY": c.TLSKey,
		"ALLOWED_ORIGIN": c.AllowedOrigin, "TENANT_ID": c.TenantID, "SENSOR_ID": c.SensorID, "REGISTRATION_ID": c.RegistrationID,
		"PLATFORM_ADDR": c.PlatformAddr, "INGEST_ADDR": c.IngestAddr, "EVE_PATH": c.EVEPath, "STATE_PATH": c.StatePath, "LOCAL_PASSWORD": c.LocalPassword,
		"COMMAND_SIGNING_KEY": c.CommandSigningKey, "COMMAND_PUBLIC_KEY": c.CommandPublicKey,
		"CREDENTIAL_KEY": c.CredentialKey, "OUTBOUND_PRIVATE_NETWORKS": c.OutboundNetworks, "OUTBOUND_CA": c.OutboundCA,
		"MCP_ISSUER": c.MCPIssuer, "MCP_INTROSPECTION_URL": c.MCPIntrospectionURL, "MCP_CLIENT_ID": c.MCPClientID, "MCP_CLIENT_SECRET": c.MCPClientSecret,
		"REPLAY_BACKEND": c.ReplayBackend, "REPLAY_DIR": c.ReplayDir,
		"PACKET_BACKEND": c.PacketBackend, "PACKET_DIR": c.PacketDir, "PACKET_CODEC": c.PacketCodec,
		"SURICATA_BINARY": c.SuricataBinary, "SURICATA_CONFIG": c.SuricataConfig, "SURICATA_RULES_PATH": c.SuricataRulesPath,
		"SURICATA_SOCKET": c.SuricataSocket, "SURICATA_PID_FILE": c.SuricataPIDFile,
		"RESPONSE_CONNECTORS_FILE": c.ResponseConnectorsFile,
	}
	for key, value := range values {
		if value != "" {
			environment = append(environment, "SB_"+key+"="+value)
		}
	}
	if c.CaptureManaged {
		environment = append(environment, "SB_CAPTURE_MANAGED=true")
		environment = append(environment, "SB_PACKET_CAPTURE="+strconv.FormatBool(c.PacketCapture))
	}
	if c.AllowRuleApply {
		environment = append(environment, "SB_ALLOW_RULE_APPLY=true")
	}
	for key, value := range map[string]int64{"NATS_REPLICAS": int64(c.Replicas), "STREAM_BYTES": c.StreamBytes, "WAL_BYTES": int64(c.WALBytes), "REPLAY_BYTES": c.ReplayBytes, "REPLAY_RETENTION_DAYS": int64(c.ReplayRetentionDays), "CAPTURE_SPOOL_BYTES": c.CaptureSpoolBytes, "CAPTURE_ROTATE_BYTES": c.CaptureRotateBytes, "PACKET_ROTATE_SECONDS": int64(c.PacketRotateInterval / time.Second), "PACKET_SPOOL_BYTES": c.PacketSpoolBytes, "PACKET_SEGMENT_BYTES": c.PacketSegmentBytes, "PACKET_STORAGE_BYTES": c.PacketStorageBytes} {
		if value > 0 {
			environment = append(environment, fmt.Sprintf("SB_%s=%d", key, value))
		}
	}
	if counters := os.Getenv("SB_TEST_BINARY_COVERDIR"); counters != "" {
		environment = append(environment, "GOCOVERDIR="+counters)
	}
	return environment
}

// 同时运行真实角色入口与后台循环，不通过直接调用索引／投递方法绕过排队链路。
func TestLiveRolesNativeCaptureToSearchNotificationAndReplay(t *testing.T) {
	testLiveRolesCaptureToSearchNotificationAndReplay(t, false)
}

func testLiveRolesCaptureToSearchNotificationAndReplay(t *testing.T, managed bool) {
	if os.Getenv("SB_MODE") != "development" || os.Getenv("SB_MIGRATION_DATABASE_URL") == "" || os.Getenv("SB_TEST_SURICATA_BINARY") == "" || os.Getenv("SB_TEST_MANAGEMENT_BINARY") == "" {
		t.Skip("需要独立依赖与明确指定的 Suricata 8.0.7")
	}
	ctx, stop := context.WithTimeout(context.Background(), 100*time.Second)
	defer stop()
	owner, err := store.Open(ctx, os.Getenv("SB_MIGRATION_DATABASE_URL"))
	require(t, err)
	defer owner.Close()
	db, err := store.Open(ctx, os.Getenv("SB_DATABASE_URL"))
	require(t, err)
	defer db.Close()
	require(t, db.VerifyRuntimeRole(ctx))
	tenant, username, password := store.RandomID("it_live_"), store.RandomID("user_live_"), store.Token()
	require(t, admin.Bootstrap(ctx, owner, tenant, "链路验收", username, password, "admin"))
	defer func() {
		clean, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		require(t, owner.TenantTx(clean, tenant, func(tx pgx.Tx) error {
			if _, err := tx.Exec(clean, `DELETE FROM starbeacon_jobs.river_job WHERE args->>'tenant_id'=$1`, tenant); err != nil {
				return err
			}
			for _, table := range []string{"sensor_quality_outbox", "sensor_quality_cursors", "packet_archives", "packet_archive_capacity", "notification_deliveries", "notification_batches", "notification_channel_versions", "notification_channels", "sensor_tasks", "application_rule_revisions", "application_rules", "replay_samples", "rule_packages", "rule_generation_jobs", "rule_sid_registry", "rule_sid_state", "decision_continuous_runs", "decision_responses", "decision_evaluations", "decision_policies", "decision_policy_revisions", "alert_triage_jobs", "model_capability_checks", "model_provider_versions", "model_providers", "operation_audits", "login_audits", "routes", "sensors", "retention_policies"} {
				if _, err := tx.Exec(clean, "DELETE FROM "+table+" WHERE tenant_id=$1", tenant); err != nil {
					return err
				}
			}
			for _, statement := range []string{"DELETE FROM sessions WHERE user_id IN(SELECT id FROM users WHERE tenant_id=$1)", "DELETE FROM users WHERE tenant_id=$1", "DELETE FROM tenants WHERE id=$1"} {
				if _, err := tx.Exec(clean, statement, tenant); err != nil {
					return err
				}
			}
			return nil
		}))
	}()
	queue, err := bus.OpenNamespace(ctx, os.Getenv("SB_NATS_URL"), store.RandomID("it_live_"))
	require(t, err)
	defer queue.Close()
	require(t, queue.Ensure(ctx, 1, 16*1024*1024))
	defer func() {
		clean, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for _, stream := range []string{bus.Alerts, bus.Context, bus.Quarantine, bus.Indexed} {
			require(t, queue.JS.DeleteStream(clean, queue.StreamName(stream)))
		}
	}()
	es, err := store.OpenES(os.Getenv("SB_ES_URL"), "")
	require(t, err)
	defer func() {
		clean, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		res, err := es.API.Indices.Delete([]string{"sb-alerts-" + tenant + "-*", "sb-context-" + tenant + "-*"}, es.API.Indices.Delete.WithContext(clean))
		if err == nil {
			res.Body.Close()
		}
	}()
	dir := t.TempDir()
	ca := filepath.Join(dir, "pki")
	require(t, admin.DevPKI(ca))
	identity, err := admin.Provision(ctx, owner, tenant, "sensor_live", "真实链路探针", ca, filepath.Join(dir, "sensor"))
	require(t, err)
	privatePath, publicPath := filepath.Join(dir, "command.key"), filepath.Join(dir, "command.pub")
	require(t, control.GenerateKeys(privatePath, publicPath))
	accepted := make(chan notify.Message, 8)
	sink := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var message notify.Message
		if json.NewDecoder(io.LimitReader(r.Body, 65537)).Decode(&message) != nil || message.ID == "" || r.Header.Get("Idempotency-Key") != message.ID {
			w.WriteHeader(400)
			return
		}
		accepted <- message
		w.WriteHeader(204)
	}))
	defer sink.Close()
	provider, modelCalls := newGenerationProvider(t)
	defer provider.Close()
	triageProvider, triageCalls := newTriageProvider(t)
	defer triageProvider.Close()
	outboundCA := filepath.Join(dir, "outbound-ca.crt")
	certificates := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: sink.Certificate().Raw}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: provider.Certificate().Raw})...)
	certificates = append(certificates, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: triageProvider.Certificate().Raw})...)
	require(t, os.WriteFile(outboundCA, certificates, 0600))
	addresses := availableAddresses(t, 6)
	platformAddr, platformGRPC, agentAddr, ingestAddr, ingestGRPC, workerAddr := addresses[0], addresses[1], addresses[2], addresses[3], addresses[4], addresses[5]
	base := config.Config{Mode: "development", DatabaseURL: os.Getenv("SB_DATABASE_URL"), ESURL: os.Getenv("SB_ES_URL"), NATSURL: os.Getenv("SB_NATS_URL"), NATSNamespace: queue.Namespace, RedisURL: os.Getenv("SB_REDIS_URL"), Replicas: 1, StreamBytes: 16 * 1024 * 1024,
		TLSCA: filepath.Join(ca, "ca.crt"), TLSCert: filepath.Join(ca, "server.crt"), TLSKey: filepath.Join(ca, "server.key"), CredentialKey: store.Token(), OutboundCA: outboundCA, OutboundNetworks: "127.0.0.0/8"}
	platformConfig := base
	platformConfig.HTTPAddr, platformConfig.GRPCAddr, platformConfig.AllowedOrigin, platformConfig.CookieName = platformAddr, platformGRPC, "http://"+platformAddr, "live_platform_session"
	platformConfig.CommandSigningKey, platformConfig.ReplayBackend, platformConfig.ReplayDir, platformConfig.ReplayBytes = privatePath, "filesystem", filepath.Join(dir, "platform-samples"), 100*1024*1024
	ingestConfig := base
	ingestConfig.HTTPAddr, ingestConfig.GRPCAddr = ingestAddr, ingestGRPC
	workerConfig := base
	workerConfig.HTTPAddr = workerAddr
	evePath := filepath.Join(dir, "eve.json")
	require(t, os.WriteFile(evePath, nil, 0600))
	agentConfig := config.Config{Mode: "development", HTTPAddr: agentAddr, AllowedOrigin: "http://" + agentAddr, CookieName: "live_collector_session", TenantID: tenant, SensorID: identity.SensorID, RegistrationID: identity.RegistrationID, TLSCA: base.TLSCA,
		TLSCert: filepath.Join(dir, "sensor/agent.crt"), TLSKey: filepath.Join(dir, "sensor/agent.key"), CommandPublicKey: publicPath, LocalPassword: password, StatePath: filepath.Join(dir, "agent.db"), EVEPath: evePath,
		IngestAddr: ingestGRPC, PlatformAddr: platformGRPC, WALBytes: 8 * 1024 * 1024, HeartbeatInterval: time.Second, ReplayDir: filepath.Join(dir, "local-samples"), ReplayBytes: 100 * 1024 * 1024, ReplayRetentionDays: 180,
		SuricataBinary: os.Getenv("SB_TEST_SURICATA_BINARY"), SuricataConfig: os.Getenv("SB_TEST_SURICATA_CONFIG")}
	responseDevice := newGenericHTTPDevice(t, dir)
	agentConfig.ResponseConnectorsFile = responseDevice.file
	rules := `alert http any any -> any any (msg:"StarBeacon end-to-end capture"; flow:established,to_server; http.uri; content:"/starbeacon/validation"; sid:1000999; rev:1;)`
	if managed {
		rules += "\n" + `alert http any any -> any any (msg:"StarBeacon quality policy observation"; flow:established,to_server; http.uri; content:"/starbeacon/quality"; noalert; sid:1001000; rev:1;)`
		agentConfig.CaptureManaged, agentConfig.AllowRuleApply = true, true
		agentConfig.PacketCapture = true
		agentConfig.PacketRotateInterval = 3 * time.Second
		agentConfig.CaptureRotateBytes = 1024 * 1024
		agentConfig.SuricataRulesPath = filepath.Join(dir, "active.rules")
		require(t, os.WriteFile(agentConfig.SuricataRulesPath, []byte(rules), 0600))
		// 受控模板沿用实际引擎的辅助文件；生成工作配置不写回系统模板。
	}
	run, cancel := context.WithCancel(ctx)
	var running sync.WaitGroup
	failures := make(chan error, 4)
	defer func() {
		defer func() {
			if t.Failed() {
				for role, configuration := range map[string]config.Config{"platform": platformConfig, "ingest": ingestConfig, "worker": workerConfig, "agent": agentConfig} {
					logRoleFailure(t, role, filepath.Join(dir, role+".log"), configuration)
				}
			}
		}()
		cancel()
		done := make(chan struct{})
		go func() { running.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("角色未在关闭期限内退出")
		}
		// 超时退出的角色仍可能写入缓冲通道，因此不关闭生产者使用的通道。
		for {
			select {
			case err := <-failures:
				t.Error(err)
			default:
				return
			}
		}
	}()
	for role, configuration := range map[string]config.Config{"platform": platformConfig, "ingest": ingestConfig, "worker": workerConfig, "agent": agentConfig} {
		name := map[string]string{"platform": "starbeacon", "ingest": "starbeacon-ingest", "worker": "starbeacon-worker", "agent": "starbeacon-agent"}[role]
		command := exec.CommandContext(run, filepath.Join(filepath.Dir(os.Getenv("SB_TEST_MANAGEMENT_BINARY")), name))
		command.Env = roleEnvironment(configuration)
		command.Cancel = func() error { return command.Process.Signal(syscall.SIGTERM) }
		command.WaitDelay = 8 * time.Second
		output, err := os.OpenFile(filepath.Join(dir, role+".log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		require(t, err)
		command.Stdout, command.Stderr = output, output
		if err := command.Start(); err != nil {
			output.Close()
			t.Fatalf("%s 制品未启动：%v", role, err)
		}
		running.Go(func() {
			defer output.Close()
			if err := command.Wait(); err != nil && !(errors.Is(err, context.Canceled) && command.ProcessState != nil && command.ProcessState.ExitCode() == 0) {
				failures <- fmt.Errorf("%s 运行退出：%w", role, err)
			}
		})
	}
	for _, address := range []string{platformAddr, ingestAddr, workerAddr, agentAddr} {
		eventually(t, ctx, "角色健康就绪", func() bool {
			client := &http.Client{Timeout: time.Second}
			res, err := client.Get("http://" + address + "/readyz")
			if err != nil {
				return false
			}
			defer res.Body.Close()
			return res.StatusCode == 200
		})
	}
	newClient := func(origin, prefix string) *liveHTTP {
		jar, err := cookiejar.New(nil)
		require(t, err)
		return &liveHTTP{t: t, ctx: ctx, origin: origin, prefix: prefix, client: &http.Client{Jar: jar, Timeout: 5 * time.Second}}
	}
	platformHTTP := newClient(platformConfig.AllowedOrigin, "/api/v1")
	platformHTTP.login(username, password)
	collectorHTTP := newClient(agentConfig.AllowedOrigin, "/api/local/v1")
	collectorHTTP.login("admin", password)
	var capture agent.CaptureState
	var capturedInterface agent.NetworkInterface
	configureFromPlatform := func(settings agent.CaptureSettings) {
		var observed agent.CaptureState
		eventually(t, ctx, "平台观测实际采集配置和网卡", func() bool {
			var inventory struct {
				Items []model.Sensor `json:"items"`
			}
			platformHTTP.request("GET", "/sensors", "", nil, &inventory, 200)
			for _, row := range inventory.Items {
				var health model.HostHealth
				if row.ID != identity.SensorID || json.Unmarshal(row.Health, &health) != nil || json.Unmarshal(health.Capture, &observed) != nil || observed.Revision != capture.Revision || observed.SettingsSHA256 != capture.SettingsSHA256 || observed.ConfigSHA256 != capture.ConfigSHA256 || observed.AppliedRevision != capture.AppliedRevision || observed.Status != capture.Status || observed.Status == "pending" || observed.Status == "starting" {
					continue
				}
				for _, nic := range health.NetworkInterfaces {
					if nic.Name == capturedInterface.Name && nic.MAC == capturedInterface.MAC && nic.Up && !nic.Loopback {
						return true
					}
				}
			}
			return false
		})
		input := control.CaptureConfiguration{ExpectedRevision: &observed.Revision, ExpectedConfigSHA256: observed.ConfigSHA256, ExpectedSettingsSHA256: observed.SettingsSHA256, Settings: control.CaptureSettings(settings)}
		var accepted struct {
			ID string `json:"id"`
		}
		platformHTTP.request("POST", "/sensors/"+identity.SensorID+"/tasks", store.RandomID("live_capture_"), map[string]any{"kind": "capture.configure", "capture_configuration": input}, &accepted, 202)
		eventually(t, ctx, "远程采集配置任务的原生生效回读", func() bool {
			var tasks struct {
				Items []store.SensorTask `json:"items"`
			}
			platformHTTP.request("GET", "/tasks?sensor_id="+identity.SensorID, "", nil, &tasks, 200)
			for _, task := range tasks.Items {
				if task.ID == accepted.ID {
					var receipt control.Receipt
					if json.Unmarshal(task.Receipt, &receipt) == nil && receipt.State == "succeeded" && control.ValidateCaptureResult(input, receipt.Result) == nil {
						return true
					}
					if task.State == "failed" || task.State == "unknown" {
						t.Fatalf("采集配置任务未得到实际生效：%s / %s", task.State, receipt.Code)
					}
				}
			}
			return false
		})
		collectorHTTP.request("GET", "/capture-config", "", nil, &capture, 200)
	}
	if managed {
		defer func() {
			if t.Failed() {
				root := filepath.Join(filepath.Dir(agentConfig.StatePath), "capture")
				collectorHTTP.request("GET", "/capture-config", "", nil, &capture, 200)
				t.Logf("实际捕获：状态 %s，错误 %s，PID %d，期望/实际修订 %d/%d，暂存 %s/%s 字节，轮转 %s，等待排空 %t", capture.Status, capture.ErrorCode, capture.PID, capture.Revision, capture.AppliedRevision, capture.SpoolBytes, capture.SpoolBudget, capture.Rotations, capture.RotationPending)
				entries, err := os.ReadDir(root)
				if err == nil && len(entries) < 64 {
					for _, entry := range entries {
						if entry.Name() != "eve.json" && entry.Name() != "eve-rotation.json" && !strings.HasPrefix(entry.Name(), "eve-segment_") {
							continue
						}
						info, err := entry.Info()
						if err == nil {
							t.Logf("实际捕获文件 %s：%d 字节", entry.Name(), info.Size())
						}
					}
				}
				logCaptureEvidence(t, filepath.Join(root, "eve.json"))
			}
		}()
		collectorHTTP.client.Timeout = 30 * time.Second
		var interfaces struct {
			Items []agent.NetworkInterface `json:"items"`
		}
		collectorHTTP.request("GET", "/network/interfaces", "", nil, &interfaces, 200)
		for _, i := range interfaces.Items {
			if i.Name == "eth0" && i.Up && !i.Loopback {
				capturedInterface = i
			}
		}
		if capturedInterface.Name == "" {
			t.Fatal("真实捕获验收要求独立容器的 eth0 网卡")
		}
		promiscuous := false
		collectorHTTP.request("GET", "/capture-config", "", nil, &capture, 200)
		configureFromPlatform(agent.CaptureSettings{Interfaces: []string{capturedInterface.Name}, Threads: 1, BPFFilter: "tcp port 8088", Promiscuous: &promiscuous})
		if capture.Status != "running" || capture.AppliedRevision != capture.Revision || capture.PID == 0 || capture.ConfigSHA256 == "" || capture.AppliedSettings == nil {
			t.Fatal("实际网卡采集没有启动", capture)
		}
		eventually(t, ctx, "独立原包捕获已在实际网卡运行", func() bool {
			var health model.HostHealth
			collectorHTTP.request("GET", "/health", "", nil, &health, 200)
			var state agent.PacketArchiveState
			if json.Unmarshal(health.PacketArchive, &state) != nil || state.State != "capturing" {
				return false
			}
			for _, nic := range state.Interfaces {
				if nic.Interface == capturedInterface.Name && nic.State == "capturing" && nic.ID != "" {
					return true
				}
			}
			return false
		})
	}
	var platformHealth struct {
		Runtime hosthealth.Snapshot `json:"runtime"`
	}
	platformHTTP.request("GET", "/platform/health", "", nil, &platformHealth, 200)
	if platformHealth.Runtime.ObservedAt.IsZero() || platformHealth.Runtime.Goroutines < 1 || platformHealth.Runtime.HeapBytes == "" {
		t.Fatal("平台运行状态不是实际进程观测", platformHealth)
	}
	var sensors struct {
		Items []model.Sensor `json:"items"`
	}
	eventually(t, ctx, "心跳与隔离重放能力", func() bool {
		platformHTTP.request("GET", "/sensors", "", nil, &sensors, 200)
		if len(sensors.Items) != 1 || sensors.Items[0].LastSeen == nil {
			return false
		}
		var health model.HostHealth
		if json.Unmarshal(sensors.Items[0].Health, &health) != nil {
			return false
		}
		protocols := health.ProtocolCapabilities
		if protocols == nil || protocols.Validate() != nil || protocols.State != "observed" || protocols.EngineVersion != "8.0.7" || protocols.EngineSHA256 == "" || len(protocols.Protocols) < 35 || protocols.CaptureActive != managed {
			return false
		}
		if managed {
			var state agent.CaptureState
			if json.Unmarshal(health.Capture, &state) != nil || health.CaptureStatus != "running" || state.PID != capture.PID || state.ConfigSHA256 != capture.ConfigSHA256 || state.AppliedRevision != capture.Revision || state.CountersObservedAt == nil {
				return false
			}
			if protocols.Source != "managed_configuration" || protocols.ConfigSHA256 != state.ConfigSHA256 {
				return false
			}
			if state.Quality == nil || state.Quality.Source != "suricata_eve_stats" || state.Quality.EngineRunID == "" || state.Quality.ConfigSHA256 != state.ConfigSHA256 || state.Quality.State != "observed" || state.Quality.SampledAt == nil || state.Quality.IntervalStartedAt == nil {
				return false
			}
		} else if protocols.Source != "offline_template" {
			return false
		}
		return strings.Contains(strings.Join(health.TaskCapabilities, ","), "rules.replay") && health.Version != ""
	})
	enabled := true
	applicationDeployment := prepareNativeApplicationDeployment(t, ctx, platformHTTP, sensors.Items[0])
	channel := store.ChannelChange{ID: "channel_live", Name: "链路告警", Kind: "webhook", Enabled: &enabled, Severities: []string{"high", "medium", "low", "unknown"}, Connection: &notify.Config{Endpoint: sink.URL}}
	platformHTTP.request("POST", "/notifications/channels", "", channel, nil, 200)
	// 真实坏批次须被隔离，后续合法告警仍能完成通知。
	_, err = queue.JS.Publish(ctx, queue.Subject("sb.indexed"), []byte(`{"private":"must-not-enter-quarantine", "alerts":[`))
	require(t, err)
	pcap, err := testpcap.HTTP(false)
	require(t, err)
	packetPath, rulesPath, logDir, overlayPath := filepath.Join(dir, "traffic.pcap"), filepath.Join(dir, "live.rules"), filepath.Join(dir, "suricata-log"), filepath.Join(dir, "suricata-overlay.yaml")
	require(t, os.Mkdir(logDir, 0700))
	started := time.Now()
	if !managed {
		require(t, os.WriteFile(packetPath, pcap, 0600))
		require(t, os.WriteFile(rulesPath, []byte(rules), 0600))
		require(t, os.WriteFile(overlayPath, []byte("%YAML 1.1\n---\nrun-as: {}\nunix-command:\n  enabled: no\noutputs:\n  - eve-log:\n      enabled: yes\n      filetype: regular\n      filename: eve.json\n      ethernet: yes\n      types:\n        - alert\n        - http:\n            extended: yes\n        - flow\n        - stats:\n            totals: yes\n            threads: no\n"), 0600))
		detection, detectionStop := context.WithTimeout(ctx, 15*time.Second)
		command := exec.CommandContext(detection, agentConfig.SuricataBinary, "-c", agentConfig.SuricataConfig, "--include", overlayPath, "-r", packetPath, "-S", rulesPath, "-l", logDir, "--runmode", "single")
		command.Env = []string{"PATH=/usr/bin:/bin:/opt/homebrew/bin", "LANG=C", "LC_ALL=C"}
		log, err := command.CombinedOutput()
		detectionStop()
		if err != nil {
			t.Fatalf("原生捕获分析失败：%v；%s", err, log)
		}
		eve, err := os.ReadFile(filepath.Join(logDir, "eve.json"))
		require(t, err)
		if !bytes.Contains(eve, []byte("StarBeacon end-to-end capture")) {
			t.Fatal("实际 PCAP 未产生目标告警")
		}
		started = time.Now()
		file, err := os.OpenFile(evePath, os.O_APPEND|os.O_WRONLY, 0600)
		require(t, err)
		_, err = file.Write(eve)
		require(t, err)
		require(t, file.Close())
	} else {
		endpoint := os.Getenv("SB_TEST_CAPTURE_ENDPOINT")
		if endpoint == "" {
			t.Fatal("托管采集验收必须提供专属 Docker HTTP 流量端点")
		}
		traffic := &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, Timeout: 3 * time.Second}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"/starbeacon/validation", nil)
		require(t, err)
		request.Host = "replay.example"
		response, err := traffic.Do(request)
		require(t, err)
		_, err = io.Copy(io.Discard, io.LimitReader(response.Body, 65537))
		require(t, err)
		require(t, response.Body.Close())
		if response.StatusCode != 200 {
			t.Fatal("专属 HTTP 流量端点没有成功响应")
		}
	}
	var received notify.Message
	select {
	case received = <-accepted:
		if len(received.Alerts) != 1 || received.Test || received.Alerts[0].RuleID != "1000999" || received.TenantID != tenant {
			t.Fatal("通知摘要与原生告警不一致")
		}
	case <-time.After(20 * time.Second):
		for _, name := range []string{bus.Alerts, bus.Context, bus.Indexed, bus.Quarantine} {
			stream, err := queue.JS.Stream(ctx, queue.StreamName(name))
			if err != nil {
				t.Logf("流 %s 无法读取：%v", name, err)
				continue
			}
			info, err := stream.Info(ctx)
			if err == nil {
				t.Logf("流 %s：消息数 %d，消费端 %d", name, info.State.Msgs, info.State.Consumers)
			}
			if name == bus.Quarantine {
				message, err := stream.GetLastMsgForSubject(ctx, queue.Subject("sb.quarantine"))
				if err == nil {
					var diagnostic struct {
						Reason string `json:"reason"`
					}
					if json.Unmarshal(message.Data, &diagnostic) == nil {
						t.Log("最后隔离原因：", diagnostic.Reason)
					}
				}
			}
		}
		t.Fatal("真实捕获、上传、索引、通知链路未完成")
	}
	acceptedDuration := time.Since(started)
	var deliveries struct {
		Items []store.Delivery `json:"items"`
	}
	eventually(t, ctx, "真实渠道受理回执", func() bool {
		platformHTTP.request("GET", "/notifications/deliveries?state=accepted", "", nil, &deliveries, 200)
		return len(deliveries.Items) == 1 && deliveries.Items[0].ID == received.ID && deliveries.Items[0].Attempts == 1
	})
	if managed {
		verifyNativeQualityEvent(t, ctx, platformHTTP, es, identity, accepted, sink.URL)
	}
	quarantine, err := queue.JS.Stream(ctx, queue.StreamName(bus.Quarantine))
	require(t, err)
	stored, err := quarantine.GetLastMsgForSubject(ctx, queue.Subject("sb.quarantine"))
	require(t, err)
	if !bytes.Contains(stored.Data, []byte("notification_batch_invalid")) || bytes.Contains(stored.Data, []byte("must-not-enter-quarantine")) {
		t.Fatal("永久坏批次未隔离或隔离日志保留了未知正文")
	}
	index, err := contract.IndexName(tenant, "alerts", time.Now().UTC().Format("2006-01-02"))
	require(t, err)
	res, err := es.API.Indices.Refresh(es.API.Indices.Refresh.WithIndex(index), es.API.Indices.Refresh.WithContext(ctx))
	require(t, err)
	res.Body.Close()
	var alerts model.SearchResult
	query := model.SearchRequest{Start: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), End: time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC), Filter: `http.request.method == "GET" && http.request.uri contains "/starbeacon/validation"`}
	if managed {
		query.Start, query.End = started.Add(-time.Minute), time.Now().UTC().Add(time.Minute)
	}
	platformHTTP.request("POST", "/alerts/search", "", query, &alerts, 200)
	expectedMAC := "02:00:00:00:00:01"
	if managed {
		expectedMAC = capturedInterface.MAC
	}
	if alerts.Total != 1 || alerts.Items[0].Rule.ID != "1000999" || alerts.Items[0].Source.MAC != expectedMAC || alerts.Items[0].HTTP.Method != "GET" {
		t.Fatal("原生告警检索、MAC 或 HTTP 解析不一致", alerts)
	}
	verifyNativeApplicationAttribution(t, alerts.Items[0], applicationDeployment)
	contextIndex, err := contract.IndexName(tenant, "context", time.Now().UTC().Format("2006-01-02"))
	require(t, err)
	defer func() {
		if !t.Failed() {
			return
		}
		logCaptureEvidence(t, filepath.Join(logDir, "eve.json"))
		inspect, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		all, err := es.SearchTraffic(inspect, tenant, model.TrafficSearchRequest{SearchRequest: model.SearchRequest{Start: query.Start, End: query.End}})
		if err != nil {
			t.Log("流量诊断查询失败")
			return
		}
		t.Logf("窗口内真实协议记录 %d 条，告警流标识 %s", all.Total, alerts.Items[0].Suricata.FlowID)
		for _, row := range all.Items {
			t.Logf("实际记录 类型=%s 协议=%s 流=%s 探针=%s 方法=%s 路径=%s 时间=%s", row.Event.Kind, row.Network.Protocol, row.Suricata.FlowID, row.SensorID, row.HTTP.Method, row.HTTP.Path, row.Timestamp.UTC().Format(time.RFC3339Nano))
		}
	}()
	trafficQuery := model.TrafficSearchRequest{SearchRequest: query, EventKind: "http", SensorID: "sensor_live", FlowID: alerts.Items[0].Suricata.FlowID}
	var protocols traffic.Result
	eventually(t, ctx, "原生 HTTP 事务经平台流量检索读回", func() bool {
		response, err := es.API.Indices.Refresh(es.API.Indices.Refresh.WithIndex(contextIndex), es.API.Indices.Refresh.WithContext(ctx))
		if err != nil {
			return false
		}
		_ = response.Body.Close()
		platformHTTP.request("POST", "/traffic/search", "", trafficQuery, &protocols, 200)
		return protocols.Total > 0
	})
	verifyNativeApplicationAttribution(t, protocols.Items[0].Alert, applicationDeployment)
	if protocols.Total != 1 || protocols.Items[0].HTTP.Method != "GET" || protocols.Items[0].HTTP.Path != "/starbeacon/validation" || protocols.Items[0].TenantID != tenant || protocols.Items[0].Event.Kind != "http" || protocols.Items[0].Event.Original == "" || protocols.Items[0].Suricata.FlowID != alerts.Items[0].Suricata.FlowID {
		t.Fatal("实际 HTTP 事务、流来源与告警不能对应")
	}
	if managed {
		verifyNativePacketArchive(t, ctx, platformHTTP, identity, capturedInterface, started)
	}
	checkNativeFlow := func() {
		flowQuery := trafficQuery
		flowQuery.EventKind, flowQuery.Filter = "flow", ""
		eventually(t, ctx, "原生会话结束时间与双向计数实际索引", func() bool {
			response, err := es.API.Indices.Refresh(es.API.Indices.Refresh.WithIndex(contextIndex), es.API.Indices.Refresh.WithContext(ctx))
			if err != nil {
				return false
			}
			_ = response.Body.Close()
			platformHTTP.request("POST", "/traffic/search", "", flowQuery, &protocols, 200)
			return protocols.Total > 0
		})
		flow := protocols.Items[0].Details.Flow
		if flow == nil || flow.Start == nil || flow.End == nil || flow.End.Before(*flow.Start) {
			t.Fatal("原生会话时间缺失或倒置")
		}
		for _, value := range []string{flow.PacketsToServer, flow.PacketsToClient, flow.BytesToServer, flow.BytesToClient} {
			n, err := strconv.ParseUint(value, 10, 64)
			if err != nil || n == 0 {
				t.Fatal("真实完整 HTTP 会话缺少双向流量计数")
			}
		}
	}
	if !managed {
		checkNativeFlow()
	}
	var rulePackage store.RulePackage
	platformHTTP.request("POST", "/rule-packages", "", map[string]any{"id": "rules_live", "name": "链路规则", "text": rules, "expected_revision": 0}, &rulePackage, 201)
	var imported replay.Sample
	platformHTTP.request("POST", "/replay/samples", "", pcap, &imported, 201)
	var task struct {
		ID string `json:"id"`
	}
	platformHTTP.request("POST", "/sensors/sensor_live/tasks", "live-replay-idempotency", map[string]any{"kind": "rules.replay", "sample_id": imported.ID, "rule_mode": "package", "package_id": rulePackage.ID, "revision": rulePackage.Revision}, &task, 202)
	var tasks struct {
		Items []store.SensorTask `json:"items"`
	}
	var lastReplayState string
	eventually(t, ctx, "指定探针执行重放并回传原生结果", func() bool {
		platformHTTP.request("GET", "/tasks", "", nil, &tasks, 200)
		for _, item := range tasks.Items {
			if item.ID == task.ID && item.State != lastReplayState {
				lastReplayState = item.State
				t.Logf("指定探针重放状态 %s，原回执 %s", item.State, item.Receipt)
			}
			if item.ID == task.ID && (item.State == "failed" || item.State == "unknown" || item.State == "expired" || item.State == "cancelled") {
				t.Fatalf("指定探针重放未完成：状态 %s，原回执 %s", item.State, item.Receipt)
			}
			if item.ID == task.ID && item.State == "succeeded" {
				var receipt control.Receipt
				require(t, json.Unmarshal(item.Receipt, &receipt))
				var report struct {
					AlertCount       int64           `json:"alert_count"`
					PacketsProcessed string          `json:"packets_processed"`
					Metadata         replay.Metadata `json:"sample_metadata"`
				}
				require(t, json.Unmarshal(receipt.Result, &report))
				if report.Metadata.TCPHandshake.CompleteHandshakes != 1 || report.Metadata.TCPHandshake.IncompleteFlows != 0 || report.Metadata.TCPHandshake.Algorithm != "tcp-handshake-observation-v1" {
					t.Fatal("探针未回传实际握手观测", report)
				}
				if report.AlertCount != 1 || report.PacketsProcessed != "9" {
					t.Fatal("指定探针重放结果与原生样本不一致", report)
				}
				return true
			}
		}
		return false
	})
	var localImported replay.Sample
	collectorHTTP.request("POST", "/replay/samples", "", pcap, &localImported, 201)
	collectorHTTP.request("POST", "/replay/tasks", "local-replay-idempotency", map[string]any{"sample_id": localImported.ID, "rule_mode": "package", "rules": rules}, &task, 202)
	var localTask agent.LocalTaskSummary
	eventually(t, ctx, "采集器本地重放执行完成", func() bool {
		collectorHTTP.request("GET", "/tasks/"+task.ID, "", nil, &localTask, 200)
		if localTask.ID != task.ID || localTask.Origin != "local" || !localTask.RetainUntil.Equal(localTask.Receipt.StartedAt.AddDate(0, 0, 180)) {
			t.Fatal("本地重放档案或默认留存未绑定原任务", localTask)
		}
		return localTask.State == "succeeded" && localTask.Acknowledged && !localTask.RetentionProtected && bytes.Contains(localTask.Receipt.Result, []byte(`"alert_count":1`))
	})
	verifyNativeRuleGeneration(t, ctx, platformHTTP, collectorHTTP, provider.URL, modelCalls)
	triageJob := verifyNativeAlertTriage(t, ctx, platformHTTP, alerts.Items[0], triageProvider.URL, triageCalls)
	if !managed {
		verifyNativeContinuousDecision(t, ctx, platformHTTP, alerts.Items[0], identity.SensorID, responseDevice, triageProvider.URL)
	}
	verifyNativeResponse(t, ctx, platformHTTP, identity.SensorID, responseDevice)
	if !managed {
		// 离线 PCAP 的保留测试地址仅连接协议夹具，不封禁真实管理链路。
		verifyNativeDecisionResponse(t, ctx, platformHTTP, triageJob, identity.SensorID, responseDevice)
	}
	if managed {
		// 通过实际 HTTP 会话生成 EVE，不向采集文件注入记录来触发轮转。
		traffic := &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, Timeout: 3 * time.Second}
		sent := 0
		for ; sent < 4096; sent++ {
			request, err := http.NewRequestWithContext(ctx, "GET", os.Getenv("SB_TEST_CAPTURE_ENDPOINT")+"/starbeacon/rotation/"+strconv.Itoa(sent), nil)
			require(t, err)
			response, err := traffic.Do(request)
			require(t, err)
			_, err = io.Copy(io.Discard, io.LimitReader(response.Body, 65537))
			require(t, err)
			require(t, response.Body.Close())
			if response.StatusCode != 200 {
				t.Fatal("轮转流量没有实际响应")
			}
			if (sent+1)%128 == 0 {
				collectorHTTP.request("GET", "/capture-config", "", nil, &capture, 200)
				rotations, _ := strconv.ParseUint(capture.Rotations, 10, 64)
				info, err := os.Lstat(filepath.Join(filepath.Dir(agentConfig.StatePath), "capture", "eve.json"))
				require(t, err)
				// 阈值按引擎实际写入的字节核对，URL 长度不能当作 EVE 大小。
				if rotations > 0 || info.Size() >= agentConfig.CaptureRotateBytes {
					sent++
					break
				}
			}
		}
		eventually(t, ctx, "真实流量触发 EVE 轮转并持久排空", func() bool {
			collectorHTTP.request("GET", "/capture-config", "", nil, &capture, 200)
			rotations, err := strconv.ParseUint(capture.Rotations, 10, 64)
			return err == nil && rotations > 0 && !capture.RotationPending && capture.Status == "running"
		})
		contextIndex, err := contract.IndexName(tenant, "context", time.Now().UTC().Format("2006-01-02"))
		require(t, err)
		eventually(t, ctx, "轮转前后 HTTP 事件全部实际索引且没有重复", func() bool {
			response, err := es.API.Indices.Refresh(es.API.Indices.Refresh.WithIndex(contextIndex), es.API.Indices.Refresh.WithContext(ctx))
			if err != nil {
				return false
			}
			_ = response.Body.Close()
			response, err = es.API.Count(es.API.Count.WithIndex(contextIndex), es.API.Count.WithContext(ctx), es.API.Count.WithBody(strings.NewReader(`{"query":{"term":{"event.kind":"http"}}}`)))
			if err != nil {
				return false
			}
			defer response.Body.Close()
			if response.IsError() {
				return false
			}
			var count struct {
				Count int `json:"count"`
			}
			require(t, json.NewDecoder(io.LimitReader(response.Body, 65536)).Decode(&count))
			// 初始告警和 noalert 质量观测各有一次真实 HTTP 请求。
			if count.Count > sent+2 {
				t.Fatal("真实 HTTP 事件被重复索引", count.Count)
			}
			return count.Count == sent+2
		})
		// 总量一致仍可能掩盖一条丢失与一条重复；逐路径核对实际发送的事务。
		response, err := es.API.Search(es.API.Search.WithContext(ctx), es.API.Search.WithIndex(contextIndex), es.API.Search.WithBody(strings.NewReader(`{"size":4200,"_source":["http.path"],"query":{"term":{"event.kind":"http"}}}`)))
		require(t, err)
		var indexed struct {
			Hits struct {
				Hits []struct {
					Source struct {
						HTTP struct {
							Path string `json:"path"`
						} `json:"http"`
					} `json:"_source"`
				} `json:"hits"`
			} `json:"hits"`
		}
		if response.IsError() {
			response.Body.Close()
			t.Fatal("真实 HTTP 事务路径核对失败")
		}
		err = json.NewDecoder(io.LimitReader(response.Body, 4*1024*1024)).Decode(&indexed)
		require(t, response.Body.Close())
		require(t, err)
		expectedPaths := map[string]bool{"/starbeacon/validation": true, "/starbeacon/quality": true}
		for i := range sent {
			expectedPaths["/starbeacon/rotation/"+strconv.Itoa(i)] = true
		}
		for _, hit := range indexed.Hits.Hits {
			path := hit.Source.HTTP.Path
			if !expectedPaths[path] {
				t.Fatal("真实 HTTP 事务重复或出现未发送路径", path)
			}
			delete(expectedPaths, path)
		}
		if len(expectedPaths) != 0 {
			t.Fatal("真实 HTTP 事务路径缺失", expectedPaths)
		}
		previousPID, previousSHA := capture.PID, capture.ConfigSHA256
		bad := *capture.AppliedSettings
		bad.BPFFilter = "tcp port ???"
		collectorHTTP.configureCapture(bad, &capture)
		if capture.Status != "degraded" || capture.ErrorCode == "" || capture.PID != previousPID || capture.ConfigSHA256 != previousSHA || capture.AppliedRevision == capture.Revision {
			t.Fatal("失败配置没有保留原进程和实际配置", capture)
		}
		good := *capture.AppliedSettings
		collectorHTTP.configureCapture(good, &capture)
		if capture.Status != "running" || capture.Revision != capture.AppliedRevision {
			t.Fatal("配置恢复没有真实启动", capture)
		}
		eventually(t, ctx, "真实捕获计数", func() bool {
			collectorHTTP.request("GET", "/capture-config", "", nil, &capture, 200)
			_, observed := capture.Counters["capture.kernel_packets"]
			return observed
		})
		configureFromPlatform(agent.CaptureSettings{Interfaces: []string{}, Threads: 1, Promiscuous: good.Promiscuous})
		if capture.Status != "stopped" || capture.PID != 0 || capture.AppliedSettings == nil || len(capture.AppliedSettings.Interfaces) != 0 {
			t.Fatal("停止采集未得到实际回读", capture)
		}
		checkNativeFlow()
		t.Logf("真实 Docker 网卡 HTTP 流量 → Suricata → EVE → WAL → mTLS → NATS → ES → 通知受理 %.3fs；实际 MAC、配置失败保留、恢复、停止及双端离线重放通过", acceptedDuration.Seconds())
		t.Logf("轮转前后 %d 个实际 HTTP 事件均已索引，逐路径核对无缺失或重复；轮转与捕获计数来自实际检测进程", sent+2)
	} else {
		t.Logf("原生 PCAP 告警的 EVE → WAL → mTLS → NATS → ES → 通知受理耗时 %.3fs（单个离线样本）；主控及采集器登录、心跳、检索、坏批次隔离、平台指定探针重放和采集器本地重放通过", acceptedDuration.Seconds())
	}
}
