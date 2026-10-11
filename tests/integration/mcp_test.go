//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/admin"
	"github.com/kkx600/StarBeacon/internal/analytics"
	"github.com/kkx600/StarBeacon/internal/config"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/inventory"
	"github.com/kkx600/StarBeacon/internal/mcpaccess"
	"github.com/kkx600/StarBeacon/internal/mcpserver"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/searchfilter"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/traffic"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type mcpBearer struct {
	base  http.RoundTripper
	token string
}

func (b mcpBearer) RoundTrip(r *http.Request) (*http.Response, error) {
	copy := r.Clone(r.Context())
	copy.Header = r.Header.Clone()
	copy.Header.Set("Authorization", "Bearer "+b.token)
	return b.base.RoundTrip(copy)
}

// 受控授权方只验证 OAuth/MCP 协议；不等同真实企业授权方已接通。
func TestMCPRealDataTLSAuthorizationBudgetsRevocationAndIsolation(t *testing.T) {
	if os.Getenv("SB_MODE") != "development" || os.Getenv("SB_MIGRATION_DATABASE_URL") == "" || os.Getenv("SB_TEST_MANAGEMENT_BINARY") == "" {
		t.Skip("需要独立开发依赖")
	}
	ctx, stop := context.WithTimeout(context.Background(), 90*time.Second)
	defer stop()
	owner, err := store.Open(ctx, os.Getenv("SB_MIGRATION_DATABASE_URL"))
	require(t, err)
	defer owner.Close()
	db, err := store.Open(ctx, os.Getenv("SB_DATABASE_URL"))
	require(t, err)
	defer db.Close()
	require(t, db.VerifyRuntimeRole(ctx))
	es, err := store.OpenES(os.Getenv("SB_ES_URL"), "")
	require(t, err)
	tenants := []string{store.RandomID("it_mcp_a_"), store.RandomID("it_mcp_b_")}
	password := store.Token()
	for _, tenant := range tenants {
		require(t, admin.Bootstrap(ctx, owner, tenant, "MCP 接入验收", tenant, password, "admin"))
		defer func() {
			clean, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			require(t, owner.TenantTx(clean, tenant, func(tx pgx.Tx) error {
				for _, table := range []string{"mcp_auth_routes", "mcp_bindings", "inventory_history", "inventory_objects", "sensors", "operation_audits", "login_audits", "retention_policies"} {
					if _, err := tx.Exec(clean, "DELETE FROM "+table+" WHERE tenant_id=$1", tenant); err != nil {
						return err
					}
				}
				for _, query := range []string{"DELETE FROM sessions WHERE user_id IN(SELECT id FROM users WHERE tenant_id=$1)", "DELETE FROM users WHERE tenant_id=$1", "DELETE FROM tenants WHERE id=$1"} {
					if _, err := tx.Exec(clean, query, tenant); err != nil {
						return err
					}
				}
				return nil
			}))
		}()
	}
	require(t, admin.Bootstrap(ctx, owner, tenants[0], "MCP 接入验收", tenants[0]+"_viewer", password, "viewer"))
	start := time.Now().UTC().Truncate(time.Hour).Add(-time.Hour)
	window := analytics.Window{Start: start, End: start.Add(2 * time.Hour)}
	index, err := contract.IndexName(tenants[0], "alerts", start.Format("2006-01-02"))
	require(t, err)
	require(t, es.EnsureIndex(ctx, index, start.Format("2006-01-02")))
	contextIndex, err := contract.IndexName(tenants[0], "context", start.Format("2006-01-02"))
	require(t, err)
	require(t, es.EnsureIndex(ctx, contextIndex, start.Format("2006-01-02")))
	defer func() {
		clean, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		response, err := es.API.Indices.Delete([]string{index, contextIndex}, es.API.Indices.Delete.WithContext(clean))
		require(t, err)
		defer response.Body.Close()
		if response.IsError() {
			t.Error("自身索引清理失败")
		}
	}()
	alert := model.Alert{SchemaVersion: "alert.v1", TenantID: tenants[0], SensorID: "probe_owned", EventID: "event_owned", Timestamp: start.Add(time.Minute), ObservedAt: start.Add(time.Minute), ReceivedAt: start.Add(time.Minute), RawSHA256: control.Digest([]byte("owned-eve")), Severity: "high"}
	alert.Event.Kind = "alert"
	alert.Event.Dataset = "suricata.alert"
	alert.Event.Original = "private-eve-payload"
	alert.Rule.ID = "1001001"
	alert.Network.Protocol = "http"
	for _, err := range es.Bulk(ctx, index, []model.Alert{alert}) {
		require(t, err)
	}
	protocol := alert
	protocol.EventID, protocol.RegistrationID = "protocol_owned", "private-registration"
	protocol.Event.Kind, protocol.Event.Dataset = "tls", "suricata.eve"
	protocol.Event.Original = `{"tls":{"sni":"service.example","version":"TLS 1.3"},"flow":{"bytes_toserver":18446744073709551615,"bytes_toclient":0}}`
	protocol.RawSHA256 = control.Digest([]byte(protocol.Event.Original))
	protocol.Network.Transport, protocol.Network.Protocol = "tcp", "tls"
	protocol.Source = model.Endpoint{IP: "192.0.2.10", Port: 54321, MAC: "02:00:00:00:00:01"}
	protocol.Destination = model.Endpoint{IP: "198.51.100.20", Port: 443}
	protocol.Suricata.FlowID = "18446744073709551615"
	for _, err := range es.Bulk(ctx, contextIndex, []model.Alert{protocol}) {
		require(t, err)
	}
	refresh, err := es.API.Indices.Refresh(es.API.Indices.Refresh.WithIndex(index, contextIndex), es.API.Indices.Refresh.WithContext(ctx))
	require(t, err)
	require(t, refresh.Body.Close())
	var revoked atomic.Bool
	var issuer *httptest.Server
	platformAddress := availableAddress(t)
	upstream, err := url.Parse("http://" + platformAddress)
	require(t, err)
	endpoint := httptest.NewTLSServer(httputil.NewSingleHostReverseProxy(upstream))
	defer endpoint.Close()
	issuer = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		client, key, ok := r.BasicAuth()
		if !ok || client != "starbeacon-resource" || key != "owned-introspection-secret" || r.Method != "POST" || r.ParseForm() != nil {
			w.WriteHeader(401)
			return
		}
		token := r.PostForm.Get("token")
		subject, app := "owned-subject", "owned-agent"
		if token == "token-b" {
			subject, app = "other-subject", "other-agent"
		}
		if token == "token-other-app" {
			app = "unregistered-agent"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"active": !revoked.Load(), "iss": issuer.URL, "sub": subject, "client_id": app, "aud": endpoint.URL + "/mcp", "scope": "alerts:read assets:read sensors:read traffic:read", "exp": time.Now().Add(time.Hour).Unix()})
	}))
	defer issuer.Close()
	// 原生平台只获得运行账号和受限内省凭据，TLS 网关代理实际二进制入口。
	directory := t.TempDir()
	pki := filepath.Join(directory, "pki")
	require(t, admin.DevPKI(pki))
	caPath := filepath.Join(directory, "oauth-ca.crt")
	require(t, os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.Certificate().Raw}), 0600))
	redisEndpoint, err := url.Parse(os.Getenv("SB_REDIS_URL"))
	require(t, err)
	redisEndpoint.Path = "/11"
	configuration := config.Config{
		Mode: "development", HTTPAddr: platformAddress, GRPCAddr: availableAddress(t),
		DatabaseURL: os.Getenv("SB_DATABASE_URL"), ESURL: os.Getenv("SB_ES_URL"), RedisURL: redisEndpoint.String(),
		TLSCA: filepath.Join(pki, "ca.crt"), TLSCert: filepath.Join(pki, "server.crt"), TLSKey: filepath.Join(pki, "server.key"),
		AllowedOrigin: endpoint.URL, OutboundCA: caPath, OutboundNetworks: "127.0.0.0/8",
		ReplayDir: filepath.Join(directory, "samples"),
		MCPIssuer: issuer.URL, MCPIntrospectionURL: issuer.URL + "/introspect", MCPClientID: "starbeacon-resource", MCPClientSecret: "owned-introspection-secret",
	}
	run, cancel := context.WithCancel(ctx)
	command := exec.CommandContext(run, filepath.Join(filepath.Dir(os.Getenv("SB_TEST_MANAGEMENT_BINARY")), "starbeacon"))
	command.Env = roleEnvironment(configuration)
	command.Cancel = func() error { return command.Process.Signal(syscall.SIGTERM) }
	command.WaitDelay = 8 * time.Second
	output, err := os.OpenFile(filepath.Join(directory, "platform.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	require(t, err)
	command.Stdout, command.Stderr = output, output
	if err := command.Start(); err != nil {
		output.Close()
		t.Fatalf("平台制品未启动：%v", err)
	}
	finished := make(chan error, 1)
	go func() { defer output.Close(); finished <- command.Wait() }()
	defer func() {
		cancel()
		select {
		case err := <-finished:
			if err != nil && !(errors.Is(err, context.Canceled) && command.ProcessState != nil && command.ProcessState.ExitCode() == 0) {
				t.Error(fmt.Errorf("平台原生进程退出：%w", err))
				log, readErr := os.Open(filepath.Join(directory, "platform.log"))
				if readErr == nil {
					defer log.Close()
					data, _ := io.ReadAll(io.LimitReader(log, 65536))
					message := string(data)
					for _, secret := range []string{configuration.DatabaseURL, configuration.RedisURL, configuration.MCPClientSecret} {
						message = strings.ReplaceAll(message, secret, "[凭据隐藏]")
					}
					t.Logf("平台进程诊断：%s", message)
				}
			}
		case <-time.After(10 * time.Second):
			t.Error("平台未在关闭期限内退出")
		}
	}()
	healthClient := *endpoint.Client()
	healthClient.Timeout = time.Second
	eventually(t, ctx, "原生 MCP 平台就绪", func() bool {
		response, err := healthClient.Get(endpoint.URL + "/readyz")
		if err != nil {
			return false
		}
		defer response.Body.Close()
		return response.StatusCode == http.StatusOK
	})
	metadataResponse, err := endpoint.Client().Get(endpoint.URL + "/.well-known/oauth-protected-resource/mcp")
	require(t, err)
	metadataBytes, err := io.ReadAll(io.LimitReader(metadataResponse.Body, 65537))
	require(t, err)
	require(t, metadataResponse.Body.Close())
	var metadata struct {
		Resource string   `json:"resource"`
		Issuers  []string `json:"authorization_servers"`
		Scopes   []string `json:"scopes_supported"`
	}
	require(t, json.Unmarshal(metadataBytes, &metadata))
	if metadataResponse.StatusCode != http.StatusOK || metadata.Resource != endpoint.URL+"/mcp" || len(metadata.Issuers) != 1 || metadata.Issuers[0] != issuer.URL || len(metadata.Scopes) != 4 || strings.Contains(string(metadataBytes), configuration.MCPClientSecret) {
		t.Fatal("原生入口的公开资源发现不符合接入契约")
	}
	unauthenticated, err := http.NewRequestWithContext(ctx, "POST", endpoint.URL+"/mcp", strings.NewReader(`{}`))
	require(t, err)
	unauthenticated.Header.Set("Content-Type", "application/json")
	response, err := endpoint.Client().Do(unauthenticated)
	require(t, err)
	require(t, response.Body.Close())
	if response.StatusCode != http.StatusUnauthorized || !strings.Contains(response.Header.Get("WWW-Authenticate"), endpoint.URL+"/.well-known/oauth-protected-resource/mcp") {
		t.Fatal("原生 MCP 入口没有拒绝未授权请求或提供资源发现")
	}
	login := func(name string) (*liveHTTP, model.Principal) {
		copy := *endpoint.Client()
		client := &copy
		jar, err := cookiejar.New(nil)
		require(t, err)
		client.Jar = jar
		client.Timeout = 12 * time.Second
		http := &liveHTTP{t: t, ctx: ctx, client: client, origin: endpoint.URL, prefix: "/api/v1"}
		http.login(name, password)
		var u model.Principal
		http.request("GET", "/auth/me", "", nil, &u, 200)
		return http, u
	}
	a, u := login(tenants[0])
	b, other := login(tenants[1])
	viewer, _ := login(tenants[0] + "_viewer")
	viewer.request("GET", "/mcp", "", nil, nil, 403)
	viewer.request("GET", "/mcp/bindings", "", nil, nil, 403)
	var info mcpserver.Info
	a.request("GET", "/mcp", "", nil, &info, 200)
	if !info.Enabled || len(info.Tools) != 9 {
		t.Fatal("公开接入信息不正确", info)
	}
	change := mcpaccess.Change{ID: "mcp_owned", Name: "调查助手", Subject: "owned-subject", OAuthClientID: "owned-agent", Scopes: []string{"alerts:read", "assets:read", "sensors:read", "traffic:read"}, Enabled: true, ExpiresAt: time.Now().Add(180 * 24 * time.Hour).UTC(), RequestsPerMinute: 2}
	var binding mcpaccess.Binding
	a.request("POST", "/mcp/bindings", "", change, &binding, 200)
	if binding.Revision != 1 || binding.OwnerID != u.ID {
		t.Fatal("服务身份归属不正确", binding)
	}
	csrf := a.csrf
	a.csrf = ""
	a.request("POST", "/mcp/bindings", "", change, nil, 403)
	a.csrf = csrf
	viewer.request("POST", "/mcp/bindings", "", change, nil, 403)
	a.request("POST", "/mcp/bindings", "", change, nil, 409)
	b.request("POST", "/mcp/bindings", "", change, nil, 409)
	changeB := change
	changeB.ID = "mcp_other"
	changeB.Subject = "other-subject"
	changeB.OAuthClientID = "other-agent"
	changeB.RequestsPerMinute = 60
	b.request("POST", "/mcp/bindings", "", changeB, nil, 200)
	var list struct {
		Items []mcpaccess.Binding `json:"items"`
	}
	b.request("GET", "/mcp/bindings", "", nil, &list, 200)
	if len(list.Items) != 1 || list.Items[0].ID != changeB.ID {
		t.Fatal("身份列表跨租户")
	}
	_, err = db.SaveMCPBinding(ctx, model.Principal{ID: u.ID, TenantID: u.TenantID, Role: "viewer"}, issuer.URL, change, "test")
	if !errors.Is(err, mcpaccess.ErrDenied) {
		t.Fatal("存储允许只读角色登记身份")
	}
	_, err = db.MCPIdentity(ctx, issuer.URL, change.Subject, "unregistered-agent")
	if !errors.Is(err, mcpaccess.ErrDenied) {
		t.Fatal("主体的其他应用继承权限")
	}
	asset, _ := json.Marshal(inventory.Asset{Name: "受控业务资产", NetworkDomain: "lab", Criticality: "high", Active: true, Interfaces: []inventory.Interface{{Name: "eth0", MAC: "02:00:00:00:00:01", IPs: []string{"192.0.2.10"}}}})
	_, err = db.SaveInventory(ctx, u, "assets", "asset_owned", 0, asset, "owned-request")
	require(t, err)
	connect := func(token string) *mcp.ClientSession {
		copy := *endpoint.Client()
		client := &copy
		client.Transport = mcpBearer{client.Transport, token}
		session, err := mcp.NewClient(&mcp.Implementation{Name: "owned-agent", Version: "test"}, nil).Connect(ctx, &mcp.StreamableClientTransport{Endpoint: endpoint.URL + "/mcp", HTTPClient: client, DisableStandaloneSSE: true}, nil)
		require(t, err)
		t.Cleanup(func() { _ = session.Close() })
		return session
	}
	session, foreign := connect("token-a"), connect("token-b")
	call := func(session *mcp.ClientSession, name string, args any, failed bool) *mcp.CallToolResult {
		t.Helper()
		result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
		require(t, err)
		if result.IsError != failed {
			raw, _ := json.Marshal(result)
			t.Fatalf("工具 %s 状态不符合预期：%s", name, raw)
		}
		return result
	}
	result := call(session, "alerts.search", window, false)
	raw, _ := json.Marshal(result.StructuredContent)
	if !strings.Contains(string(raw), "event_owned") || strings.Contains(string(raw), "private-eve-payload") || !strings.Contains(string(raw), `"total":"1"`) {
		t.Fatal("告警工具没有遵守精度或证据权限", string(raw))
	}
	call(session, "assets.get", map[string]string{"id": "asset_owned"}, false)
	call(session, "sensors.list", map[string]int{"limit": 100}, true)
	call(foreign, "assets.get", map[string]string{"id": "asset_owned"}, true)
	result = call(foreign, "alerts.search", window, false)
	raw, _ = json.Marshal(result.StructuredContent)
	if strings.Contains(string(raw), "event_owned") || !strings.Contains(string(raw), `"total":"0"`) {
		t.Fatal("告警工具跨租户")
	}
	change.ExpectedRevision = 1
	change.RequestsPerMinute = 60
	a.request("POST", "/mcp/bindings", "", change, &binding, 200)
	call(session, "alerts.aggregate", window, false)
	call(session, "sensors.list", map[string]int{"limit": 100}, false)
	query := map[string]any{"start": window.Start, "end": window.End, "event_kind": "tls", "filter": "tcp.port == 443 and ip.src == 192.0.2.10"}
	result = call(session, "traffic.search", query, false)
	raw, _ = json.Marshal(result.StructuredContent)
	if !strings.Contains(string(raw), "protocol_owned") || !strings.Contains(string(raw), "service.example") || !strings.Contains(string(raw), "18446744073709551615") || !strings.Contains(string(raw), `"total":"1"`) || strings.Contains(string(raw), "private-registration") || strings.Contains(string(raw), `"original":"{`) {
		t.Fatal("原生协议查询未遵守元数据、精度和载荷权限", string(raw))
	}
	result = call(foreign, "traffic.search", query, false)
	raw, _ = json.Marshal(result.StructuredContent)
	if strings.Contains(string(raw), "protocol_owned") || !strings.Contains(string(raw), `"total":"0"`) {
		t.Fatal("协议检索跨租户", string(raw))
	}
	result = call(session, "traffic.fields", map[string]any{}, false)
	raw, _ = json.Marshal(result.StructuredContent)
	if !strings.Contains(string(raw), `"dataset":"context"`) || !strings.Contains(string(raw), "tcp.port") || strings.Contains(string(raw), `"name":"severity"`) || strings.Contains(string(raw), `"name":"rule.id"`) {
		t.Fatal("原生协议目录与校验器不一致", string(raw))
	}
	for _, input := range []struct {
		tool, expression string
		valid            bool
	}{{"traffic.filter.validate", "tcp.port in {80 443}", true}, {"traffic.filter.validate", "tcp or (suricata.sid == 1)", false}, {"alerts.filter.validate", "suricata.sid == 1", true}, {"alerts.filter.validate", "ip.src ==", false}} {
		result = call(session, input.tool, mcpserver.FilterInput{Filter: input.expression}, false)
		raw, _ = json.Marshal(result.StructuredContent)
		var decoded struct {
			Data mcpserver.FilterValidation `json:"data"`
		}
		require(t, json.Unmarshal(raw, &decoded))
		if decoded.Data.Valid != input.valid || decoded.Data.Version != searchfilter.Version || (!input.valid && (decoded.Data.Error == nil || decoded.Data.Error.Line < 1 || decoded.Data.Error.Column < 1)) {
			t.Fatal("原生表达式校验没有返回实际有效性和错误位置", string(raw))
		}
	}
	call(session, "alerts.fields", map[string]any{}, false)
	call(session, "traffic.search", map[string]any{"start": window.Start, "end": window.End, "filter": "rule.id == 1"}, true)
	var browserTraffic traffic.Result
	viewer.request("POST", "/traffic/search", "", query, &browserTraffic, 200)
	if len(browserTraffic.Items) != 1 || browserTraffic.Items[0].Details.TLS == nil || browserTraffic.Items[0].Details.TLS.SNI != "service.example" || browserTraffic.Items[0].Event.Original != "" {
		t.Fatal("浏览器与 MCP 的协议元数据契约不一致", browserTraffic)
	}
	viewer.request("POST", "/traffic/search", "", map[string]any{"start": window.Start, "end": window.End, "filter": "severity == high"}, nil, 400)
	change.ExpectedRevision = 1
	a.request("POST", "/mcp/bindings", "", change, nil, 409)
	change.ExpectedRevision = 2
	change.Enabled = false
	a.request("POST", "/mcp/bindings", "", change, &binding, 200)
	if _, err = session.CallTool(ctx, &mcp.CallToolParams{Name: "alerts.search", Arguments: window}); err == nil {
		t.Fatal("停用身份的既有客户端仍能查询")
	}
	change.ExpectedRevision = 3
	change.Enabled = true
	change.Scopes = []string{"assets:read"}
	a.request("POST", "/mcp/bindings", "", change, &binding, 200)
	// SDK 在 401 后关闭传输，重新启用身份须建立新的客户端连接。
	session = connect("token-a")
	call(session, "alerts.search", window, true)
	call(session, "traffic.search", query, true)
	call(session, "traffic.fields", map[string]any{}, true)
	call(session, "traffic.filter.validate", mcpserver.FilterInput{Filter: "tcp"}, true)
	call(session, "assets.get", map[string]string{"id": "asset_owned"}, false)
	require(t, owner.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "UPDATE users SET active=false WHERE id=$1", u.ID)
		return err
	}))
	if _, err = session.CallTool(ctx, &mcp.CallToolParams{Name: "assets.get", Arguments: map[string]string{"id": "asset_owned"}}); err == nil {
		t.Fatal("所属账号停用仍能查询")
	}
	revoked.Store(true)
	if _, err = foreign.CallTool(ctx, &mcp.CallToolParams{Name: "alerts.search", Arguments: window}); err == nil {
		t.Fatal("授权方撤销令牌仍能查询")
	}
	_, err = db.MCPIdentity(ctx, issuer.URL, changeB.Subject, changeB.OAuthClientID)
	require(t, err)
	audits, err := db.Audits(ctx, u.TenantID, "operations", store.AuditQuery{Start: time.Now().Add(-time.Hour), End: time.Now().Add(time.Minute), Limit: 100})
	require(t, err)
	found, foundTraffic := false, false
	for _, audit := range audits.Items {
		if audit.Action == "mcp.tool.alerts.search.succeeded" && audit.ObjectID == change.ID && audit.RequestID != "" {
			found = true
		}
		if audit.Action == "mcp.tool.traffic.search.succeeded" && audit.ObjectID == change.ID && audit.RequestID != "" {
			foundTraffic = true
		}
	}
	if !found || !foundTraffic {
		t.Fatal("真实工具成功查询未写入租户审计")
	}
	b.request("DELETE", "/mcp/bindings/"+change.ID, "", map[string]int64{"expected_revision": 4}, nil, 409)
	viewer.request("DELETE", "/mcp/bindings/"+change.ID, "", map[string]int64{"expected_revision": 4}, nil, 403)
	b.request("DELETE", "/mcp/bindings/"+changeB.ID, "", map[string]int64{"expected_revision": 2}, nil, 409)
	b.request("DELETE", "/mcp/bindings/"+changeB.ID, "", map[string]int64{"expected_revision": 1}, nil, 200)
	_, err = db.MCPIdentity(ctx, issuer.URL, changeB.Subject, changeB.OAuthClientID)
	if !errors.Is(err, mcpaccess.ErrDenied) {
		t.Fatal("删除身份仍能认证")
	}
	// RLS 不依赖 WHERE 子句裁剪：同一事务看不到另一租户的授权配置。
	require(t, db.TenantTx(ctx, other.TenantID, func(tx pgx.Tx) error {
		var count int
		err := tx.QueryRow(ctx, "SELECT count(*) FROM mcp_bindings WHERE id=$1", change.ID).Scan(&count)
		if count != 0 {
			t.Fatal("授权配置绕过强制 RLS")
		}
		return err
	}))
}
