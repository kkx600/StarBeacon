//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/admin"
	"github.com/kkx600/StarBeacon/internal/assistant"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/llm"
	"github.com/kkx600/StarBeacon/internal/mcpaccess"
	"github.com/kkx600/StarBeacon/internal/mcpserver"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/notify"
	"github.com/kkx600/StarBeacon/internal/platform"
	"github.com/kkx600/StarBeacon/internal/probepki"
	"github.com/kkx600/StarBeacon/internal/retention"
	"github.com/kkx600/StarBeacon/internal/secrets"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/transport"
)

func authenticatedFaultHTTP(t *testing.T, ctx context.Context, authDB *store.Postgres, api *platform.API, username, password string) *liveHTTP {
	t.Helper()
	auth := httpapi.NewAuth(authDB, nil, "", "it_failure_session", false)
	api.Auth = auth
	server := httptest.NewServer(httpapi.Middleware(api.Handler()))
	t.Cleanup(server.Close)
	auth.Origin = server.URL
	jar, err := cookiejar.New(nil)
	require(t, err)
	client := &liveHTTP{t: t, ctx: ctx, client: &http.Client{Jar: jar, Timeout: 5 * time.Second}, origin: server.URL, prefix: "/api/v1"}
	client.login(username, password)
	return client
}

func TestPlatformHTTPDependencyFailuresNeverBecomeEmptySuccess(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	f := newIsolatedDatabase(t, ctx)
	tenant, password := store.RandomID("it_http_failure_"), store.Token()
	require(t, admin.Bootstrap(ctx, f.Owner, tenant, "接口失败验收", tenant, password, "admin"))
	broken, err := store.Open(ctx, f.RuntimeDSN)
	require(t, err)
	broken.Close()
	_, signer, err := ed25519.GenerateKey(rand.Reader)
	require(t, err)
	vault, err := secrets.New(store.Token())
	require(t, err)
	api := &platform.API{DB: broken, Authority: newProbeTestAuthority(t), Signer: signer, Vault: vault, MCP: &mcpserver.Server{Info: mcpserver.Info{Issuer: "https://issuer.example.com"}}}
	client := authenticatedFaultHTTP(t, ctx, f.Runtime, api, tenant, password)
	for _, path := range []string{
		"/sensors", "/tasks", "/rule-packages", "/rule-packages/rules_owned/1", "/replay/samples",
		"/inventory/assets", "/inventory/assets/asset_owned", "/inventory/assets/asset_owned/history",
		"/notifications/channels", "/notifications/deliveries", "/models/providers",
		"/analysis/jobs", "/analysis/jobs/job_owned", "/analysis/jobs/job_owned/report", "/analysis/threads", "/analysis/threads/thread_owned",
		"/retention-policies", "/mcp/bindings", "/audits/operations", "/audits/logins",
		"/sensor-enrollments", "/sensors/sensor_owned/certificates",
	} {
		t.Run("GET"+path, func(t *testing.T) {
			requestClient := *client
			requestClient.t = t
			requestClient.request("GET", path, "", nil, nil, 503)
		})
	}
	enabled := true
	modelChange := store.ModelChange{ID: "model_owned", ReplaceKey: true, Config: llm.Config{Name: "模型提供方", Kind: "openai_responses", BaseURL: "https://models.example.com/v1", Model: "owned", Enabled: true, APIKey: "owned-key", MaxOutputTokens: 256, TimeoutSeconds: 5, DailyRequests: 1000}}
	connection := notify.Config{Name: "通知渠道", Kind: "webhook", Enabled: true, Endpoint: "https://notice.example.com/ingest", Severities: []string{"high"}}
	channelChange := store.ChannelChange{ID: "channel_owned", Name: connection.Name, Kind: connection.Kind, Enabled: &enabled, Severities: connection.Severities, Connection: &connection}
	candidate := retention.Candidate{Category: "alerts", Days: 90, ExpectedRevision: 1, ApplyMode: "future"}
	binding := mcpaccess.Change{ID: "binding_owned", Name: "分析服务", Subject: "subject_owned", OAuthClientID: "client_owned", Scopes: []string{"alerts:read"}, Enabled: true, ExpiresAt: time.Now().UTC().Add(time.Hour), RequestsPerMinute: 60}
	probeID := transport.SensorIdentity{TenantID: tenant, SensorID: "sensor_owned", RegistrationID: "registration_owned"}
	token, err := probepki.NewCredential(probeID, "enrollment_owned")
	require(t, err)
	type request struct {
		method, path string
		input        any
	}
	for _, tc := range []request{
		{"PATCH", "/sensors/sensor_owned", map[string]bool{"active": true}},
		{"POST", "/sensors/sensor_owned/tasks", map[string]string{"kind": "diagnostics"}},
		{"POST", "/tasks/task_owned/cancel", map[string]any{}},
		{"POST", "/rule-packages", map[string]any{"id": "rules_owned", "name": "检测规则", "text": "alert tcp any any -> any any (sid:1000001;)", "expected_revision": 0}},
		{"POST", "/inventory/groups", map[string]any{"data": map[string]any{"name": "资产组", "active": true}}},
		{"POST", "/notifications/channels", channelChange},
		{"POST", "/notifications/channels/channel_owned/test", map[string]any{}},
		{"POST", "/notifications/deliveries/delivery_owned/retry", map[string]any{"expected_version": 1, "acknowledge_duplicates": true}},
		{"POST", "/models/providers", modelChange},
		{"POST", "/models/providers/model_owned/test", map[string]any{"expected_revision": 1}},
		{"POST", "/analysis/jobs", assistant.Request{Kind: "daily", Period: time.Now().UTC().AddDate(0, 0, -1).Format("2006-01-02"), Timezone: "UTC"}},
		{"POST", "/analysis/jobs/job_owned/cancel", map[string]any{}},
		{"POST", "/retention-policies/preview", candidate},
		{"PUT", "/retention-policies/alerts", retention.Change{PreviewID: "preview_owned", Candidate: candidate}},
		{"POST", "/mcp/bindings", binding},
		{"DELETE", "/mcp/bindings/binding_owned", map[string]any{"expected_revision": 1}},
		{"POST", "/alerts/search", model.SearchRequest{Start: time.Now().UTC().Add(-time.Hour), End: time.Now().UTC()}},
		{"POST", "/sensor-enrollments", probepki.EnrollmentInput{Token: token, Name: "证书故障验收", TTLSeconds: 3600}},
		{"POST", "/sensor-enrollments/enrollment_owned/revoke", map[string]any{}},
		{"POST", "/sensor-certificates/certificate_owned/revoke", map[string]any{}},
	} {
		t.Run(tc.method+tc.path, func(t *testing.T) {
			requestClient := *client
			requestClient.t = t
			requestClient.request(tc.method, tc.path, "failure_owned_key", tc.input, nil, 503)
		})
	}
	csr, _, err := probepki.NewCSR(probeID)
	require(t, err)
	// 设备交换不继承浏览器会话；数据库不可用时也不能把 CA 响应当作登记成功。
	server := httptest.NewServer(httpapi.Middleware(api.Handler()))
	t.Cleanup(server.Close)
	body, err := json.Marshal(probepki.Exchange{Token: token, CSR: csr})
	require(t, err)
	response, err := http.Post(server.URL+"/api/v1/sensor-enrollments/exchange", "application/json", bytes.NewReader(body))
	require(t, err)
	response.Body.Close()
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatal("设备交换在存储故障时未明确失败", response.StatusCode)
	}
	before := ownedBusinessSnapshot(t, ctx, f.Owner, tenant)
	// 业务依赖恢复后读回真实空数据；失败请求没有持久化半成品或审计成功记录。
	healthy := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime, Vault: vault}, tenant, password)
	for _, path := range []string{"/sensors", "/tasks", "/inventory/assets", "/notifications/channels", "/models/providers", "/analysis/jobs", "/mcp/bindings"} {
		healthy.request("GET", path, "", nil, nil, 200)
	}
	if before != ownedBusinessSnapshot(t, ctx, f.Owner, tenant) {
		t.Fatal("失败请求或恢复读操作改写了业务状态")
	}
}

func TestPlatformHTTPInvalidInputsAndUnavailableCapabilities(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	f := newIsolatedDatabase(t, ctx)
	tenant, password := store.RandomID("it_invalid_http_"), store.Token()
	require(t, admin.Bootstrap(ctx, f.Owner, tenant, "参数边界验收", tenant, password, "admin"))
	_, signer, err := ed25519.GenerateKey(rand.Reader)
	require(t, err)
	api := &platform.API{DB: f.Runtime, Signer: signer, MCP: &mcpserver.Server{Info: mcpserver.Info{Issuer: "https://issuer.example.com"}}}
	client := authenticatedFaultHTTP(t, ctx, f.Runtime, api, tenant, password)
	for _, path := range []string{
		"/inventory/unsupported/id_owned", "/inventory/assets/id.invalid", "/inventory/assets/id.invalid/history", "/inventory/unsupported/id_owned/history",
		"/inventory/assets?keyword=%00", "/inventory/assets?keyword=%0A",
		"/analysis/jobs?limit=wrong", "/analysis/jobs?limit=0", "/analysis/jobs?limit=51", "/analysis/jobs?group=unsupported", "/analysis/jobs?before=id.invalid",
		"/analysis/threads?before=id.invalid", "/analysis/threads/id.invalid", "/analysis/threads/thread_owned?before=id.invalid",
		"/notifications/deliveries?state=unsupported", "/notifications/deliveries?cursor=broken",
		"/audits/operations?start=wrong", "/audits/operations?end=wrong", "/audits/operations?limit=wrong", "/audits/logins?success=unsupported",
	} {
		t.Run("GET"+path, func(t *testing.T) { client.request("GET", path, "", nil, nil, 400) })
	}
	type bad struct {
		method, path, key string
		body              any
		status            int
	}
	for _, tc := range []bad{
		{"POST", "/inventory/groups", "", map[string]any{"unknown": true}, 400},
		{"POST", "/inventory/groups", "", map[string]any{"id": "id.invalid", "data": map[string]any{"name": "资产组", "active": true}}, 400},
		{"POST", "/inventory/groups", "", map[string]any{"data": map[string]any{"name": "资产组", "active": true}, "expected_revision": -1}, 400},
		{"POST", "/inventory/assets", "", map[string]any{"data": map[string]any{"name": "主机", "group_id": "id.invalid", "network_domain": "office", "criticality": "high", "active": true, "interfaces": []any{map[string]any{"name": "eth0", "ips": []string{"192.0.2.1"}}}}}, 400},
		{"POST", "/notifications/channels", "", map[string]any{"unknown": true}, 400},
		{"POST", "/models/providers/model_owned/test", "owned_key", map[string]any{"unknown": true}, 400},
		{"POST", "/models/providers/model_owned/test", "", map[string]any{"expected_revision": 1}, 409},
		{"POST", "/models/providers", "", map[string]any{"id": "model_owned", "replace_key": true, "config": map[string]any{}}, 400},
		{"POST", "/analysis/jobs", "owned_key", map[string]any{"unknown": true}, 400},
		{"POST", "/analysis/jobs/job_owned/cancel", "", map[string]any{"unknown": true}, 400},
		{"POST", "/retention-policies/preview", "", map[string]any{"unknown": true}, 400},
		{"PUT", "/retention-policies/alerts", "owned_key", map[string]any{"unknown": true}, 400},
		{"PUT", "/retention-policies/alerts", "owned_key", retention.Change{PreviewID: "preview_owned", Candidate: retention.Candidate{Category: "alerts", Days: 0, ExpectedRevision: 1, ApplyMode: "future"}}, 400},
		{"POST", "/mcp/bindings", "", map[string]any{"unknown": true}, 400},
		{"POST", "/mcp/bindings", "", map[string]any{}, 400},
		{"DELETE", "/mcp/bindings/binding_owned", "", map[string]any{"unknown": true}, 400},
		{"DELETE", "/mcp/bindings/id.invalid", "", map[string]any{"expected_revision": 1}, 400},
		{"DELETE", "/mcp/bindings/binding_owned", "", map[string]any{"expected_revision": 0}, 400},
		{"POST", "/search/validate", "", map[string]any{"unknown": true}, 400},
		{"POST", "/alerts/search", "", map[string]any{"source_ip": "not_ip"}, 400},
		{"POST", "/sensors/sensor_owned/tasks", "short", map[string]any{}, 400},
		{"POST", "/sensors/sensor_owned/tasks", "owned_key", map[string]any{"unknown": true}, 400},
		{"POST", "/sensors/sensor_owned/tasks", "owned_key", map[string]any{"kind": "diagnostics", "sample_id": "sample_owned"}, 400},
		{"POST", "/sensors/sensor_owned/tasks", "owned_key", map[string]any{"kind": "diagnostics", "rule_mode": "package"}, 400},
		{"POST", "/replay/samples", "", map[string]any{}, 503},
	} {
		t.Run(tc.method+tc.path+tc.key, func(t *testing.T) { client.request(tc.method, tc.path, tc.key, tc.body, nil, tc.status) })
	}
	report := assistant.Request{Kind: "daily", Period: time.Now().UTC().AddDate(0, 0, -1).Format("2006-01-02"), Timezone: "UTC"}
	client.request("POST", "/analysis/jobs", "statistics_owned", report, nil, 503)
	chat := assistant.Request{Kind: "chat", ProviderID: "model_owned", ProviderRevision: 1, AllowContext: true, Question: "分析告警"}
	chat.Window.Start, chat.Window.End = time.Now().UTC().Add(-time.Hour), time.Now().UTC()
	client.request("POST", "/analysis/jobs", "chat_owned", chat, nil, 503)
	// 没有配置授权方或签名密钥时，入口返回明确不可用状态。
	missing := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime}, tenant, password)
	missing.request("POST", "/mcp/bindings", "", map[string]any{}, nil, 503)
	missing.request("POST", "/sensors/sensor_owned/tasks", "owned_key", map[string]any{}, nil, 503)
	missing.request("GET", "/mcp", "", nil, nil, 200)
}
