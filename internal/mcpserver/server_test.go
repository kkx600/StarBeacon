package mcpserver

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/analytics"
	"github.com/kkx600/StarBeacon/internal/inventory"
	"github.com/kkx600/StarBeacon/internal/mcpaccess"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/outbound"
	"github.com/kkx600/StarBeacon/internal/traffic"
	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type mockBackend struct {
	identity                                    mcpaccess.Identity
	denied, errorBudget, errorAudit, errorQuery error
	queries, identities                         int
	audits                                      []string
	revokeAfterQuery                            bool
}

func (b *mockBackend) MCPIdentity(_ context.Context, issuer, subject, app string) (mcpaccess.Identity, error) {
	b.identities++
	if b.denied != nil {
		return mcpaccess.Identity{}, b.denied
	}
	if issuer != b.identity.Binding.Issuer || subject != b.identity.Binding.Subject || app != b.identity.Binding.OAuthClientID {
		return mcpaccess.Identity{}, mcpaccess.ErrDenied
	}
	i := b.identity
	if b.revokeAfterQuery && b.queries > 0 {
		i.Binding.Revision++
	}
	return i, nil
}
func (b *mockBackend) MCPAudit(_ context.Context, _ mcpaccess.Identity, tool, result string) error {
	b.audits = append(b.audits, tool+"."+result)
	return b.errorAudit
}
func (b *mockBackend) MCPAllow(context.Context, string, string, int) error { return b.errorBudget }
func (b *mockBackend) SearchAlerts(_ context.Context, u model.Principal, q model.SearchRequest) (model.SearchResult, error) {
	b.queries++
	if u.Role != "viewer" || u.TenantID != "tenant_owned" {
		return model.SearchResult{}, mcpaccess.ErrDenied
	}
	a := model.Alert{RegistrationID: "private-registration"}
	a.Event.Original = "private-payload"
	return model.SearchResult{Items: []model.Alert{a}, Total: 9007199254740993, Page: q.Page, PageSize: q.PageSize}, b.errorQuery
}
func (b *mockBackend) Overview(context.Context, model.Principal, analytics.Window) (analytics.Snapshot, error) {
	b.queries++
	return analytics.Snapshot{}, b.errorQuery
}
func (b *mockBackend) SearchTraffic(_ context.Context, u model.Principal, q model.TrafficSearchRequest) (traffic.Result, error) {
	b.queries++
	if u.Role != "viewer" || u.TenantID != "tenant_owned" {
		return traffic.Result{}, mcpaccess.ErrDenied
	}
	a := model.Alert{EventID: "protocol_owned", TenantID: u.TenantID, RegistrationID: "private-registration"}
	a.Event.Kind = "tls"
	a.Event.Original = "private-payload"
	return traffic.Result{Items: []traffic.Record{{Alert: a, Details: traffic.Parse(`{"tls":{"sni":"service.example","version":"TLS 1.3"},"flow":{"bytes_toserver":18446744073709551615,"bytes_toclient":0}}`)}}, Total: 9007199254740993, Page: q.Page, PageSize: q.PageSize}, b.errorQuery
}
func (b *mockBackend) InventoryAsset(context.Context, model.Principal, string) (inventory.Record, error) {
	b.queries++
	return inventory.Record{ID: "asset_owned"}, b.errorQuery
}
func (b *mockBackend) ListSensors(context.Context, model.Principal) ([]model.Sensor, error) {
	b.queries++
	return []model.Sensor{{ID: "probe_a", RegistrationID: "private-registration", Health: json.RawMessage(`{"cpu_percent":25,"protocol_capabilities":{"private":"native-protocol-directory"}}`)}, {ID: "probe_b"}}, b.errorQuery
}

type bearerTransport struct {
	token string
	base  http.RoundTripper
}

func (r bearerTransport) RoundTrip(q *http.Request) (*http.Response, error) {
	copy := q.Clone(q.Context())
	copy.Header = q.Header.Clone()
	copy.Header.Set("Authorization", "Bearer "+r.token)
	return r.base.RoundTrip(copy)
}

func fixture(t *testing.T) (*Server, *mockBackend, *httptest.Server, *map[string]any) {
	t.Helper()
	data := map[string]any{}
	issuer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, secret, ok := r.BasicAuth()
		if !ok || id != url.QueryEscape("resource:reader") || secret != url.QueryEscape("test:secret+value") || r.Method != "POST" || r.ParseForm() != nil || r.PostForm.Get("token") != "owned-token" || r.PostForm.Get("token_type_hint") != "access_token" {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(data)
	}))
	t.Cleanup(issuer.Close)
	roots := x509.NewCertPool()
	roots.AddCert(issuer.Certificate())
	networks, _ := outbound.ParseNetworks("127.0.0.0/8")
	mux := http.NewServeMux()
	endpoint := httptest.NewTLSServer(mux)
	t.Cleanup(endpoint.Close)
	backend := &mockBackend{identity: mcpaccess.Identity{Principal: model.Principal{ID: "owner", TenantID: "tenant_owned", Role: "admin"}, Binding: mcpaccess.Binding{ID: "mcp_owned", Issuer: issuer.URL, Subject: "subject_owned", OAuthClientID: "agent_owned", Scopes: []string{"alerts:read", "assets:read", "sensors:read", "traffic:read"}, Enabled: true, ExpiresAt: time.Now().Add(time.Hour), RequestsPerMinute: 60, Revision: 1}}}
	data = map[string]any{"active": true, "iss": issuer.URL, "sub": "subject_owned", "client_id": "agent_owned", "aud": endpoint.URL + "/mcp", "scope": "alerts:read assets:read sensors:read traffic:read", "exp": time.Now().Add(time.Hour).Unix()}
	s, err := New(Config{Origin: endpoint.URL, Issuer: issuer.URL, IntrospectionURL: issuer.URL + "/introspect", ClientID: "resource:reader", ClientSecret: "test:secret+value"}, backend, outbound.Policy{Roots: roots, PrivateNetworks: networks})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	mux.Handle("/mcp", s.Handler)
	mux.Handle("/.well-known/oauth-protected-resource/mcp", s.Metadata)
	return s, backend, endpoint, &data
}

func TestOfficialClientDiscoveryAndReadOnlyBoundedResults(t *testing.T) {
	_, b, endpoint, _ := fixture(t)
	ctx, stop := context.WithTimeout(context.Background(), 15*time.Second)
	defer stop()
	c := endpoint.Client()
	c.Transport = bearerTransport{"owned-token", c.Transport}
	client := mcp.NewClient(&mcp.Implementation{Name: "owned-agent", Version: "test"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: endpoint.URL + "/mcp", HTTPClient: c, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	list, err := session.ListTools(ctx, nil)
	if err != nil || len(list.Tools) != 9 {
		t.Fatal(err, list)
	}
	for _, tool := range list.Tools {
		if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint || tool.Annotations.DestructiveHint == nil || *tool.Annotations.DestructiveHint || tool.Annotations.OpenWorldHint == nil || *tool.Annotations.OpenWorldHint {
			t.Fatal("工具能力声明不正确", tool)
		}
	}
	window := map[string]any{"start": "2026-10-02T00:00:00Z", "end": "2026-10-03T00:00:00Z"}
	for _, call := range []*mcp.CallToolParams{{Name: "alerts.search", Arguments: window}, {Name: "alerts.aggregate", Arguments: window}, {Name: "assets.get", Arguments: map[string]any{"id": "asset_owned"}}, {Name: "sensors.list", Arguments: map[string]any{"limit": 1}}} {
		result, err := session.CallTool(ctx, call)
		if err != nil || result.IsError {
			t.Fatal(err, result)
		}
		raw, _ := json.Marshal(result.StructuredContent)
		if strings.Contains(string(raw), "private-payload") || strings.Contains(string(raw), "private-registration") {
			t.Fatal("只读工具泄露原始载荷")
		}
		if call.Name == "alerts.search" && !strings.Contains(string(raw), `"total":"9007199254740993"`) {
			t.Fatal("大整数发生精度损失", string(raw))
		}
		if call.Name == "sensors.list" && !strings.Contains(string(raw), `"truncated":true`) {
			t.Fatal("列表截断没有标注", string(raw))
		}
		if call.Name == "sensors.list" && (strings.Contains(string(raw), "native-protocol-directory") || !strings.Contains(string(raw), `"cpu_percent":25`)) {
			t.Fatal("探针摘要丢失资源观测或隐式带出完整协议目录")
		}
	}
	before := b.queries
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "alerts.search", Arguments: map[string]any{"start": "2026-10-02T00:00:00Z", "end": "2026-10-03T00:00:00Z", "tenant_id": "foreign"}})
	if err == nil && !result.IsError || b.queries != before {
		t.Fatal("输入 schema 接受了调用方租户")
	}
	for _, call := range []*mcp.CallToolParams{{Name: "alerts.search", Arguments: map[string]any{"start": "2026-10-02T00:00:00Z", "end": "2026-11-03T00:00:00Z"}}, {Name: "assets.get", Arguments: map[string]any{"id": "../../secret"}}, {Name: "sensors.list", Arguments: map[string]any{"limit": 201}}} {
		result, err := session.CallTool(ctx, call)
		if err == nil && !result.IsError {
			t.Fatal("无界输入被接受")
		}
	}
	if b.queries != before {
		t.Fatal("无效查询访问了业务数据")
	}
}

func TestTokenClaimsScopesAndOriginFailClosed(t *testing.T) {
	s, b, endpoint, data := fixture(t)
	base := mapsClone(*data)
	for name, mutate := range map[string]func(map[string]any){"inactive": func(c map[string]any) { c["active"] = false }, "issuer": func(c map[string]any) { c["iss"] = "https://foreign.example" }, "audience": func(c map[string]any) { c["aud"] = "https://foreign.example/mcp" }, "expired": func(c map[string]any) { c["exp"] = time.Now().Unix() - 1 }, "no-expiry": func(c map[string]any) { delete(c, "exp") }, "future": func(c map[string]any) { c["nbf"] = time.Now().Add(time.Hour).Unix() }, "lifetime": func(c map[string]any) { c["exp"] = time.Now().Add(25 * time.Hour).Unix() }, "other-app": func(c map[string]any) { c["client_id"] = "another-app" }, "unknown-scope": func(c map[string]any) { c["scope"] = "response:execute" }, "bad-sub": func(c map[string]any) { c["sub"] = "�" }} {
		t.Run(name, func(t *testing.T) {
			*data = mapsClone(base)
			mutate(*data)
			req := httptest.NewRequest("POST", endpoint.URL+"/mcp", strings.NewReader(`{}`))
			req.Header.Set("Authorization", "Bearer owned-token")
			w := httptest.NewRecorder()
			s.Handler.ServeHTTP(w, req)
			if w.Code != 401 || w.Header().Get("WWW-Authenticate") == "" {
				t.Fatal(w.Code, w.Body.String())
			}
		})
	}
	*data = mapsClone(base)
	(*data)["aud"] = []string{s.Info.Resource, "https://other.example/resource"}
	if _, err := s.verify(context.Background(), "owned-token", httptest.NewRequest("POST", "/mcp", nil)); err != nil {
		t.Fatal("规范 audience 数组被拒绝", err)
	}
	b.denied = mcpaccess.ErrDenied
	if _, err := s.verify(context.Background(), "owned-token", httptest.NewRequest("POST", "/mcp", nil)); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatal("停用绑定仍可认证", err)
	}
	b.denied = errors.New("database-secret-error")
	if _, err := s.verify(context.Background(), "owned-token", httptest.NewRequest("POST", "/mcp", nil)); err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatal("依赖错误泄露", err)
	}
	b.denied = nil
	for _, token := range []string{"", "with space", "with\tseparator", strings.Repeat("a", 8193)} {
		if _, err := s.verify(context.Background(), token, httptest.NewRequest("POST", "/mcp", nil)); !errors.Is(err, auth.ErrInvalidToken) {
			t.Fatal("无效令牌格式", err)
		}
	}
	for _, entry := range []struct {
		method, origin, cookie, query string
		length                        int64
		status                        int
	}{{"POST", "https://foreign.example", "", "", 0, 403}, {"POST", "null", "", "", 0, 403}, {"GET", "", "", "", 0, 405}, {"DELETE", "", "", "", 0, 405}, {"POST", "", "session=x", "", 0, 400}, {"POST", "", "", "?token=owned-token", 0, 400}, {"POST", "", "", "", 65537, 413}} {
		r := httptest.NewRequest(entry.method, endpoint.URL+"/mcp"+entry.query, strings.NewReader("{}"))
		r.Header.Set("Origin", entry.origin)
		r.Header.Set("Cookie", entry.cookie)
		r.ContentLength = entry.length
		w := httptest.NewRecorder()
		s.Handler.ServeHTTP(w, r)
		if w.Code != entry.status {
			t.Fatal(entry, w.Code, w.Body.String())
		}
	}
	b.errorBudget = mcpaccess.ErrQuota
	w := httptest.NewRecorder()
	s.Handler.ServeHTTP(w, httptest.NewRequest("POST", "/mcp", nil))
	if w.Code != 429 || w.Header().Get("Retry-After") == "" {
		t.Fatal("超预算仍被处理")
	}
	b.errorBudget = errors.New("redis-error")
	w = httptest.NewRecorder()
	s.Handler.ServeHTTP(w, httptest.NewRequest("POST", "/mcp", nil))
	if w.Code != 503 {
		t.Fatal("预算故障仍放行")
	}
}
func mapsClone(in map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range in {
		out[k] = v
	}
	return out
}

func TestInFlightRevocationAuditAndQueryFailure(t *testing.T) {
	s, b, _, _ := fixture(t)
	info, err := s.verify(context.Background(), "owned-token", httptest.NewRequest("POST", "/mcp", nil))
	if err != nil {
		t.Fatal(err)
	}
	query := func(context.Context, mcpaccess.Identity) (any, bool, error) {
		b.queries++
		return "owned-data", false, b.errorQuery
	}
	if _, err := s.invoke(context.Background(), nil, catalog[0], query); !errors.Is(err, mcpaccess.ErrDenied) {
		t.Fatal(err)
	}
	invalid := *info
	invalid.Extra = map[string]any{}
	if _, err := s.invoke(context.Background(), &invalid, catalog[0], query); !errors.Is(err, mcpaccess.ErrDenied) {
		t.Fatal(err)
	}
	b.identity.Binding.Scopes = []string{"assets:read"}
	if _, err := s.invoke(context.Background(), info, catalog[0], query); !errors.Is(err, mcpaccess.ErrDenied) {
		t.Fatal(err)
	}
	b.identity.Binding.Scopes = []string{"alerts:read"}
	b.errorAudit = errors.New("audit-error")
	if _, err := s.invoke(context.Background(), info, catalog[0], query); err == nil || b.queries != 0 {
		t.Fatal("审计失败仍读取业务数据")
	}
	b.errorAudit = nil
	b.errorQuery = errors.New("sensitive-query-error")
	if _, err := s.invoke(context.Background(), info, catalog[0], query); err == nil || strings.Contains(err.Error(), "sensitive") {
		t.Fatal(err)
	}
	b.errorQuery = nil
	b.queries = 0
	b.revokeAfterQuery = true
	if _, err := s.invoke(context.Background(), info, catalog[0], query); !errors.Is(err, mcpaccess.ErrDenied) {
		t.Fatal("途中撤销仍释放数据", err)
	}
	if !reflect.DeepEqual(b.audits[len(b.audits)-2:], []string{"alerts.search.started", "alerts.search.refused"}) {
		t.Fatal("撤销路径未审计", b.audits)
	}
	b.revokeAfterQuery = false
	for _, value := range []any{strings.Repeat("x", 256*1024), make(chan int)} {
		_, err := s.invoke(context.Background(), info, catalog[0], func(context.Context, mcpaccess.Identity) (any, bool, error) { return value, false, nil })
		if err == nil || b.audits[len(b.audits)-1] != "alerts.search.limited" {
			t.Fatal("输出上限没有被执行", err)
		}
	}
	if requestToken(nil) != nil || requestToken(&mcp.CallToolRequest{}) != nil {
		t.Fatal("空协议上下文不能携带身份")
	}
}

func TestHTTPSConfigurationAndProtectedResourceMetadata(t *testing.T) {
	s, _, endpoint, _ := fixture(t)
	for _, alter := range []func(*Config){func(c *Config) { c.Origin = "http://platform.example" }, func(c *Config) { c.Origin = "https://platform.example/path" }, func(c *Config) { c.Issuer = "http://issuer.example" }, func(c *Config) { c.IntrospectionURL = "https://foreign.example/introspect" }, func(c *Config) { c.ClientSecret = "" }} {
		c := s.config
		alter(&c)
		if _, err := New(c, s.backend, outbound.Policy{}); err == nil {
			t.Fatal("非规范授权配置被接受")
		}
	}
	response, err := endpoint.Client().Get(endpoint.URL + "/.well-known/oauth-protected-resource/mcp")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != 200 || !bytes.Contains(raw, []byte(s.Info.Resource)) || bytes.Contains(raw, []byte(s.config.ClientSecret)) {
		t.Fatal("资源发现不正确", response.StatusCode, string(raw))
	}
}
