//go:build integration

package integration

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/admin"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/mcpaccess"
	"github.com/kkx600/StarBeacon/internal/mcpserver"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/outbound"
	"github.com/kkx600/StarBeacon/internal/platform"
	"github.com/kkx600/StarBeacon/internal/searchfilter"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/redis/go-redis/v9"
)

// 两个无会话服务实例共享实际 PG／Redis；受控 TLS 授权方不代表企业身份系统已验收。
func TestMCPResourcesRealScopesSharedBudgetsRevocationAndAudit(t *testing.T) {
	if os.Getenv("SB_MODE") != "development" || os.Getenv("SB_MIGRATION_DATABASE_URL") == "" || os.Getenv("SB_REDIS_URL") == "" {
		t.Skip("需要独立开发依赖")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	owner, err := store.Open(ctx, os.Getenv("SB_MIGRATION_DATABASE_URL"))
	require(t, err)
	defer owner.Close()
	db, err := store.Open(ctx, os.Getenv("SB_DATABASE_URL"))
	require(t, err)
	defer db.Close()
	require(t, db.VerifyRuntimeRole(ctx))
	options, err := redis.ParseURL(os.Getenv("SB_REDIS_URL"))
	require(t, err)
	options.DB = 11
	cache := redis.NewClient(options)
	defer cache.Close()
	require(t, cache.Ping(ctx).Err())
	tenants := []string{store.RandomID("it_mcp_res_a_"), store.RandomID("it_mcp_res_b_")}
	principals := make([]model.Principal, 0, len(tenants))
	for _, tenant := range tenants {
		require(t, admin.Bootstrap(ctx, owner, tenant, "MCP 元数据资源验收", tenant, store.Token(), "admin"))
		principal, _, err := db.Password(ctx, tenant)
		require(t, err)
		principals = append(principals, principal)
		defer func() {
			clean, stop := context.WithTimeout(context.Background(), 10*time.Second)
			defer stop()
			for _, prefix := range []string{"sb:mcp:quota:tenant:" + tenant + ":*", "sb:mcp:quota:binding:" + tenant + ":*"} {
				var cursor uint64
				for {
					keys, next, err := cache.Scan(clean, cursor, prefix, 100).Result()
					require(t, err)
					if len(keys) > 0 {
						require(t, cache.Del(clean, keys...).Err())
					}
					if cursor = next; cursor == 0 {
						break
					}
				}
			}
			require(t, owner.TenantTx(clean, tenant, func(tx pgx.Tx) error {
				for _, table := range []string{"mcp_auth_routes", "mcp_bindings", "operation_audits", "login_audits", "retention_policies"} {
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
	var handlers [2]http.Handler
	var next atomic.Uint64
	endpoint := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlers[next.Add(1)%2].ServeHTTP(w, r)
	}))
	defer endpoint.Close()
	// 授权方标识来自固定配置，不采纳客户端或资源 URI 中的身份字段。
	var issuer *httptest.Server
	issuer = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, secret, ok := r.BasicAuth()
		if !ok || id != "resource-reader" || secret != "private-introspection-secret" || r.Method != "POST" || r.ParseForm() != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		subject := r.PostForm.Get("token")
		active := subject == "resource-a" || subject == "resource-b" || subject == "resource-quota"
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"active": active, "iss": issuer.URL, "sub": subject, "client_id": "metadata-agent", "aud": endpoint.URL + "/mcp", "scope": "alerts:read traffic:read assets:read", "exp": time.Now().Add(time.Hour).Unix()})
	}))
	defer issuer.Close()
	roots := x509.NewCertPool()
	roots.AddCert(issuer.Certificate())
	networks, err := outbound.ParseNetworks("127.0.0.0/8")
	require(t, err)
	backend := &platform.API{DB: db, Redis: cache}
	for index := range handlers {
		server, err := mcpserver.New(mcpserver.Config{Origin: endpoint.URL, Issuer: issuer.URL, IntrospectionURL: issuer.URL + "/introspect", ClientID: "resource-reader", ClientSecret: "private-introspection-secret"}, backend, outbound.Policy{Roots: roots, PrivateNetworks: networks})
		require(t, err)
		defer server.Close()
		handlers[index] = httpapi.Middleware(server.Handler)
	}
	changes := []mcpaccess.Change{
		{ID: "mcp_resources_a", Name: "协议调查资源", Subject: "resource-a", OAuthClientID: "metadata-agent", Scopes: []string{"alerts:read", "traffic:read"}, Enabled: true, ExpiresAt: time.Now().Add(time.Hour), RequestsPerMinute: 120},
		{ID: "mcp_resources_b", Name: "资产元数据资源", Subject: "resource-b", OAuthClientID: "metadata-agent", Scopes: []string{"assets:read"}, Enabled: true, ExpiresAt: time.Now().Add(time.Hour), RequestsPerMinute: 120},
		{ID: "mcp_resources_quota", Name: "资源调用预算", Subject: "resource-quota", OAuthClientID: "metadata-agent", Scopes: []string{"alerts:read"}, Enabled: true, ExpiresAt: time.Now().Add(time.Hour), RequestsPerMinute: 2},
	}
	for index, change := range changes {
		principal := principals[0]
		if index == 1 {
			principal = principals[1]
		}
		_, err := db.SaveMCPBinding(ctx, principal, issuer.URL, change, store.RandomID("request_"))
		require(t, err)
	}
	connect := func(token string) *mcp.ClientSession {
		copy := *endpoint.Client()
		copy.Transport = mcpBearer{base: copy.Transport, token: token}
		session, err := mcp.NewClient(&mcp.Implementation{Name: "metadata-agent", Version: "test"}, nil).Connect(ctx, &mcp.StreamableClientTransport{Endpoint: endpoint.URL + "/mcp", HTTPClient: &copy, DisableStandaloneSSE: true}, nil)
		require(t, err)
		t.Cleanup(func() { _ = session.Close() })
		return session
	}
	a, b := connect("resource-a"), connect("resource-b")
	resources, err := a.ListResources(ctx, nil)
	require(t, err)
	if len(resources.Resources) != 3 {
		t.Fatal("授权资源目录不完整", resources)
	}
	templates, err := a.ListResourceTemplates(ctx, nil)
	require(t, err)
	if len(templates.ResourceTemplates) != 1 || templates.ResourceTemplates[0].URITemplate != mcpserver.FieldsResourceTemplate {
		t.Fatal("原生资源模板未注册", templates)
	}
	result, err := a.ReadResource(ctx, &mcp.ReadResourceParams{URI: mcpserver.TrafficFieldsURI})
	require(t, err)
	if len(result.Contents) != 1 || result.Contents[0].MIMEType != "application/json" || len(result.Contents[0].Text) > 256*1024 {
		t.Fatal("资源输出未遵守内容契约", result)
	}
	var catalog struct {
		Data mcpserver.FieldCatalog `json:"data"`
	}
	require(t, json.Unmarshal([]byte(result.Contents[0].Text), &catalog))
	if catalog.Data.Dataset != "context" || catalog.Data.Version != searchfilter.Version || len(catalog.Data.Fields) < 30 || strings.Contains(result.Contents[0].Text, `"paths"`) || strings.Contains(result.Contents[0].Text, `"name":"severity"`) {
		t.Fatal("字段资源泄露内部映射或错误数据集", catalog)
	}
	resources, err = b.ListResources(ctx, nil)
	require(t, err)
	if len(resources.Resources) != 1 || resources.Resources[0].URI != mcpserver.CapabilitiesURI {
		t.Fatal("共享实例混用不同租户的授权目录", resources)
	}
	if denied, err := b.ReadResource(ctx, &mcp.ReadResourceParams{URI: mcpserver.TrafficFieldsURI}); err == nil || denied != nil {
		t.Fatal("未授权资源返回伪成功", denied, err)
	}
	for _, uri := range []string{"starbeacon://catalog/logs/fields", mcpserver.AlertsFieldsURI + "?tenant_id=" + tenants[1], "file:///etc/passwd"} {
		value, err := a.ReadResource(ctx, &mcp.ReadResourceParams{URI: uri})
		var protocolError *jsonrpc.Error
		if value != nil || !errors.As(err, &protocolError) || protocolError.Code != mcp.CodeResourceNotFound {
			t.Fatal("非法 URI 未返回标准资源错误", uri, value, err)
		}
	}
	changes[0].ExpectedRevision, changes[0].Scopes = 1, []string{"assets:read"}
	_, err = db.SaveMCPBinding(ctx, principals[0], issuer.URL, changes[0], store.RandomID("request_"))
	require(t, err)
	result, err = a.ReadResource(ctx, &mcp.ReadResourceParams{URI: mcpserver.CapabilitiesURI})
	require(t, err)
	var capabilities struct {
		Data mcpserver.MetadataCapabilities `json:"data"`
	}
	require(t, json.Unmarshal([]byte(result.Contents[0].Text), &capabilities))
	if !reflect.DeepEqual(capabilities.Data.Scopes, []string{"assets:read"}) || len(capabilities.Data.Datasets) != 0 || len(capabilities.Data.Tools) != 1 || capabilities.Data.Tools[0].Name != "assets.get" {
		t.Fatal("身份变更后能力资源保留旧授权", capabilities)
	}
	if denied, err := a.ReadResource(ctx, &mcp.ReadResourceParams{URI: mcpserver.AlertsFieldsURI}); err == nil || denied != nil {
		t.Fatal("范围撤回后旧客户端仍读取字段资源", denied, err)
	}
	changes[0].ExpectedRevision, changes[0].Enabled = 2, false
	_, err = db.SaveMCPBinding(ctx, principals[0], issuer.URL, changes[0], store.RandomID("request_"))
	require(t, err)
	if value, err := a.ReadResource(ctx, &mcp.ReadResourceParams{URI: mcpserver.CapabilitiesURI}); err == nil || value != nil {
		t.Fatal("停用绑定的客户端仍能读取元数据", value, err)
	}
	quota := connect("resource-quota")
	if remaining := time.Until(time.Now().Truncate(time.Minute).Add(time.Minute)); remaining < 3*time.Second {
		timer := time.NewTimer(remaining + 10*time.Millisecond)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	var succeeded, refused atomic.Int32
	var workers sync.WaitGroup
	for range 6 {
		workers.Go(func() {
			value, err := quota.ReadResource(ctx, &mcp.ReadResourceParams{URI: mcpserver.AlertsFieldsURI})
			if err == nil && value != nil && len(value.Contents) == 1 {
				succeeded.Add(1)
			} else if err != nil && value == nil {
				refused.Add(1)
			}
		})
	}
	workers.Wait()
	if succeeded.Load() != 2 || refused.Load() != 4 {
		t.Fatal("双实例资源调用绕过共享原子预算", succeeded.Load(), refused.Load())
	}
	audits, err := db.Audits(ctx, tenants[0], "operations", store.AuditQuery{Start: time.Now().Add(-time.Hour), End: time.Now().Add(time.Minute), Limit: 100})
	require(t, err)
	foundList, foundRead := false, false
	for _, audit := range audits.Items {
		foundList = foundList || audit.Action == "mcp.tool.resources.list.succeeded" && audit.RequestID != ""
		foundRead = foundRead || audit.Action == "mcp.tool.resources.read.alerts.search-fields.succeeded" && audit.RequestID != ""
	}
	if !foundList || !foundRead {
		t.Fatal("资源目录与读取没有真实租户审计")
	}
	require(t, owner.TenantTx(ctx, tenants[0], func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "UPDATE users SET active=false WHERE tenant_id=$1 AND id=$2", tenants[0], principals[0].ID)
		return err
	}))
	if value, err := quota.ReadResource(ctx, &mcp.ReadResourceParams{URI: mcpserver.CapabilitiesURI}); err == nil || value != nil {
		t.Fatal("所属账号停用后仍能读取资源", value, err)
	}
}
