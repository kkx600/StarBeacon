//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/admin"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/inventory"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/platform"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/redis/go-redis/v9"
)

func TestInventoryHTTPPersistenceHistoryAndTenantIsolation(t *testing.T) {
	if os.Getenv("SB_MODE") != "development" || os.Getenv("SB_MIGRATION_DATABASE_URL") == "" {
		t.Skip("需要独立开发依赖")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	owner, err := store.Open(ctx, os.Getenv("SB_MIGRATION_DATABASE_URL"))
	require(t, err)
	defer owner.Close()
	db, err := store.Open(ctx, os.Getenv("SB_DATABASE_URL"))
	require(t, err)
	defer db.Close()
	require(t, db.VerifyRuntimeRole(ctx))
	redisOptions, err := redis.ParseURL(os.Getenv("SB_REDIS_URL"))
	require(t, err)
	redisOptions.DB = 15
	cache := redis.NewClient(redisOptions)
	defer cache.Close()
	require(t, cache.Ping(ctx).Err())
	tenants := []string{store.RandomID("it_inv_a_"), store.RandomID("it_inv_b_")}
	password := store.Token()
	for _, tenant := range tenants {
		require(t, admin.Bootstrap(ctx, owner, tenant, "资产验收", tenant, password, "admin"))
		defer func() {
			clean, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			require(t, owner.TenantTx(clean, tenant, func(tx pgx.Tx) error {
				for _, statement := range []string{`DELETE FROM inventory_history WHERE tenant_id=$1`, `DELETE FROM inventory_objects WHERE tenant_id=$1`, `DELETE FROM operation_audits WHERE tenant_id=$1`, `DELETE FROM login_audits WHERE tenant_id=$1`, `DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE tenant_id=$1)`, `DELETE FROM retention_policies WHERE tenant_id=$1`, `DELETE FROM users WHERE tenant_id=$1`, `DELETE FROM tenants WHERE id=$1`} {
					if _, err := tx.Exec(clean, statement, tenant); err != nil {
						return err
					}
				}
				return nil
			}))
		}()
	}
	require(t, admin.Bootstrap(ctx, owner, tenants[0], "资产验收", tenants[0]+"_viewer", password, "viewer"))
	auth := httpapi.NewAuth(db, cache, "http://127.0.0.1", "it_inventory", false)
	api := &platform.API{DB: db, Auth: auth, Redis: cache}
	server := httptest.NewServer(httpapi.Middleware(api.Handler()))
	defer server.Close()
	auth.Origin = server.URL
	client := func() *http.Client {
		jar, err := cookiejar.New(nil)
		require(t, err)
		return &http.Client{Jar: jar, Timeout: 5 * time.Second}
	}
	request := func(client *http.Client, method, path, csrf, origin string, body any, status int, target any) {
		t.Helper()
		var input io.Reader
		if body != nil {
			data, err := json.Marshal(body)
			require(t, err)
			input = bytes.NewReader(data)
		}
		req, err := http.NewRequestWithContext(ctx, method, server.URL+path, input)
		require(t, err)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", origin)
		req.Header.Set("X-CSRF-Token", csrf)
		response, err := client.Do(req)
		require(t, err)
		defer response.Body.Close()
		data, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		require(t, err)
		if response.StatusCode != status {
			t.Fatalf("%s %s: 状态 %d，期望 %d；%s", method, path, response.StatusCode, status, data)
		}
		if target != nil {
			require(t, json.Unmarshal(data, target))
		}
	}
	login := func(username string) (*http.Client, model.Principal) {
		t.Helper()
		c := client()
		var principal model.Principal
		request(c, "POST", "/api/v1/auth/login", "", server.URL, map[string]string{"username": username, "password": password}, 200, &principal)
		if principal.CSRF == "" {
			t.Fatal("缺少 CSRF")
		}
		return c, principal
	}
	request(client(), "GET", "/api/v1/inventory/assets", "", "", nil, 401, nil)
	a, user := login(tenants[0])
	b, other := login(tenants[1])
	viewer, v := login(tenants[0] + "_viewer")
	group := inventory.Group{Name: "生产资产", Owner: "安全运营", Active: true}
	write := func(id string, revision int64, data any) map[string]any {
		return map[string]any{"id": id, "expected_revision": revision, "data": data}
	}
	request(a, "POST", "/api/v1/inventory/groups", "", server.URL, write("obj_group", 0, group), 403, nil)
	request(a, "POST", "/api/v1/inventory/groups", user.CSRF, "http://other.example", write("obj_group", 0, group), 403, nil)
	request(viewer, "POST", "/api/v1/inventory/groups", v.CSRF, server.URL, write("obj_group", 0, group), 403, nil)
	var saved inventory.Record
	request(a, "POST", "/api/v1/inventory/groups", user.CSRF, server.URL, write("obj_group", 0, group), 201, &saved)
	if saved.Revision != 1 {
		t.Fatal("首次修订不是 1")
	}
	asset := inventory.Asset{Name: "业务服务器", GroupID: "obj_group", NetworkDomain: "office", Criticality: "high", Active: true, Interfaces: []inventory.Interface{{Name: "eth0", MAC: "AA-BB-CC-DD-EE-FF", IPs: []string{"192.0.2.1"}}}}
	request(a, "POST", "/api/v1/inventory/assets", user.CSRF, server.URL, write("obj_asset", 0, asset), 201, &saved)
	first := saved.UpdatedAt
	group.Active = false
	request(a, "POST", "/api/v1/inventory/groups", user.CSRF, server.URL, write("obj_group", 1, group), 409, nil)
	asset.Name = "业务服务器归属确认"
	request(a, "POST", "/api/v1/inventory/assets", user.CSRF, server.URL, write("obj_asset", 0, asset), 409, nil)
	asset.Interfaces[0].IPs = []string{"192.0.2.2"}
	request(a, "POST", "/api/v1/inventory/assets", user.CSRF, server.URL, write("obj_asset", 1, asset), 201, &saved)
	if saved.Revision != 2 {
		t.Fatal("修订未递增")
	}
	var history struct {
		Items []inventory.Record `json:"items"`
	}
	request(a, "GET", "/api/v1/inventory/assets/obj_asset/history?at="+url.QueryEscape(first.Format(time.RFC3339Nano)), "", "", nil, 200, &history)
	if len(history.Items) != 1 || history.Items[0].Revision != 1 {
		t.Fatal("历史时间过滤失效")
	}
	var historical inventory.Asset
	require(t, json.Unmarshal(history.Items[0].Data, &historical))
	if historical.Interfaces[0].IPs[0] != "192.0.2.1" || historical.Name != "业务服务器" {
		t.Fatal("当前配置覆盖了历史事实")
	}
	request(a, "GET", "/api/v1/inventory/assets/obj_asset/history", "", "", nil, 200, &history)
	if len(history.Items) != 2 {
		t.Fatal("历史修订缺失")
	}
	request(b, "GET", "/api/v1/inventory/assets/obj_asset", "", "", nil, 404, nil)
	request(b, "POST", "/api/v1/inventory/assets", other.CSRF, server.URL, write("obj_foreign", 0, asset), 404, nil)
	var page inventory.Page
	request(b, "GET", "/api/v1/inventory/assets", "", "", nil, 200, &page)
	if len(page.Items) != 0 {
		t.Fatal("跨租户读取资产")
	}
	request(viewer, "GET", "/api/v1/inventory/assets", "", "", nil, 200, &page)
	if len(page.Items) != 1 {
		t.Fatal("只读身份无法查询")
	}
	network := inventory.Network{Name: "办公网段", Prefix: "192.0.2.99/24", GroupID: "obj_group", NetworkDomain: "office", Purpose: "internal", Active: true}
	request(a, "POST", "/api/v1/inventory/networks", user.CSRF, server.URL, write("obj_network", 0, network), 201, &saved)
	var normalized inventory.Network
	require(t, json.Unmarshal(saved.Data, &normalized))
	if normalized.Prefix != "192.0.2.0/24" {
		t.Fatal("CIDR 未标准化")
	}
	for _, id := range []string{"obj_group_2", "obj_group_3"} {
		request(a, "POST", "/api/v1/inventory/groups", user.CSRF, server.URL, write(id, 0, inventory.Group{Name: "100%", Active: true}), 201, nil)
	}
	request(a, "GET", "/api/v1/inventory/groups?limit=1&keyword=100%25", "", "", nil, 200, &page)
	if len(page.Items) != 1 || page.NextCursor == "" {
		t.Fatal("游标页未生成")
	}
	cursor := page.NextCursor
	request(a, "GET", "/api/v1/inventory/groups?limit=1&keyword=100%25&cursor="+cursor, "", "", nil, 200, &page)
	if len(page.Items) != 1 || page.Items[0].ID == cursor || page.NextCursor != "" {
		t.Fatal("游标重读或遗漏")
	}
	for _, path := range []string{"/api/v1/inventory/users", "/api/v1/inventory/assets?limit=101", "/api/v1/inventory/assets?limit=wrong", "/api/v1/inventory/assets?cursor=..", "/api/v1/inventory/assets/obj_asset/history?at=wrong"} {
		request(a, "GET", path, "", "", nil, 400, nil)
	}
	request(a, "POST", "/api/v1/search/validate", user.CSRF, server.URL, map[string]string{"filter": "tenant_id == other"}, 400, nil)
	request(a, "POST", "/api/v1/search/validate", user.CSRF, server.URL, map[string]string{"filter": `tcp.port in {80 443} and ip.addr != 192.0.2.1`}, 200, nil)
	var fields struct {
		Fields []any `json:"fields"`
	}
	request(a, "GET", "/api/v1/search/fields", "", "", nil, 200, &fields)
	if len(fields.Fields) < 30 {
		t.Fatal("缺少真实字段目录")
	}
	var count int
	require(t, owner.TenantTx(ctx, tenants[0], func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM inventory_history WHERE tenant_id=$1 AND expires_at-valid_from=interval '180 days'`, tenants[0]).Scan(&count)
	}))
	if count != 6 {
		t.Fatalf("历史默认留存错误：%d", count)
	}
	t.Log("真实 HTTP、PostgreSQL RLS、Redis 会话限流、资产修订、网段标准化、游标、权限与 180 天快照留存通过")
}
