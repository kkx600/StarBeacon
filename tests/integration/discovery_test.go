//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/admin"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/discovery"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/inventory"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/platform"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/redis/go-redis/v9"
)

// 会话存储故障只在测试服务注入；真实网段、索引和额度仍使用专属依赖。
type discoverySessions struct {
	httpapi.SessionStore
	mu            sync.Mutex
	calls, failAt int
	changed       bool
}

func (s *discoverySessions) configure(at int, changed bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = 0
	s.failAt = at
	s.changed = changed
}
func (s *discoverySessions) Session(ctx context.Context, token string) (model.Principal, error) {
	u, err := s.SessionStore.Session(ctx, token)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.failAt > 0 && s.calls == s.failAt {
		if s.changed {
			u.CredentialRevision++
			return u, nil
		}
		return model.Principal{}, model.ErrUnauthenticated
	}
	return u, err
}

func TestPassiveDiscoveryRealESScopesEvidenceQuotaAndNoAutomaticIdentity(t *testing.T) {
	if os.Getenv("SB_MODE") != "development" || os.Getenv("SB_MIGRATION_DATABASE_URL") == "" {
		t.Skip("需要专属 Docker 依赖")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	owner, err := store.Open(ctx, os.Getenv("SB_MIGRATION_DATABASE_URL"))
	require(t, err)
	defer owner.Close()
	db, err := store.Open(ctx, os.Getenv("SB_DATABASE_URL"))
	require(t, err)
	defer db.Close()
	require(t, db.VerifyRuntimeRole(ctx))
	es, err := store.OpenES(os.Getenv("SB_ES_URL"), os.Getenv("SB_ES_API_KEY"))
	require(t, err)
	options, err := redis.ParseURL(os.Getenv("SB_REDIS_URL"))
	require(t, err)
	options.DB = 15
	cache := redis.NewClient(options)
	defer cache.Close()
	tenants := []string{store.RandomID("it_discovery_a_"), store.RandomID("it_discovery_b_")}
	password := store.Token()
	for _, tenant := range tenants {
		require(t, admin.Bootstrap(ctx, owner, tenant, "地址观测验收", tenant, password, "admin"))
		defer func() {
			clean, stop := context.WithTimeout(context.Background(), 10*time.Second)
			defer stop()
			require(t, owner.TenantTx(clean, tenant, func(tx pgx.Tx) error {
				for _, table := range []string{"inventory_history", "inventory_objects", "operation_audits", "login_audits", "routes", "sensors", "retention_policies"} {
					if _, err := tx.Exec(clean, "DELETE FROM "+table+" WHERE tenant_id=$1", tenant); err != nil {
						return err
					}
				}
				for _, sql := range []string{"DELETE FROM sessions WHERE user_id IN(SELECT id FROM users WHERE tenant_id=$1)", "DELETE FROM users WHERE tenant_id=$1", "DELETE FROM tenants WHERE id=$1"} {
					if _, err := tx.Exec(clean, sql, tenant); err != nil {
						return err
					}
				}
				return nil
			}))
		}()
	}
	require(t, admin.Bootstrap(ctx, owner, tenants[0], "地址观测验收", tenants[0]+"_viewer", password, "viewer"))
	registration := store.RandomID("reg_")
	require(t, owner.TenantTx(ctx, tenants[0], func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO sensors(tenant_id,id,name,registration_id,active,last_seen) VALUES($1,'probe_owned','办公探针',$2,true,now())`, tenants[0], registration)
		return err
	}))
	auth := httpapi.NewAuth(db, cache, "", "it_discovery", false)
	sessions := &discoverySessions{SessionStore: db}
	auth.Store = sessions
	api := &platform.API{DB: db, ES: es, Redis: cache, Auth: auth}
	server := httptest.NewServer(httpapi.Middleware(api.Handler()))
	defer server.Close()
	auth.Origin = server.URL
	login := func(name string) *liveHTTP {
		jar, err := cookiejar.New(nil)
		require(t, err)
		c := &liveHTTP{t: t, ctx: ctx, client: &http.Client{Jar: jar, Timeout: 15 * time.Second}, origin: server.URL, prefix: "/api/v1"}
		c.login(name, password)
		return c
	}
	a, b, viewer := login(tenants[0]), login(tenants[1]), login(tenants[0]+"_viewer")
	network := inventory.Network{Name: "办公网段", Prefix: "192.0.2.0/24", NetworkDomain: "office", Purpose: "internal", Active: true}
	writeNetwork := func(id string, revision int, network inventory.Network) {
		a.request("POST", "/inventory/networks", "", map[string]any{"id": id, "expected_revision": revision, "data": network}, nil, 201)
	}
	writeNetwork("network_owned", 0, network)
	start := time.Now().UTC().Truncate(24 * time.Hour).Add(-24 * time.Hour)
	q := discovery.Query{NetworkID: "network_owned", NetworkRevision: 1, SensorID: "probe_owned", RegistrationID: registration, Prefix: network.Prefix, Start: start, End: start.Add(time.Hour)}
	quota := func() string {
		return "sb:discovery:{" + tenants[0] + "}:quota:" + time.Now().UTC().Format("200601021504")
	}
	lock := "sb:discovery:{" + tenants[0] + "}:lock"
	defer cache.Del(context.Background(), quota(), lock)
	query := func(q discovery.Query, status int) *discovery.Result {
		require(t, cache.Del(ctx, quota()).Err())
		var result discovery.Result
		a.request("POST", "/inventory/discovery", "", q, &result, status)
		return &result
	}
	for n, tenant := range append(append([]string{}, tenants...), tenants[0]+"-shadow") {
		index, err := contract.IndexName(tenant, "context", start.Add(24*time.Hour).Format("2006-01-02"))
		require(t, err)
		require(t, es.EnsurePolicy(ctx))
		require(t, es.EnsureIndexRetention(ctx, index, start.Add(24*time.Hour).Format("2006-01-02"), 180))
		defer func() {
			clean, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			res, err := es.API.Indices.Delete([]string{index}, es.API.Indices.Delete.WithContext(clean))
			require(t, err)
			defer res.Body.Close()
			if res.IsError() && res.StatusCode != 404 {
				t.Error("自身索引清理失败", res.StatusCode)
			}
		}()
		items := []model.Alert{}
		add := func(id, src, dst, reg, kind string, ns int) {
			v := model.Alert{SchemaVersion: "1.0", EventID: id, TenantID: tenant, SensorID: q.SensorID, RegistrationID: reg, SourceGenerationID: "generation_owned", Sequence: fmt.Sprint(ns), RawSHA256: control.Digest([]byte(tenant + id)), Timestamp: start.Add(time.Duration(ns)), ObservedAt: start.Add(time.Second), ReceivedAt: start.Add(time.Second), Source: model.Endpoint{IP: src, MAC: "02:00:00:00:00:01"}, Destination: model.Endpoint{IP: dst, MAC: "02:00:00:00:00:02"}}
			v.Event.Kind = kind
			v.Event.Dataset = "suricata." + kind
			v.Suricata.FlowID = "18446744073709551615"
			items = append(items, v)
		}
		add("flow_one", "192.0.2.10", "198.51.100.20", registration, "flow", 1)
		add("flow_two", "192.0.2.10", "192.0.2.20", registration, "flow", 2)
		add("flow_three", "192.0.2.20", "192.0.2.10", registration, "flow", 3)
		add("flow_old", "192.0.2.99", "198.51.100.1", "reg_previous", "flow", 4)
		add("http_ignored", "192.0.2.98", "198.51.100.1", registration, "http", 5)
		add("ipv6_flow", "2001:db8::1", "2001:db8::2", registration, "flow", 6)
		add("multicast_flow", "0.0.0.0", "224.0.0.1", registration, "flow", 7)
		for i := 0; i < 513; i++ {
			add(fmt.Sprintf("limit_%d", i), fmt.Sprintf("198.18.%d.%d", i/256, i%256), "203.0.113.1", registration, "flow", 8+i)
		}
		if n == 1 {
			add("foreign_only", "192.0.2.77", "198.51.100.1", registration, "flow", 800)
		}
		for _, err := range es.Bulk(ctx, index, items) {
			require(t, err)
		}
		res, err := es.API.Indices.Refresh(es.API.Indices.Refresh.WithIndex(index), es.API.Indices.Refresh.WithContext(ctx))
		require(t, err)
		require(t, res.Body.Close())
		if n == 0 && len(query(q, 200).Addresses) != 2 {
			t.Fatal("没有同前缀租户时，排除模式不应把已有分区误判为空")
		}
	}
	result := query(q, 200)
	if result.PartitionStatus != "available" || len(result.Addresses) != 2 || result.Scope.NetworkDomain != "office" || result.QueriedAt.IsZero() {
		t.Fatal("发现范围或结果不完整", result)
	}
	row := result.Addresses[0]
	if row.IP != "192.0.2.10" || row.SourceRecords != "2" || row.DestinationRecords != "1" || row.First.Timestamp.Nanosecond() != 1 || row.Last.Timestamp.Nanosecond() != 3 || row.First.FlowID != "18446744073709551615" || row.Last.Side != "destination" {
		t.Fatal("方向计数、纳秒或流标识失真", row)
	}
	var page inventory.Page
	a.request("GET", "/inventory/assets", "", nil, &page, 200)
	if len(page.Items) != 0 {
		t.Fatal("地址观测自动变成了资产身份")
	}
	b.request("POST", "/inventory/discovery", "", q, nil, 404)
	viewer.request("POST", "/inventory/discovery", "", q, nil, 403)
	wrong := q
	wrong.NetworkRevision++
	query(wrong, 409)
	wrong = q
	wrong.RegistrationID = "reg_previous"
	query(wrong, 409)
	wrong = q
	wrong.Prefix = "198.51.100.0/24"
	query(wrong, 400)
	wrong = q
	wrong.SensorID = "probe_missing"
	query(wrong, 404)
	for _, phase := range []int{2, 3, 4} {
		sessions.configure(phase, false)
		query(q, 401)
		sessions.configure(0, false)
		if exists, err := cache.Exists(ctx, lock).Result(); err != nil || exists != 0 {
			t.Fatal("撤权后查询锁未释放", err)
		}
	}
	sessions.configure(2, true)
	query(q, 401)
	sessions.configure(0, false)
	for _, raw := range []string{`{"name":"损坏网段"}`, `{"name":"办公网段","prefix":"192.0.2.0/24","network_domain":"office","purpose":"internal","group_id":"","description":"","active":false}`} {
		require(t, owner.TenantTx(ctx, tenants[0], func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE inventory_objects SET data=$3::jsonb WHERE tenant_id=$1 AND kind='networks' AND id=$2`, tenants[0], q.NetworkID, raw)
			return err
		}))
		query(q, 503)
	}
	rawNetwork, err := json.Marshal(network)
	require(t, err)
	require(t, owner.TenantTx(ctx, tenants[0], func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE inventory_objects SET data=$3::jsonb WHERE tenant_id=$1 AND kind='networks' AND id=$2`, tenants[0], q.NetworkID, rawNetwork)
		return err
	}))
	wrong = q
	wrong.Prefix = "192.0.2.0/25"
	if len(query(wrong, 200).Addresses) != 2 {
		t.Fatal("包含关系合法的子网段不可查询")
	}
	wrong = q
	wrong.Start = wrong.Start.Add(-72 * time.Hour)
	wrong.End = wrong.Start.Add(time.Hour)
	if result := query(wrong, 200); result.PartitionStatus != "available" || len(result.Addresses) != 0 {
		t.Fatal("没有匹配事件不等于没有租户分区")
	}
	for _, entry := range []struct {
		id, prefix string
		count      int
	}{{"network_v6", "2001:db8::/64", 2}, {"network_all", "0.0.0.0/0", 0}, {"network_limit", "198.18.0.0/15", 0}} {
		n := network
		n.Prefix = entry.prefix
		writeNetwork(entry.id, 0, n)
		test := q
		test.NetworkID = entry.id
		test.Prefix = entry.prefix
		if entry.id == "network_v6" {
			if len(query(test, 200).Addresses) != entry.count {
				t.Fatal("IPv6 地址观测遗漏")
			}
		} else if entry.id == "network_limit" {
			query(test, 413)
		} else {
			query(test, 413)
		}
	}
	// 使用单地址排除范围独立验证组播，不受超限目录影响。
	n := network
	n.Prefix = "224.0.0.0/4"
	writeNetwork("network_multicast", 0, n)
	test := q
	test.NetworkID = "network_multicast"
	test.Prefix = n.Prefix
	if result := query(test, 200); len(result.Addresses) != 0 || result.DestinationExcluded != "1" {
		t.Fatal("组播地址混入目录", result)
	}
	require(t, cache.Set(ctx, quota(), 6, time.Minute).Err())
	a.request("POST", "/inventory/discovery", "", q, nil, 429)
	require(t, cache.Del(ctx, quota()).Err())
	require(t, cache.Set(ctx, lock, "other_request", time.Second).Err())
	a.request("POST", "/inventory/discovery", "", q, nil, 429)
	if value, err := cache.Get(ctx, lock).Result(); err != nil || value != "other_request" {
		t.Fatal("覆盖了并发查询锁")
	}
	require(t, cache.Del(ctx, lock).Err())
	network.Active = false
	writeNetwork("network_owned", 1, network)
	query(q, 409)
	var audits, assets int
	require(t, owner.TenantTx(ctx, tenants[0], func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM operation_audits WHERE tenant_id=$1 AND action='inventory.assets.discover' AND expires_at-created_at=interval '180 days'`, tenants[0]).Scan(&audits); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT count(*) FROM inventory_objects WHERE tenant_id=$1 AND kind='assets'`, tenants[0]).Scan(&assets)
	}))
	if audits < 4 || assets != 0 {
		t.Fatal("审计留存或只读边界失效", audits, assets)
	}
	// 当前用户及网段仍须在最终交付事务中有效；名称变化也不能沿用旧范围。
	var user model.Principal
	a.request("GET", "/auth/me", "", nil, &user, 200)
	v6 := q
	v6.NetworkID = "network_v6"
	v6.Prefix = "2001:db8::/64"
	scope, err := db.DiscoveryScope(ctx, user, v6, nil, "")
	require(t, err)
	scope.SensorName = "过期名称"
	if _, err := db.DiscoveryScope(ctx, user, v6, &scope, "test_scope"); !errors.Is(err, store.ErrConflict) {
		t.Fatal("过期范围仍然交付", err)
	}
	require(t, owner.TenantTx(ctx, tenants[0], func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE sensors SET registration_id='reg_replaced' WHERE tenant_id=$1 AND id=$2`, tenants[0], q.SensorID)
		return err
	}))
	query(v6, 409)
	// 仅存在同前缀的其他租户时，也不能把它识别为当前租户的分区。
	ownedIndex, _ := contract.IndexName(tenants[0], "context", start.Add(24*time.Hour).Format("2006-01-02"))
	deleted, err := es.API.Indices.Delete([]string{ownedIndex}, es.API.Indices.Delete.WithContext(ctx))
	require(t, err)
	require(t, deleted.Body.Close())
	if deleted.IsError() {
		t.Fatal("自身分区删除未完成", deleted.StatusCode)
	}
	absent, err := es.DiscoverAddresses(ctx, tenants[0], q)
	require(t, err)
	if absent.PartitionStatus != "absent" || len(absent.Addresses) != 0 {
		t.Fatal("同前缀租户影响了分区存在性", absent)
	}
	t.Log("真实 ES 双向流记录聚合、纳秒证据、IPv6、当前探针注册、网段修订、RLS、组播排除、512 地址拒绝截断、Redis 配额与 180 天审计通过；没有自动登记资产")
}
