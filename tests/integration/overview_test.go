//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/admin"
	"github.com/kkx600/StarBeacon/internal/analytics"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/platform"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/redis/go-redis/v9"
)

func TestOverviewRealAggregationTenantIsolationCacheAndWindow(t *testing.T) {
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
	es, err := store.OpenES(os.Getenv("SB_ES_URL"), os.Getenv("SB_ES_API_KEY"))
	require(t, err)
	options, err := redis.ParseURL(os.Getenv("SB_REDIS_URL"))
	require(t, err)
	options.DB = 14
	cache := redis.NewClient(options)
	defer cache.Close()
	tenants := []string{store.RandomID("it_overview_a_"), store.RandomID("it_overview_b_")}
	password := store.Token()
	for _, tenant := range tenants {
		require(t, admin.Bootstrap(ctx, owner, tenant, "态势统计验收", tenant, password, "admin"))
		defer func() {
			clean, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			require(t, owner.TenantTx(clean, tenant, func(tx pgx.Tx) error {
				for _, table := range []string{"inventory_history", "inventory_objects", "operation_audits", "login_audits", "routes", "sensors", "retention_policies"} {
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
	require(t, admin.Bootstrap(ctx, owner, tenants[0], "态势统计验收", tenants[0]+"_viewer", password, "viewer"))
	require(t, owner.TenantTx(ctx, tenants[0], func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO sensors(tenant_id,id,name,registration_id,active,last_seen) VALUES($1,'probe_online','在线探针',$2,true,now()),($1,'probe_offline','离线探针',$3,true,now()-interval '1 hour'),($1,'probe_disabled','停用探针',$4,false,now())`, tenants[0], store.RandomID("reg_"), store.RandomID("reg_"), store.RandomID("reg_"))
		return err
	}))
	start := time.Now().UTC().Truncate(time.Hour).Add(-2 * time.Hour)
	window := analytics.Window{Start: start, End: start.Add(3 * time.Hour)}
	for tenantIndex, tenant := range tenants {
		index := "sb-alerts-" + tenant + "-" + start.Format("2006.01.02")
		require(t, es.EnsurePolicy(ctx))
		require(t, es.EnsureIndex(ctx, index, start.Format("2006-01-02")))
		defer func() {
			clean, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			response, err := es.API.Indices.Delete([]string{index}, es.API.Indices.Delete.WithContext(clean))
			require(t, err)
			defer response.Body.Close()
			if response.IsError() {
				t.Errorf("清理自身索引失败：%d", response.StatusCode)
			}
		}()
		items := []model.Alert{}
		for i := 0; i < 7; i++ {
			now := start.Add(time.Hour)
			item := model.Alert{SchemaVersion: "alert.v1", EventID: fmt.Sprintf("owned_event_%d", i), TenantID: tenant, SensorID: "probe_online", Timestamp: now, ObservedAt: now, ReceivedAt: now, RawSHA256: control.Digest([]byte(fmt.Sprint(tenant, i))), Severity: []string{"high", "high", "medium", "medium", "low", "unknown", "high"}[i]}
			item.Event.Kind = "alert"
			item.Event.Dataset = "suricata.alert"
			item.Rule.ID = "1000001"
			item.Network.Protocol = "http"
			if i == 5 {
				item.Rule.ID = ""
				item.Network.Protocol = ""
			}
			if i == 6 {
				item.Timestamp = window.End
			}
			if tenantIndex == 1 {
				item.Rule.ID = "foreign_rule"
			}
			items = append(items, item)
		}
		for _, err := range es.Bulk(ctx, index, items) {
			require(t, err)
		}
		response, err := es.API.Indices.Refresh(es.API.Indices.Refresh.WithIndex(index), es.API.Indices.Refresh.WithContext(ctx))
		require(t, err)
		require(t, response.Body.Close())
	}
	auth := httpapi.NewAuth(db, cache, "", "it_overview", false)
	api := &platform.API{DB: db, ES: es, Redis: cache, Auth: auth}
	server := httptest.NewServer(httpapi.Middleware(api.Handler()))
	defer server.Close()
	auth.Origin = server.URL
	login := func(name string) *liveHTTP {
		jar, err := cookiejar.New(nil)
		require(t, err)
		client := &liveHTTP{t: t, ctx: ctx, client: &http.Client{Jar: jar, Timeout: 12 * time.Second}, origin: server.URL, prefix: "/api/v1"}
		client.login(name, password)
		return client
	}
	a, b, viewer := login(tenants[0]), login(tenants[1]), login(tenants[0]+"_viewer")
	var snapshot analytics.Snapshot
	a.request("POST", "/overview", "", window, &snapshot, 200)
	require(t, snapshot.Validate())
	if snapshot.Events.Total != "6" || snapshot.Inventory.Sensors != "3" || snapshot.Inventory.Online != "1" || snapshot.Inventory.Offline != "1" || snapshot.Inventory.Disabled != "1" {
		t.Fatal("真实统计没有遵守窗口或探针状态", snapshot)
	}
	if snapshot.Events.Rules.Buckets[0].Key != "1000001" || len(snapshot.Events.Protocols.Buckets) != 2 {
		t.Fatal("分布遗漏未知或混入其他租户", snapshot.Events)
	}
	var again analytics.Snapshot
	a.request("POST", "/overview", "", window, &again, 200)
	if !again.ObservedAt.Equal(snapshot.ObservedAt) {
		t.Fatal("同窗口未共享快照")
	}
	viewer.request("POST", "/overview", "", window, &again, 200)
	if again.Events.Total != "6" {
		t.Fatal("只读用户统计范围错误")
	}
	b.request("POST", "/overview", "", window, &again, 200)
	if again.Events.Rules.Buckets[0].Key != "foreign_rule" || again.Inventory.Sensors != "0" {
		t.Fatal("缓存或数据库跨租户")
	}
	csrf := a.csrf
	a.csrf = ""
	a.request("POST", "/overview", "", window, nil, 403)
	a.csrf = csrf
	a.request("POST", "/overview", "", map[string]any{"start": start, "end": window.End, "tenant_id": tenants[1]}, nil, 400)
	a.request("POST", "/overview", "", analytics.Window{Start: start, End: start.Add(32 * 24 * time.Hour)}, nil, 400)
	empty := analytics.Window{Start: start.Add(-48 * time.Hour), End: start.Add(-24 * time.Hour)}
	a.request("POST", "/overview", "", empty, &again, 200)
	if again.Events.Total != "0" {
		t.Fatal("空范围不应继承其他时间窗的计数")
	}
	// 异常缓存不解释为完整零统计；恢复缓存后仍使用同一授权窗口。
	raw, _ := json.Marshal(window)
	key := "sb:overview:" + tenants[0] + ":admin:" + control.Digest(raw)
	defer cache.Del(context.Background(), key, key+":lock", "sb:overview:quota:"+tenants[0]+":"+time.Now().UTC().Format("200601021504"))
	require(t, cache.Set(ctx, key, `{}`, time.Second).Err())
	a.request("POST", "/overview", "", window, nil, 503)
	require(t, cache.Del(ctx, key).Err())
	quota := "sb:overview:quota:" + tenants[0] + ":" + time.Now().UTC().Format("200601021504")
	require(t, cache.Set(ctx, quota, 30, time.Minute).Err())
	a.request("POST", "/overview", "", window, nil, 429)
	require(t, cache.Del(ctx, quota).Err())
	a.request("POST", "/overview", "", window, &again, 200)
}
