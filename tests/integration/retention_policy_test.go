//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"github.com/kkx600/StarBeacon/internal/clientip"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/admin"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/platform"
	"github.com/kkx600/StarBeacon/internal/replay"
	"github.com/kkx600/StarBeacon/internal/retention"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/testpcap"
	"github.com/kkx600/StarBeacon/internal/transport"
	"github.com/redis/go-redis/v9"
)

func TestRetentionPoliciesPreviewIsolationFutureExpiryAndESPartition(t *testing.T) {
	if os.Getenv("SB_MODE") != "development" || os.Getenv("SB_MIGRATION_DATABASE_URL") == "" {
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
	options.DB = 12
	cache := redis.NewClient(options)
	defer cache.Close()
	es, err := store.OpenES(os.Getenv("SB_ES_URL"), os.Getenv("SB_ES_API_KEY"))
	require(t, err)
	tenants := []string{store.RandomID("it_ret_a_"), store.RandomID("it_ret_b_")}
	password := store.Token()
	for _, tenant := range tenants {
		require(t, admin.Bootstrap(ctx, owner, tenant, "留存策略验收", tenant, password, "admin"))
		defer func() {
			// 共享索引同时承载其他租户，不整体删除；只回收本租户可能写入的文档。
			deleteTenantEvents(t, es, tenant)
			clean, stop := context.WithTimeout(context.Background(), 10*time.Second)
			defer stop()
			require(t, owner.TenantTx(clean, tenant, func(tx pgx.Tx) error {
				for _, table := range []string{"retention_changes", "retention_previews", "replay_samples", "routes", "sensors", "operation_audits", "login_audits", "retention_policies"} {
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
	require(t, admin.Bootstrap(ctx, owner, tenants[0], "留存策略验收", tenants[0]+"_other", password, "admin"))
	require(t, admin.Bootstrap(ctx, owner, tenants[0], "留存策略验收", tenants[0]+"_view", password, "viewer"))
	storage, err := replay.NewLocal(filepath.Join(t.TempDir(), "samples"), 100*1024*1024)
	require(t, err)
	auth := httpapi.NewAuth(db, cache, "http://127.0.0.1", "it_retention", false)
	api := &platform.API{DB: db, Auth: auth, Redis: cache, Samples: storage, SampleQuota: 100 * 1024 * 1024}
	server := httptest.NewServer(httpapi.Middleware(api.Handler(), clientip.Policy{}))
	defer server.Close()
	auth.Origin = server.URL
	client := func(username string) *liveHTTP {
		jar, err := cookiejar.New(nil)
		require(t, err)
		c := &liveHTTP{t: t, ctx: ctx, client: &http.Client{Jar: jar, Timeout: 15 * time.Second}, origin: server.URL, prefix: "/api/v1"}
		c.login(username, password)
		return c
	}
	a, b, other, viewer := client(tenants[0]), client(tenants[1]), client(tenants[0]+"_other"), client(tenants[0]+"_view")
	viewer.request("GET", "/retention-policies", "", nil, nil, 403)
	var page struct {
		Items       []retention.Policy   `json:"items"`
		Catalog     []retention.Category `json:"catalog"`
		DefaultDays int                  `json:"default_days"`
	}
	a.request("GET", "/retention-policies", "", nil, &page, 200)
	if page.DefaultDays != 180 || len(page.Items) != 12 || len(page.Catalog) != 12 {
		t.Fatal("默认分类或期限不完整")
	}
	for _, p := range page.Items {
		if p.Days != 180 || p.Revision != 1 {
			t.Fatal("默认策略不一致")
		}
	}
	capture, err := testpcap.HTTP(false)
	require(t, err)
	var oldSample, newSample replay.Sample
	a.request("POST", "/replay/samples", "", capture, &oldSample, 201)
	candidate := retention.Candidate{Category: "pcap", Days: 210, ExpectedRevision: 1, ApplyMode: "future"}
	var preview retention.Preview
	a.request("POST", "/retention-policies/preview", "", candidate, &preview, 200)
	if preview.CurrentDays != 180 || !preview.ExistingUnmodified || preview.Scope != "new_samples" {
		t.Fatal("预览没有明确存量保护和生效范围")
	}
	input := retention.Change{PreviewID: preview.ID, Candidate: candidate}
	b.request("PUT", "/retention-policies/pcap", store.RandomID("key_"), input, nil, 404)
	other.request("PUT", "/retention-policies/pcap", store.RandomID("key_"), input, nil, 404)
	viewer.request("POST", "/retention-policies/preview", "", candidate, nil, 403)
	a.request("PUT", "/retention-policies/pcap", "", input, nil, 400)
	bad := input
	bad.Candidate.Days = 211
	a.request("PUT", "/retention-policies/pcap", store.RandomID("key_"), bad, nil, 409)
	key := store.RandomID("retkey_")
	var saved, repeat retention.Policy
	a.request("PUT", "/retention-policies/pcap", key, input, &saved, 200)
	a.request("PUT", "/retention-policies/pcap", key, input, &repeat, 200)
	if saved.Revision != 2 || saved.Days != 210 || repeat != saved {
		t.Fatal("策略发布或重复提交未保持不可变结果")
	}
	a.request("PUT", "/retention-policies/pcap", key, bad, nil, 409)
	a.request("POST", "/retention-policies/preview", "", candidate, nil, 409)
	a.request("POST", "/replay/samples", "", capture, &newSample, 201)
	require(t, owner.TenantTx(ctx, tenants[0], func(tx pgx.Tx) error {
		var oldDays, newDays float64
		if err := tx.QueryRow(ctx, "SELECT EXTRACT(epoch FROM expires_at-created_at)/86400 FROM replay_samples WHERE tenant_id=$1 AND id=$2", tenants[0], oldSample.ID).Scan(&oldDays); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, "SELECT EXTRACT(epoch FROM expires_at-created_at)/86400 FROM replay_samples WHERE tenant_id=$1 AND id=$2", tenants[0], newSample.ID).Scan(&newDays); err != nil {
			return err
		}
		if oldDays != 180 || newDays != 210 {
			t.Fatal("存量期限被重算或未来样本未应用策略")
		}
		var audits, changes int
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM operation_audits WHERE tenant_id=$1 AND action='retention.change'", tenants[0]).Scan(&audits); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM retention_changes WHERE tenant_id=$1", tenants[0]).Scan(&changes); err != nil {
			return err
		}
		if audits != 1 || changes != 1 {
			t.Fatal("策略发布审计重复或缺失")
		}
		return nil
	}))
	candidate.ExpectedRevision = 2
	candidate.Days = 365
	a.request("POST", "/retention-policies/preview", "", candidate, &preview, 200)
	require(t, owner.TenantTx(ctx, tenants[0], func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "UPDATE retention_previews SET expires_at=now()-interval '1 minute' WHERE tenant_id=$1 AND id=$2", tenants[0], preview.ID)
		return err
	}))
	a.request("PUT", "/retention-policies/pcap", store.RandomID("key_"), retention.Change{PreviewID: preview.ID, Candidate: candidate}, nil, 404)
	for _, days := range []int{0, 3651} {
		candidate.Days = days
		a.request("POST", "/retention-policies/preview", "", candidate, nil, 400)
	}
	candidate.Days = 365
	candidate.ApplyMode = "recompute"
	a.request("POST", "/retention-policies/preview", "", candidate, nil, 400)
	// 路由创建时按租户当前保留期冻结共享索引；策略变更只影响此后新建的路由，既有路由与索引保持原期限。
	probes := []transport.SensorIdentity{{TenantID: tenants[0], SensorID: "probe_before", RegistrationID: store.RandomID("reg_")}, {TenantID: tenants[0], SensorID: "probe_after", RegistrationID: store.RandomID("reg_")}}
	require(t, owner.TenantTx(ctx, tenants[0], func(tx pgx.Tx) error {
		for _, probe := range probes {
			if _, err := tx.Exec(ctx, `INSERT INTO sensors(tenant_id,id,name,registration_id,active,last_seen) VALUES($1,$2,'留存路由探针',$3,true,now())`, probe.TenantID, probe.SensorID, probe.RegistrationID); err != nil {
				return err
			}
		}
		return nil
	}))
	if _, err := db.Route(ctx, probes[0], "other"); err == nil {
		t.Fatal("未知事件流读取了默认策略")
	}
	before, err := db.Route(ctx, probes[0], "alerts")
	require(t, err)
	firstIndex := before.Index
	if firstIndex != sharedEventIndex(t, "alerts", before.Partition) {
		t.Fatal("路由未按默认保留期冻结共享索引", firstIndex)
	}
	require(t, es.EnsureIndex(ctx, firstIndex, before.Partition))
	candidate = retention.Candidate{Category: "alerts", Days: 365, ExpectedRevision: 1, ApplyMode: "future"}
	a.request("POST", "/retention-policies/preview", "", candidate, &preview, 200)
	a.request("PUT", "/retention-policies/alerts", store.RandomID("key_"), retention.Change{PreviewID: preview.ID, Candidate: candidate}, nil, 200)
	again, err := db.Route(ctx, probes[0], "alerts")
	require(t, err)
	if again.Token != before.Token || again.Index != firstIndex {
		t.Fatal("既有路由改用了新保留期索引", again.Index)
	}
	renewed, err := db.Route(ctx, probes[1], "alerts")
	require(t, err)
	secondIndex, err := contract.EventIndexName("alerts", 365, contract.DefaultIndexLayout().For("alerts").Period, renewed.Partition)
	require(t, err)
	if renewed.Index != secondIndex {
		t.Fatal("索引保留期未读取租户策略", renewed.Index)
	}
	// 新客户端没有本地缓存，必须回读既有索引；先建索引沿用名称冻结的期限，新路由索引按新期限建立。
	fresh, err := store.OpenES(os.Getenv("SB_ES_URL"), os.Getenv("SB_ES_API_KEY"))
	require(t, err)
	require(t, fresh.EnsureIndex(ctx, firstIndex, before.Partition))
	require(t, fresh.EnsureIndex(ctx, secondIndex, renewed.Partition))
	// 告警默认按周分区，生命周期为保留天数加七天分区跨度。
	for index, expected := range map[string]string{firstIndex: "sb-retention-187d", secondIndex: "sb-retention-372d"} {
		response, err := es.API.Indices.GetSettings(es.API.Indices.GetSettings.WithIndex(index), es.API.Indices.GetSettings.WithFlatSettings(true), es.API.Indices.GetSettings.WithContext(ctx))
		require(t, err)
		var settings map[string]struct {
			Settings map[string]string `json:"settings"`
		}
		if response.IsError() {
			response.Body.Close()
			t.Fatalf("索引策略读取失败：%d", response.StatusCode)
		}
		err = json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&settings)
		response.Body.Close()
		require(t, err)
		if settings[index].Settings["index.lifecycle.name"] != expected {
			t.Fatal("索引首次策略被覆盖或未来分区未固化策略")
		}
	}
	// 索引不存在时写入必须明确失败，不能自动建立无策略的动态映射；以最长保留期的协议日分区作为尚未建立的共享索引。
	missing, err := contract.EventIndexName("context", 3650, contract.PeriodDay, renewed.Partition)
	require(t, err)
	errs := es.Bulk(ctx, missing, []model.Alert{{EventID: "missing_owned", TenantID: tenants[0]}})
	if len(errs) != 1 || errs[0] == nil {
		t.Fatal("事件索引被自动建立")
	}
}
