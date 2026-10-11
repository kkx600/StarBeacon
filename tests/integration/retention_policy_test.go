//go:build integration

package integration

import (
	"context"
	"encoding/json"
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
			clean, stop := context.WithTimeout(context.Background(), 10*time.Second)
			defer stop()
			response, err := es.API.Indices.Delete([]string{"sb-alerts-" + tenant + "-*", "sb-context-" + tenant + "-*"}, es.API.Indices.Delete.WithContext(clean))
			if err == nil {
				response.Body.Close()
			}
			require(t, owner.TenantTx(clean, tenant, func(tx pgx.Tx) error {
				for _, table := range []string{"retention_changes", "retention_previews", "replay_samples", "operation_audits", "login_audits", "retention_policies"} {
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
	server := httptest.NewServer(httpapi.Middleware(api.Handler()))
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
	if page.DefaultDays != 180 || len(page.Items) != 11 || len(page.Catalog) != 11 {
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
	if _, err := db.EventRetention(ctx, tenants[0], "other"); err == nil {
		t.Fatal("未知事件流读取了默认策略")
	}
	firstDay, secondDay := time.Now().UTC().AddDate(0, 0, -1).Format("2006-01-02"), time.Now().UTC().Format("2006-01-02")
	firstIndex, err := contract.IndexName(tenants[0], "alerts", firstDay)
	require(t, err)
	require(t, es.EnsureIndex(ctx, firstIndex, firstDay))
	candidate = retention.Candidate{Category: "alerts", Days: 365, ExpectedRevision: 1, ApplyMode: "future"}
	a.request("POST", "/retention-policies/preview", "", candidate, &preview, 200)
	a.request("PUT", "/retention-policies/alerts", store.RandomID("key_"), retention.Change{PreviewID: preview.ID, Candidate: candidate}, nil, 200)
	days, err := db.EventRetention(ctx, tenants[0], "alerts")
	require(t, err)
	if days != 365 {
		t.Fatal("索引保留期未读取租户策略")
	}
	fresh, err := store.OpenES(os.Getenv("SB_ES_URL"), os.Getenv("SB_ES_API_KEY"))
	require(t, err)
	require(t, fresh.EnsureIndexRetention(ctx, firstIndex, firstDay, days))
	secondIndex, err := contract.IndexName(tenants[0], "alerts", secondDay)
	require(t, err)
	require(t, fresh.EnsureIndexRetention(ctx, secondIndex, secondDay, days))
	for index, expected := range map[string]string{firstIndex: "sb-default-180d", secondIndex: "sb-retention-365d"} {
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
	// 索引不存在时写入必须明确失败，不能自动建立无策略的动态映射。
	missing, err := contract.IndexName(tenants[0], "context", secondDay)
	require(t, err)
	errs := es.Bulk(ctx, missing, []model.Alert{{EventID: "missing_owned", TenantID: tenants[0]}})
	if len(errs) != 1 || errs[0] == nil {
		t.Fatal("事件索引被自动建立")
	}
}
