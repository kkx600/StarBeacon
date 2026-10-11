//go:build integration

package integration

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/admin"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/platform"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/redis/go-redis/v9"
)

func searchExportHTTP(t *testing.T, client *liveHTTP, path string, query any, status int) ([]byte, http.Header) {
	t.Helper()
	body, err := json.Marshal(query)
	require(t, err)
	req, err := http.NewRequestWithContext(client.ctx, "POST", client.origin+client.prefix+path, bytes.NewReader(body))
	require(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", client.origin)
	req.Header.Set("X-CSRF-Token", client.csrf)
	res, err := client.client.Do(req)
	require(t, err)
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 9<<20))
	require(t, err)
	if res.StatusCode != status {
		t.Fatal("导出接口状态不符合预期", res.StatusCode, status)
	}
	if status != 200 && (res.Header.Get("Content-Disposition") != "" || strings.HasPrefix(res.Header.Get("Content-Type"), "text/csv")) {
		t.Fatal("失败响应提供了可下载的部分文件")
	}
	return raw, res.Header
}

func TestSearchExportRealPITPrunedHistoricalIndices(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	f := newIsolatedDatabase(t, ctx)
	tenant, password := store.RandomID("it_export_pruned_"), store.Token()
	require(t, admin.Bootstrap(ctx, f.Owner, tenant, "历史索引导出验收", tenant, password, "admin"))
	es, err := store.OpenES(os.Getenv("SB_ES_URL"), "")
	require(t, err)
	now := time.Now().UTC()
	currentIDs := map[string]string{}
	for _, dataset := range []string{"alerts", "context"} {
		for _, at := range []time.Time{now.Add(-96 * time.Hour), now.Add(-72 * time.Hour), now} {
			index, err := contract.IndexName(tenant, dataset, at.Format("2006-01-02"))
			require(t, err)
			require(t, es.EnsureIndex(ctx, index, at.Format("2006-01-02")))
			t.Cleanup(func() {
				clean, stop := context.WithTimeout(context.Background(), 5*time.Second)
				defer stop()
				res, err := es.API.Indices.Delete([]string{index}, es.API.Indices.Delete.WithContext(clean))
				require(t, err)
				defer res.Body.Close()
				if res.IsError() {
					t.Error("历史裁剪验收索引无法清理", res.StatusCode)
				}
			})
			doc := model.Alert{EventID: store.RandomID("event_"), TenantID: tenant, Timestamp: at, ObservedAt: at, ReceivedAt: now, SensorID: "sensor_owned", RegistrationID: "reg_owned", SourceGenerationID: "gen_owned", Sequence: "1", RawSHA256: strings.Repeat("a", 64)}
			doc.Event.Kind = "alert"
			if dataset == "context" {
				doc.Event.Kind = "flow"
			}
			doc.Event.Original = `{"private":"raw_must_not_be_exported"}`
			if at.Equal(now) {
				currentIDs[dataset] = doc.EventID
			}
			for _, err := range es.Bulk(ctx, index, []model.Alert{doc}) {
				require(t, err)
			}
			refreshed, err := es.API.Indices.Refresh(es.API.Indices.Refresh.WithIndex(index), es.API.Indices.Refresh.WithContext(ctx))
			require(t, err)
			if refreshed.IsError() {
				t.Fatal("历史裁剪验收索引无法刷新", refreshed.StatusCode)
			}
			refreshed.Body.Close()
		}
	}
	api := &platform.API{DB: f.Runtime, ES: es}
	client := authenticatedFaultHTTP(t, ctx, f.Runtime, api, tenant, password)
	for _, dataset := range []string{"alerts", "context"} {
		path := "/alerts/export"
		if dataset == "context" {
			path = "/traffic/export"
		}
		q := model.SearchRequest{Start: now.Add(-time.Hour), End: now.Add(time.Minute)}
		raw, headers := searchExportHTTP(t, client, path, q, 200)
		rows, err := csv.NewReader(strings.NewReader(strings.TrimPrefix(string(raw), "\ufeff"))).ReadAll()
		require(t, err)
		if len(rows) != 2 || len(rows[0]) != 28 || rows[1][0] != currentIDs[dataset] || headers.Get("X-Export-Rows") != "1" || headers.Get("X-Export-Dataset") != dataset || strings.Contains(string(raw), "raw_must_not_be_exported") {
			t.Fatal("部分历史索引裁剪后的完整元数据不一致", dataset)
		}
		q.Start, q.End = now.Add(-24*time.Hour), now.Add(-23*time.Hour)
		raw, headers = searchExportHTTP(t, client, path, q, 200)
		rows, err = csv.NewReader(strings.NewReader(strings.TrimPrefix(string(raw), "\ufeff"))).ReadAll()
		require(t, err)
		if len(rows) != 1 || len(rows[0]) != 28 || headers.Get("X-Export-Rows") != "0" || headers.Get("X-Export-Dataset") != dataset {
			t.Fatal("全部历史索引裁剪未提供完整空表头", dataset)
		}
	}
	var count int
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT count(*) FROM operation_audits WHERE tenant_id=$1 AND action LIKE 'search.export.prepare.%'`, tenant).Scan(&count))
	if count != 4 {
		t.Fatal("历史裁剪导出的准备审计缺失", count)
	}
}

func TestSearchExportRealPITCSVIsolationRefreshAndAudit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	f := newIsolatedDatabase(t, ctx)
	tenant, foreign, empty, viewer, password := store.RandomID("it_export_"), store.RandomID("it_export_other_"), store.RandomID("it_export_empty_"), store.RandomID("it_export_viewer_"), store.Token()
	for _, v := range []struct{ tenant, user, role string }{{tenant, tenant, "admin"}, {tenant, viewer, "viewer"}, {empty, empty, "admin"}} {
		require(t, admin.Bootstrap(ctx, f.Owner, v.tenant, "检索导出验收", v.user, password, v.role))
	}
	es, err := store.OpenES(os.Getenv("SB_ES_URL"), "")
	require(t, err)
	now := time.Now().UTC()
	indices := map[string]string{}
	for _, target := range []string{tenant, foreign} {
		for _, dataset := range []string{"alerts", "context"} {
			index, err := contract.IndexName(target, dataset, now.Format("2006-01-02"))
			require(t, err)
			indices[target+"/"+dataset] = index
			require(t, es.EnsureIndex(ctx, index, now.Format("2006-01-02")))
			t.Cleanup(func() {
				clean, stop := context.WithTimeout(context.Background(), 5*time.Second)
				defer stop()
				res, err := es.API.Indices.Delete([]string{index}, es.API.Indices.Delete.WithContext(clean))
				require(t, err)
				defer res.Body.Close()
				if res.IsError() {
					t.Error("导出验收索引无法清理", res.StatusCode)
				}
			})
			docs := []model.Alert{}
			count := 1
			if target == tenant && dataset == "alerts" {
				count = 501
			}
			for range count {
				doc := model.Alert{EventID: store.RandomID("event_"), TenantID: target, SensorID: "sensor_owned", RegistrationID: "reg_owned", SourceGenerationID: "gen_owned", Sequence: "18446744073709551615", Timestamp: now, ObservedAt: now, ReceivedAt: now, RawSHA256: strings.Repeat("a", 64)}
				doc.Event.Kind = "alert"
				if dataset == "context" {
					doc.Event.Kind = "flow"
				}
				doc.Event.Original = `{"scope":"raw_material_must_not_be_exported"}`
				doc.Rule.Name = " \t=2+2"
				doc.Network.Protocol = "http"
				doc.Network.Transport = "tcp"
				doc.Destination.Port = 443
				doc.Source.IP = "192.0.2.10"
				doc.HTTP.Path = "/export,\"scope\""
				doc.Suricata.FlowID = "18446744073709551615"
				docs = append(docs, doc)
			}
			for _, err := range es.Bulk(ctx, index, docs) {
				require(t, err)
			}
			res, err := es.API.Indices.Refresh(es.API.Indices.Refresh.WithIndex(index), es.API.Indices.Refresh.WithContext(ctx))
			require(t, err)
			if res.IsError() {
				t.Fatal("导出验收索引未刷新")
			}
			res.Body.Close()
		}
	}
	redisOptions, err := redis.ParseURL(os.Getenv("SB_REDIS_URL"))
	require(t, err)
	cache := redis.NewClient(redisOptions)
	defer cache.Close()
	target, err := url.Parse(os.Getenv("SB_ES_URL"))
	require(t, err)
	proxy := httputil.NewSingleHostReverseProxy(target)
	var injected atomic.Bool
	proxy.ModifyResponse = func(res *http.Response) error {
		if res.Request.URL.Path != "/_search" || !injected.CompareAndSwap(false, true) {
			return nil
		}
		doc := model.Alert{EventID: store.RandomID("late_"), TenantID: tenant, Timestamp: now, ObservedAt: now, ReceivedAt: now}
		doc.Event.Kind = "alert"
		doc.Network.Protocol, doc.Network.Transport, doc.Destination.Port = "http", "tcp", 443
		for _, err := range es.Bulk(ctx, indices[tenant+"/alerts"], []model.Alert{doc}) {
			if err != nil {
				return err
			}
		}
		refreshed, err := es.API.Indices.Refresh(es.API.Indices.Refresh.WithIndex(indices[tenant+"/alerts"]), es.API.Indices.Refresh.WithContext(ctx))
		if err != nil {
			return err
		}
		defer refreshed.Body.Close()
		if refreshed.IsError() {
			t.Error("快照期间索引刷新失败")
		}
		return nil
	}
	upstream := httptest.NewServer(proxy)
	defer upstream.Close()
	snapshotES, err := store.OpenES(upstream.URL, "")
	require(t, err)
	api := &platform.API{DB: f.Runtime, ES: snapshotES, Redis: cache}
	adminHTTP := authenticatedFaultHTTP(t, ctx, f.Runtime, api, tenant, password)
	q := model.SearchRequest{Start: now.Add(-time.Hour), End: now.Add(time.Minute), Filter: "http && tcp.port == 443"}
	raw, headers := searchExportHTTP(t, adminHTTP, "/alerts/export", q, 200)
	digest := sha256.Sum256(raw)
	rows, err := csv.NewReader(strings.NewReader(strings.TrimPrefix(string(raw), "\ufeff"))).ReadAll()
	require(t, err)
	if len(rows) != 502 || headers.Get("X-Export-Rows") != "501" || headers.Get("X-Content-SHA256") != hex.EncodeToString(digest[:]) || headers.Get("Content-Length") != strconv.Itoa(len(raw)) || !strings.HasPrefix(headers.Get("Content-Disposition"), "attachment;") || headers.Get("X-Export-Dataset") != "alerts" || strings.Contains(string(raw), "raw_material_must_not_be_exported") || rows[1][8] != "'18446744073709551615" || !strings.HasPrefix(rows[1][21], "'") || !injected.Load() {
		t.Fatal("实际 CSV、快照范围、长整数或元数据约束不一致")
	}
	current, err := es.Search(ctx, tenant, q)
	require(t, err)
	if current.Total != 502 {
		t.Fatal("快照期间写入的合格记录未进入后续新查询", current.Total)
	}
	viewerHTTP := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime, ES: es, Redis: cache}, viewer, password)
	trafficQuery := model.TrafficSearchRequest{SearchRequest: q, EventKind: "flow", SensorID: "sensor_owned", RegistrationID: "reg_owned", GenerationID: "gen_owned", FlowID: "18446744073709551615"}
	_, headers = searchExportHTTP(t, viewerHTTP, "/traffic/export", trafficQuery, 200)
	if headers.Get("X-Export-Rows") != "1" || headers.Get("X-Export-Dataset") != "context" {
		t.Fatal("协议导出来源或租户隔离错误")
	}
	emptyHTTP := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime, ES: es}, empty, password)
	raw, headers = searchExportHTTP(t, emptyHTTP, "/alerts/export", q, 200)
	if headers.Get("X-Export-Rows") != "0" || strings.Count(string(raw), "\r\n") != 1 {
		t.Fatal("无索引空快照不符合契约")
	}
	var count int
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT count(*) FROM operation_audits WHERE tenant_id=$1 AND action LIKE 'search.export.prepare.%'`, tenant).Scan(&count))
	if count != 2 {
		t.Fatal("导出准备审计缺失", count)
	}
	if cache.Exists(ctx, "sb:search-export:"+tenant).Val() != 0 {
		t.Fatal("完成导出后租约未释放")
	}
	for _, path := range []string{"/alerts/export", "/traffic/export"} {
		adminHTTP.request("POST", path, "", map[string]any{"start": q.Start, "end": q.End, "index": "*"}, nil, 400)
		adminHTTP.request("POST", path, "", map[string]any{"start": q.Start, "end": q.Start}, nil, 400)
	}
	unavailable := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime}, tenant, password)
	searchExportHTTP(t, unavailable, "/alerts/export", q, 503)
	if err := f.Runtime.RecordSearchExport(ctx, model.Principal{}, "invalid", "../request"); err == nil {
		t.Fatal("无效导出审计未拒绝")
	}
}

func TestSearchExportRealFailuresRevocationAndDistributedQuota(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()
	f := newIsolatedDatabase(t, ctx)
	tenant, password := store.RandomID("it_export_failure_"), store.Token()
	require(t, admin.Bootstrap(ctx, f.Owner, tenant, "导出故障验收", tenant, password, "admin"))
	es, err := store.OpenES(os.Getenv("SB_ES_URL"), "")
	require(t, err)
	now := time.Now().UTC()
	index, err := contract.IndexName(tenant, "alerts", now.Format("2006-01-02"))
	require(t, err)
	require(t, es.EnsureIndex(ctx, index, now.Format("2006-01-02")))
	t.Cleanup(func() {
		clean, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		res, err := es.API.Indices.Delete([]string{index}, es.API.Indices.Delete.WithContext(clean))
		require(t, err)
		defer res.Body.Close()
	})
	doc := model.Alert{TenantID: tenant, EventID: store.RandomID("event_"), Timestamp: now, ObservedAt: now, ReceivedAt: now}
	doc.Event.Kind = "alert"
	for _, err := range es.Bulk(ctx, index, []model.Alert{doc}) {
		require(t, err)
	}
	refreshed, err := es.API.Indices.Refresh(es.API.Indices.Refresh.WithIndex(index), es.API.Indices.Refresh.WithContext(ctx))
	require(t, err)
	refreshed.Body.Close()
	var mode atomic.Int32
	target, err := url.Parse(os.Getenv("SB_ES_URL"))
	require(t, err)
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.ModifyResponse = func(res *http.Response) error {
		if res.Request.URL.Path != "/_search" || mode.Load() == 0 {
			return nil
		}
		if mode.Load() == 3 {
			_, err := f.Owner.Pool.Exec(ctx, `UPDATE users SET active=false,revision=revision+1 WHERE tenant_id=$1 AND username=$2`, tenant, tenant)
			return err
		}
		// ES 响应实际协商 gzip；故障注入须先解码，避免把压缩字节当作 JSON。
		var reader io.Reader = res.Body
		if res.Header.Get("Content-Encoding") == "gzip" {
			decoded, err := gzip.NewReader(res.Body)
			if err != nil {
				return err
			}
			defer decoded.Close()
			reader = decoded
		}
		var body map[string]any
		err := json.NewDecoder(reader).Decode(&body)
		res.Body.Close()
		if err != nil {
			return err
		}
		if mode.Load() == 1 {
			body["timed_out"] = true
		} else {
			body["hits"].(map[string]any)["total"].(map[string]any)["value"] = 10001
		}
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		res.Body = io.NopCloser(bytes.NewReader(raw))
		res.ContentLength = int64(len(raw))
		res.Header.Del("Content-Length")
		res.Header.Del("Content-Encoding")
		return nil
	}
	upstream := httptest.NewServer(proxy)
	defer upstream.Close()
	checked, err := store.OpenES(upstream.URL, "")
	require(t, err)
	redisOptions, err := redis.ParseURL(os.Getenv("SB_REDIS_URL"))
	require(t, err)
	cache := redis.NewClient(redisOptions)
	defer cache.Close()
	client := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime, ES: checked, Redis: cache}, tenant, password)
	q := model.SearchRequest{Start: now.Add(-time.Hour), End: now.Add(time.Minute)}
	for _, tc := range []struct {
		mode   int32
		status int
	}{{1, 503}, {2, 413}} {
		mode.Store(tc.mode)
		searchExportHTTP(t, client, "/alerts/export", q, tc.status)
	}
	mode.Store(0)
	require(t, cache.Set(ctx, "sb:search-export:"+tenant, "owned_other_execution", time.Minute).Err())
	searchExportHTTP(t, client, "/alerts/export", q, 429)
	if cache.Get(ctx, "sb:search-export:"+tenant).Val() != "owned_other_execution" {
		t.Fatal("配额拒绝删除了其它执行者租约")
	}
	require(t, cache.Del(ctx, "sb:search-export:"+tenant).Err())
	brokenOptions := *redisOptions
	brokenOptions.Addr = "127.0.0.1:1"
	brokenCache := redis.NewClient(&brokenOptions)
	defer brokenCache.Close()
	unavailable := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime, ES: es, Redis: brokenCache}, tenant, password)
	searchExportHTTP(t, unavailable, "/alerts/export", q, 503)
	mode.Store(3)
	searchExportHTTP(t, client, "/alerts/export", q, 401)
	var count int
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT count(*) FROM operation_audits WHERE tenant_id=$1 AND action LIKE 'search.export.prepare.%'`, tenant).Scan(&count))
	if count != 0 {
		t.Fatal("失败或撤权被记录为已准备导出", count)
	}
}
