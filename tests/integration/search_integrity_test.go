//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/admin"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/platform"
	"github.com/kkx600/StarBeacon/internal/store"
)

func TestSearchRealEvidenceRejectsIncompleteDependencyResults(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	f := newIsolatedDatabase(t, ctx)
	tenant, foreign, password := store.RandomID("it_search_"), store.RandomID("it_search_other_"), store.Token()
	require(t, admin.Bootstrap(ctx, f.Owner, tenant, "检索完整性验收", tenant, password, "admin"))
	es, err := store.OpenES(os.Getenv("SB_ES_URL"), "")
	require(t, err)
	require(t, es.EnsurePolicy(ctx))
	now := time.Now().UTC()
	for _, target := range []string{tenant, foreign} {
		index, err := contract.IndexName(target, "alerts", now.Format("2006-01-02"))
		require(t, err)
		require(t, es.EnsureIndex(ctx, index, now.Format("2006-01-02")))
		t.Cleanup(func() {
			clean, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			response, err := es.API.Indices.Delete([]string{index}, es.API.Indices.Delete.WithContext(clean))
			require(t, err)
			defer response.Body.Close()
			if response.IsError() {
				t.Error("无法清理检索验收索引", response.StatusCode)
			}
		})
		doc := model.Alert{EventID: store.RandomID("event_"), TenantID: target, SensorID: "sensor_owned", Timestamp: now, ReceivedAt: now, ObservedAt: now}
		doc.Event.Kind, doc.Event.Original, doc.Rule.Name, doc.Severity = "alert", `{"scope":"search_fixture"}`, "检索受控记录", "medium"
		for _, err := range es.Bulk(ctx, index, []model.Alert{doc}) {
			require(t, err)
		}
		refreshed, err := es.API.Indices.Refresh(es.API.Indices.Refresh.WithIndex(index), es.API.Indices.Refresh.WithContext(ctx))
		require(t, err)
		if refreshed.IsError() {
			t.Fatal("检索验收索引未刷新", refreshed.StatusCode)
		}
		refreshed.Body.Close()
	}
	target, err := url.Parse(os.Getenv("SB_ES_URL"))
	require(t, err)
	var fault atomic.Int32
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.ModifyResponse = func(response *http.Response) error {
		if fault.Load() == 0 {
			return nil
		}
		var original map[string]any
		err := json.NewDecoder(response.Body).Decode(&original)
		response.Body.Close()
		if err != nil {
			return err
		}
		// 从实际 ES 回执注入失败标志，不以静态模拟结果代替成功检索。
		switch fault.Load() {
		case 1:
			original["timed_out"] = true
		case 2:
			original["_shards"].(map[string]any)["failed"] = 1
		case 3:
			original["hits"].(map[string]any)["total"].(map[string]any)["relation"] = "gte"
		case 4:
			original["hits"].(map[string]any)["hits"] = []any{}
		case 5:
			original["hits"].(map[string]any)["hits"].([]any)[0].(map[string]any)["_source"].(map[string]any)["tenant_id"] = foreign
		}
		body, err := json.Marshal(original)
		if err != nil {
			return err
		}
		response.Body, response.ContentLength = io.NopCloser(bytes.NewReader(body)), int64(len(body))
		response.Header.Del("Content-Length")
		return nil
	}
	server := httptest.NewServer(proxy)
	defer server.Close()
	checkedES, err := store.OpenES(server.URL, "")
	require(t, err)
	client := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime, ES: checkedES}, tenant, password)
	query := model.SearchRequest{Start: now.Add(-time.Hour), End: now.Add(time.Minute)}
	var result model.SearchResult
	client.request("POST", "/alerts/search", "", query, &result, 200)
	if result.Total != 1 || len(result.Items) != 1 || result.Items[0].TenantID != tenant {
		t.Fatal("真实 ES 命中未按租户限定", result)
	}
	for _, mode := range []int32{1, 2, 3, 4, 5} {
		fault.Store(mode)
		var failure struct {
			Code  string          `json:"code"`
			Items json.RawMessage `json:"items"`
		}
		client.request("POST", "/alerts/search", "", query, &failure, 503)
		if failure.Code != "search_unavailable" || failure.Items != nil {
			t.Fatal("失败检索返回了可误用的告警结果", mode, failure)
		}
	}
	fault.Store(0)
	client.request("POST", "/alerts/search", "", query, &result, 200)
	if result.Total != 1 {
		t.Fatal("恢复后未读回原始记录", result)
	}
	query.SourceIP = "192.0.2.255"
	client.request("POST", "/alerts/search", "", query, &result, 200)
	if result.Total != 0 || len(result.Items) != 0 {
		t.Fatal("真实空结果未与失败区分", result)
	}
}
