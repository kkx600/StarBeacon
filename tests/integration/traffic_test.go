//go:build integration

package integration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/admin"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/platform"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/traffic"
)

func TestTrafficHTTPRealIndexIsolationAndViewerMetadata(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
	defer cancel()
	f := newIsolatedDatabase(t, ctx)
	tenant, foreign, viewer, password := store.RandomID("it_traffic_"), store.RandomID("it_traffic_other_"), store.RandomID("it_traffic_viewer_"), store.Token()
	require(t, admin.Bootstrap(ctx, f.Owner, tenant, "流量检索验收", tenant, password, "admin"))
	require(t, admin.Bootstrap(ctx, f.Owner, tenant, "流量检索验收", viewer, password, "viewer"))
	es, err := store.OpenES(os.Getenv("SB_ES_URL"), "")
	require(t, err)
	now := time.Now().UTC()
	for _, target := range []string{tenant, foreign} {
		index, err := contract.IndexName(target, "context", now.Format("2006-01-02"))
		require(t, err)
		require(t, es.EnsureIndex(ctx, index, now.Format("2006-01-02")))
		t.Cleanup(func() {
			clean, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			res, err := es.API.Indices.Delete([]string{index}, es.API.Indices.Delete.WithContext(clean))
			require(t, err)
			defer res.Body.Close()
			if res.IsError() {
				t.Error("流量验收索引无法清理", res.StatusCode)
			}
		})
		doc := model.Alert{EventID: store.RandomID("flow_"), TenantID: target, SensorID: "sensor_owned", RegistrationID: "reg_owned", SourceGenerationID: "gen_owned", Timestamp: now, ReceivedAt: now, ObservedAt: now}
		doc.Event.Kind, doc.Event.Original = "flow", `{"event_type":"flow","flow":{"start":"2026-10-03T01:00:00Z","end":"2026-10-03T01:00:01Z","bytes_toserver":18446744073709551615,"bytes_toclient":0,"pkts_toserver":9,"pkts_toclient":0},"ether":{"src_macs":["02:00:00:00:00:01"]}}`
		doc.Network.Protocol, doc.Network.Transport, doc.Suricata.FlowID = "http", "tcp", "18446744073709551615"
		for _, err := range es.Bulk(ctx, index, []model.Alert{doc}) {
			require(t, err)
		}
		refreshed, err := es.API.Indices.Refresh(es.API.Indices.Refresh.WithIndex(index), es.API.Indices.Refresh.WithContext(ctx))
		require(t, err)
		if refreshed.IsError() {
			t.Fatal("流量验收索引未刷新", refreshed.StatusCode)
		}
		refreshed.Body.Close()
	}
	api := &platform.API{DB: f.Runtime, ES: es}
	adminHTTP := authenticatedFaultHTTP(t, ctx, f.Runtime, api, tenant, password)
	viewerHTTP := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime, ES: es}, viewer, password)
	query := model.TrafficSearchRequest{SearchRequest: model.SearchRequest{Start: now.Add(-time.Hour), End: now.Add(time.Minute)}, EventKind: "flow", SensorID: "sensor_owned", RegistrationID: "reg_owned", GenerationID: "gen_owned", FlowID: "18446744073709551615"}
	var result traffic.Result
	for _, client := range []*liveHTTP{adminHTTP, viewerHTTP} {
		client.request("POST", "/traffic/search", "", query, &result, 200)
		if result.Total != 1 || len(result.Items) != 1 || result.Items[0].TenantID != tenant || result.Items[0].Details.Flow == nil || result.Items[0].Details.Flow.BytesToServer != "18446744073709551615" || result.Items[0].Details.Flow.BytesToClient != "0" || len(result.Items[0].Details.SourceMACs) != 1 {
			t.Fatal("流量元数据或租户隔离失败")
		}
		if (client == viewerHTTP) != (result.Items[0].Event.Original == "") {
			t.Fatal("原始 EVE 权限未受角色限制")
		}
		var fields struct {
			Dataset string `json:"dataset"`
			Fields  []struct {
				Name string `json:"name"`
			} `json:"fields"`
		}
		client.request("GET", "/traffic/fields", "", nil, &fields, 200)
		if fields.Dataset != "context" || len(fields.Fields) == 0 {
			t.Fatal("流量字段目录缺失")
		}
		for _, field := range fields.Fields {
			if field.Name == "severity" || field.Name == "rule.name" {
				t.Fatal("字段目录混入告警字段")
			}
		}
	}
	query.SensorID = "sensor_foreign"
	adminHTTP.request("POST", "/traffic/search", "", query, &result, 200)
	if result.Total != 0 || len(result.Items) != 0 {
		t.Fatal("无匹配记录未返回真实空结果")
	}
	for _, invalid := range []any{map[string]any{"start": now.Add(-time.Hour), "end": now, "event_kind": "alert"}, map[string]any{"start": now.Add(-time.Hour), "end": now, "sensor_registration_id": "reg_owned"}, map[string]any{"start": now.Add(-time.Hour), "end": now, "flow_id": "01"}, map[string]any{"start": now.Add(-time.Hour), "end": now, "index": "*"}} {
		adminHTTP.request("POST", "/traffic/search", "", invalid, nil, 400)
	}
	unavailable := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime}, tenant, password)
	unavailable.request("POST", "/traffic/search", "", query, nil, 503)
	failingServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503) }))
	defer failingServer.Close()
	brokenES, err := store.OpenES(failingServer.URL, "")
	require(t, err)
	broken := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime, ES: brokenES}, tenant, password)
	broken.request("POST", "/traffic/search", "", query, nil, 503)
}
