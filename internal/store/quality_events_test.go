package store

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/detectionquality"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/qualityevent"
)

func TestQualityEventSearchPinsDatasetTenantRegistrationAndCompleteness(t *testing.T) {
	now := time.Now().UTC()
	var tr detectionquality.Tracker
	tr.Start("engine_owned", strings.Repeat("a", 64), now.Add(-10*time.Second))
	for i := range 2 {
		at := now.Add(time.Duration(i*5-9) * time.Second)
		raw, _ := json.Marshal(map[string]any{"event_type": "stats", "timestamp": at.Format(time.RFC3339Nano), "stats": map[string]any{"capture": map[string]int{"errors": i}}})
		tr.Observe(raw, at)
	}
	report := tr.Snapshot(now, true)
	event, err := qualityevent.New("tenant_owned", "probe_owned", "reg_owned", report, qualityevent.Classify(report), now)
	if err != nil {
		t.Fatal(err)
	}
	q := model.SearchRequest{Start: now.Add(-time.Hour), End: now.Add(time.Hour), Page: 1, PageSize: 20}
	for _, mode := range []string{"valid", "empty", "tamper", "scope", "kind", "incomplete", "transport"} {
		t.Run(mode, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !strings.Contains(r.URL.Path, "sb-context-tenant_owned-*,-sb-context-tenant_owned-*-*") || r.URL.Query().Get("allow_partial_search_results") != "false" {
					t.Error("索引未排除同前缀其他租户", r.URL.Path)
				}
				var body map[string]any
				_ = json.NewDecoder(r.Body).Decode(&body)
				raw, _ := json.Marshal(body)
				for _, part := range []string{"starbeacon.sensor_quality", "probe_owned", "reg_owned", "quality", "limitation"} {
					if !strings.Contains(string(raw), part) {
						t.Error("缺少固定过滤", part)
					}
				}
				if mode == "transport" {
					w.WriteHeader(503)
					return
				}
				d := event.Document()
				if mode == "tamper" {
					d.Event.Original = "{}"
				}
				if mode == "scope" {
					d.RegistrationID = "reg_other"
				}
				if mode == "kind" {
					d.Rule.ID = "policy"
				}
				hits := []any{map[string]any{"_id": d.EventID, "_index": "sb-context-tenant_owned-" + now.Format("2006.01.02"), "_source": d}}
				if mode == "empty" {
					hits = []any{}
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"timed_out": mode == "incomplete", "_shards": map[string]int{"total": 1, "successful": 1, "failed": 0}, "hits": map[string]any{"total": map[string]any{"value": len(hits), "relation": "eq"}, "hits": hits}})
			}))
			defer server.Close()
			es, _ := OpenES(server.URL, "")
			got, err := es.QualityEvents(context.Background(), "tenant_owned", "probe_owned", "reg_owned", "limitation", q)
			if (err == nil) != (mode == "valid" || mode == "empty") {
				t.Fatal("不完整事件被接受或有效事件被拒绝", err)
			}
			if mode == "valid" && (got.Total != "1" || len(got.Items) != 1 || got.Items[0].ID != event.ID) {
				t.Fatal(got)
			}
			if mode == "empty" && (got.Total != "0" || got.Items == nil) {
				t.Fatal(got)
			}
		})
	}
	if err := (&Postgres{}).FinishQuality(context.Background(), QualityLease{}, true); err == nil {
		t.Fatal("空租约进入依赖")
	}
}
