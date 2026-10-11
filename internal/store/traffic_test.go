package store

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/model"
)

func TestTrafficSearchBoundsAndSourceScope(t *testing.T) {
	now := time.Now().UTC()
	base := model.TrafficSearchRequest{SearchRequest: model.SearchRequest{Start: now.Add(-time.Hour), End: now.Add(time.Minute)}}
	for name, mutate := range map[string]func(*model.TrafficSearchRequest){
		"alert_kind":                      func(q *model.TrafficSearchRequest) { q.EventKind = "alert" },
		"unknown_kind":                    func(q *model.TrafficSearchRequest) { q.EventKind = "stats" },
		"alert_keyword":                   func(q *model.TrafficSearchRequest) { q.Keyword = "告警" },
		"alert_severity":                  func(q *model.TrafficSearchRequest) { q.Severity = "high" },
		"alert_filter":                    func(q *model.TrafficSearchRequest) { q.Filter = "severity == high" },
		"alert_filter_alias":              func(q *model.TrafficSearchRequest) { q.Filter = "tcp or (suricata.sid == 1)" },
		"sensor_wildcard":                 func(q *model.TrafficSearchRequest) { q.SensorID = "sensor*" },
		"registration_wildcard":           func(q *model.TrafficSearchRequest) { q.RegistrationID = "reg*" },
		"generation_wildcard":             func(q *model.TrafficSearchRequest) { q.GenerationID = "gen*" },
		"registration_without_sensor":     func(q *model.TrafficSearchRequest) { q.RegistrationID = "reg_1" },
		"generation_without_registration": func(q *model.TrafficSearchRequest) { q.SensorID, q.GenerationID = "sensor_1", "gen_1" },
		"generation_without_sensor":       func(q *model.TrafficSearchRequest) { q.RegistrationID, q.GenerationID = "reg_1", "gen_1" },
		"flow_overflow":                   func(q *model.TrafficSearchRequest) { q.FlowID = "18446744073709551616" },
		"flow_negative":                   func(q *model.TrafficSearchRequest) { q.FlowID = "-1" },
		"flow_leading_zero":               func(q *model.TrafficSearchRequest) { q.FlowID = "01" },
		"flow_fraction":                   func(q *model.TrafficSearchRequest) { q.FlowID = "1.0" },
		"flow_plus":                       func(q *model.TrafficSearchRequest) { q.FlowID = "+1" },
		"missing_window":                  func(q *model.TrafficSearchRequest) { q.End = time.Time{} },
	} {
		t.Run(name, func(t *testing.T) {
			q := base
			mutate(&q)
			if ValidateTrafficSearch(&q) == nil {
				t.Fatal("无效流量条件被接受")
			}
			if _, err := (&Elasticsearch{}).SearchTraffic(context.Background(), "tenant", q); err == nil {
				t.Fatal("无效请求进入存储查询")
			}
		})
	}
	for _, kind := range append([]string{""}, trafficKinds...) {
		q := base
		q.EventKind, q.SensorID, q.RegistrationID, q.GenerationID, q.FlowID = kind, "sensor_1", "reg_1", "gen_1", "18446744073709551615"
		q.SourceIP = "::ffff:192.0.2.1"
		if err := ValidateTrafficSearch(&q); err != nil {
			t.Fatal(err)
		}
		if q.Page != 1 || q.PageSize != 20 || q.SourceIP != "192.0.2.1" {
			t.Fatal("规范化结果错误", q)
		}
	}
}

func TestTrafficSearchUsesOwnedContextAndExactSourceFilters(t *testing.T) {
	now := time.Now().UTC()
	q := model.TrafficSearchRequest{SearchRequest: model.SearchRequest{Start: now.Add(-time.Hour), End: now.Add(time.Minute)}, SensorID: "sensor_1", RegistrationID: "reg_1", GenerationID: "gen_1", FlowID: "18446744073709551615"}
	kind, sourceKind := "http", "http"
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path != "/sb-context-tenant_1-*/_search" || r.URL.Query().Get("allow_partial_search_results") != "false" || r.URL.Query().Get("ignore_unavailable") == "true" {
			t.Error("流量查询未限定完整租户上下文索引", r.URL)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		filters := body["query"].(map[string]any)["bool"].(map[string]any)["filter"].([]any)
		for field, want := range map[string]string{"tenant_id": "tenant_1", "sensor_id": "sensor_1", "sensor_registration_id": "reg_1", "source_generation_id": "gen_1", "suricata.flow_id": "18446744073709551615"} {
			found := false
			for _, filter := range filters {
				term, ok := filter.(map[string]any)["term"].(map[string]any)
				if ok && term[field] == want {
					found = true
				}
			}
			if !found {
				t.Error("来源筛选缺失", field)
			}
		}
		serialized, _ := json.Marshal(filters)
		if kind != "" && !strings.Contains(string(serialized), `"event.kind":"`+kind+`"`) {
			t.Error("记录类型未被强制限定")
		}
		if kind == "" && (!strings.Contains(string(serialized), `"event.kind":[`) || strings.Contains(string(serialized), `"alert"`)) {
			t.Error("全记录检索混入告警")
		}
		w.Header().Set("X-Elastic-Product", "Elasticsearch")
		w.Header().Set("Content-Type", "application/json")
		row := model.Alert{TenantID: "tenant_1", EventID: "event_1", Timestamp: now}
		row.Event.Kind = sourceKind
		_ = json.NewEncoder(w).Encode(map[string]any{"timed_out": false, "_shards": map[string]int{"total": 1, "successful": 1, "failed": 0}, "hits": map[string]any{"total": map[string]any{"value": 1, "relation": "eq"}, "hits": []any{map[string]any{"_id": row.EventID, "_index": "sb-context-tenant_1-" + now.Format("2006.01.02"), "_source": row}}}})
	}))
	defer server.Close()
	es, err := OpenES(server.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	q.EventKind = kind
	result, err := es.SearchTraffic(context.Background(), "tenant_1", q)
	if err != nil || result.Total != 1 || len(result.Items) != 1 {
		t.Fatal("合法上下文检索失败", result, err)
	}
	kind, q.EventKind = "", ""
	if _, err := es.SearchTraffic(context.Background(), "tenant_1", q); err != nil {
		t.Fatal(err)
	}
	sourceKind = "alert"
	result, err = es.SearchTraffic(context.Background(), "tenant_1", q)
	if err == nil || len(result.Items) != 0 || result.Total != 0 {
		t.Fatal("上下文回执中的告警未被拒绝")
	}
	if requests != 3 {
		t.Fatal("查询次数不一致", requests)
	}
}
