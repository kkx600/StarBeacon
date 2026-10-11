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

func TestSearchRejectsPartialCountsAndForeignEvidence(t *testing.T) {
	start := time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)
	query := model.SearchRequest{Start: start, End: start.Add(time.Hour), Page: 1, PageSize: 20}
	hit := func() map[string]any {
		return map[string]any{"_id": "event_owned", "_index": "sb-alerts-tenant_owned-2026.10.03", "_source": map[string]any{"event_id": "event_owned", "tenant_id": "tenant_owned", "@timestamp": start.Add(time.Minute), "event": map[string]string{"kind": "alert"}}}
	}
	valid := func() map[string]any {
		return map[string]any{"timed_out": false, "_shards": map[string]any{"total": 2, "successful": 2, "failed": 0}, "hits": map[string]any{"total": map[string]any{"value": 1, "relation": "eq"}, "hits": []any{hit()}}}
	}
	type mutation func(map[string]any)
	tests := []struct {
		name  string
		alter mutation
	}{
		{"timeout", func(v map[string]any) { v["timed_out"] = true }},
		{"timeout_absent", func(v map[string]any) { delete(v, "timed_out") }},
		{"shards_absent", func(v map[string]any) { delete(v, "_shards") }},
		{"shard_failed", func(v map[string]any) { v["_shards"].(map[string]any)["failed"] = 1 }},
		{"shard_incomplete", func(v map[string]any) { v["_shards"].(map[string]any)["successful"] = 1 }},
		{"shard_total_absent", func(v map[string]any) { delete(v["_shards"].(map[string]any), "total") }},
		{"shard_success_absent", func(v map[string]any) { delete(v["_shards"].(map[string]any), "successful") }},
		{"shard_failed_absent", func(v map[string]any) { delete(v["_shards"].(map[string]any), "failed") }},
		{"shard_total_negative", func(v map[string]any) { v["_shards"].(map[string]any)["total"] = -1 }},
		{"approximate_total", func(v map[string]any) { v["hits"].(map[string]any)["total"].(map[string]any)["relation"] = "gte" }},
		{"count_absent", func(v map[string]any) { delete(v["hits"].(map[string]any)["total"].(map[string]any), "value") }},
		{"count_negative", func(v map[string]any) { v["hits"].(map[string]any)["total"].(map[string]any)["value"] = -1 }},
		{"rows_absent", func(v map[string]any) { delete(v["hits"].(map[string]any), "hits") }},
		{"rows_incomplete", func(v map[string]any) { v["hits"].(map[string]any)["hits"] = []any{} }},
		{"foreign_index", func(v map[string]any) {
			v["hits"].(map[string]any)["hits"].([]any)[0].(map[string]any)["_index"] = "sb-alerts-tenant_foreign-2026.10.03"
		}},
		{"noncanonical_index", func(v map[string]any) {
			v["hits"].(map[string]any)["hits"].([]any)[0].(map[string]any)["_index"] = "sb-alerts-tenant_owned-2026.10.03-alias"
		}},
		{"mismatched_id", func(v map[string]any) {
			v["hits"].(map[string]any)["hits"].([]any)[0].(map[string]any)["_id"] = "event_foreign"
		}},
		{"invalid_id", func(v map[string]any) {
			v["hits"].(map[string]any)["hits"].([]any)[0].(map[string]any)["_id"] = "../event"
		}},
		{"foreign_source", func(v map[string]any) {
			v["hits"].(map[string]any)["hits"].([]any)[0].(map[string]any)["_source"].(map[string]any)["tenant_id"] = "tenant_foreign"
		}},
		{"missing_source", func(v map[string]any) {
			delete(v["hits"].(map[string]any)["hits"].([]any)[0].(map[string]any), "_source")
		}},
		{"other_event", func(v map[string]any) {
			v["hits"].(map[string]any)["hits"].([]any)[0].(map[string]any)["_source"].(map[string]any)["event"] = map[string]string{"kind": "flow"}
		}},
		{"before_window", func(v map[string]any) {
			v["hits"].(map[string]any)["hits"].([]any)[0].(map[string]any)["_source"].(map[string]any)["@timestamp"] = start.Add(-time.Nanosecond)
		}},
		{"at_exclusive_end", func(v map[string]any) {
			v["hits"].(map[string]any)["hits"].([]any)[0].(map[string]any)["_source"].(map[string]any)["@timestamp"] = query.End
		}},
		{"duplicate_identity", func(v map[string]any) {
			v["hits"].(map[string]any)["total"].(map[string]any)["value"] = 2
			v["hits"].(map[string]any)["hits"] = []any{hit(), hit()}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body := valid()
			tc.alter(body)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _ = json.NewEncoder(w).Encode(body) }))
			defer server.Close()
			es, err := OpenES(server.URL, "")
			if err != nil {
				t.Fatal(err)
			}
			result, err := es.Search(context.Background(), "tenant_owned", query)
			if err == nil || len(result.Items) != 0 || result.Total != 0 {
				t.Fatal("不完整结果或错误来源暴露为成功告警", result, err)
			}
		})
	}
	for _, tc := range []struct {
		name  string
		total int
		page  int
		items []any
	}{
		{"one_owned", 1, 1, []any{hit()}}, {"empty_indices", 0, 1, []any{}}, {"after_last_page", 1, 2, []any{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := valid()
			body["hits"].(map[string]any)["total"].(map[string]any)["value"] = tc.total
			body["hits"].(map[string]any)["hits"] = tc.items
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get("allow_partial_search_results") != "false" || r.URL.Query().Get("ignore_unavailable") == "true" {
					t.Error("读取允许返回不完整索引")
				}
				_ = json.NewEncoder(w).Encode(body)
			}))
			defer server.Close()
			es, err := OpenES(server.URL, "")
			if err != nil {
				t.Fatal(err)
			}
			q := query
			q.Page = tc.page
			result, err := es.Search(context.Background(), "tenant_owned", q)
			if err != nil || result.Total != int64(tc.total) || len(result.Items) != len(tc.items) {
				t.Fatal("合法有界结果未被接收", result, err)
			}
		})
	}
}

func TestSearchRejectsUnsafeTextAndNormalizesIP(t *testing.T) {
	start := time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)
	query := model.SearchRequest{Start: start, End: start.Add(time.Hour)}
	for _, change := range []func(*model.SearchRequest){
		func(q *model.SearchRequest) { q.Keyword = "\xff" }, func(q *model.SearchRequest) { q.Path = "/\x00" },
		func(q *model.SearchRequest) { q.Protocol = "tcp\n" }, func(q *model.SearchRequest) { q.Method = "GET\t" },
		func(q *model.SearchRequest) { q.SourceIP = "fe80::1%eth0" },
		func(q *model.SearchRequest) { q.Keyword = strings.Repeat("x", 257) },
		func(q *model.SearchRequest) { q.Path = strings.Repeat("x", 1025) },
		func(q *model.SearchRequest) { q.Protocol = strings.Repeat("x", 33) },
		func(q *model.SearchRequest) {
			q.Start = time.Date(-1, 1, 1, 0, 0, 0, 0, time.UTC)
			q.End = q.Start.Add(time.Hour)
		},
		func(q *model.SearchRequest) {
			q.End = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
			q.Start = q.End.Add(-time.Hour)
		},
	} {
		q := query
		change(&q)
		if ValidateSearch(&q) == nil {
			t.Fatal("非法文本或不可编码时间进入检索", q)
		}
	}
	query.SourceIP, query.DestinationIP = "::ffff:192.0.2.1", "2001:0db8:0000:0000:0000:0000:0000:0001"
	if err := ValidateSearch(&query); err != nil || query.SourceIP != "192.0.2.1" || query.DestinationIP != "2001:db8::1" {
		t.Fatal("检索 IP 未与入库地址对齐", query, err)
	}
}
