package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/elastic/go-elasticsearch/v9/esapi"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/searchsnapshot"
)

var snapshotStart = time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)

func snapshotHit(id int) map[string]any {
	return map[string]any{"_id": fmt.Sprintf("event_%04d", id), "_index": "sb-alerts-tenant_owned-2026.10.09", "sort": []int{id}, "_source": map[string]any{"event_id": fmt.Sprintf("event_%04d", id), "tenant_id": "tenant_owned", "@timestamp": snapshotStart, "event": map[string]string{"kind": "alert"}}}
}

func snapshotBody(total int, hits ...any) map[string]any {
	if hits == nil {
		hits = []any{}
	}
	return map[string]any{"pit_id": "pit_latest", "timed_out": false, "_shards": map[string]int{"total": 1, "successful": 1, "skipped": 0, "failed": 0}, "hits": map[string]any{"total": map[string]any{"value": total, "relation": "eq"}, "hits": hits}}
}

func snapshotQuery() model.TrafficSearchRequest {
	return model.TrafficSearchRequest{SearchRequest: model.SearchRequest{Start: snapshotStart.Add(-time.Minute), End: snapshotStart.Add(time.Hour)}}
}

func TestSnapshotUsesStableCursorNewestPITAndMetadataProjection(t *testing.T) {
	for _, dataset := range []string{"alerts", "context"} {
		t.Run(dataset, func(t *testing.T) {
			searches, closed, checked := 0, false, 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body map[string]any
				_ = json.NewDecoder(r.Body).Decode(&body)
				switch {
				case r.Method == "DELETE":
					closed = true
					if r.URL.Path != "/_pit" || body["id"] != "pit_latest" {
						t.Error("没有关闭最新快照")
					}
					_, _ = w.Write([]byte(`{"succeeded":true,"num_freed":1}`))
				case strings.HasSuffix(r.URL.Path, "/_pit"):
					if r.URL.Path != "/sb-"+dataset+"-tenant_owned-*/_pit" || r.URL.Query().Get("ignore_unavailable") != "false" || r.URL.Query().Get("allow_partial_search_results") != "false" || r.URL.Query().Get("expand_wildcards") != "open,closed" || body["index_filter"] == nil {
						t.Error("快照范围或部分分片保护缺失")
					}
					_, _ = w.Write([]byte(`{"id":"pit_first","_shards":{"total":1,"successful":1,"skipped":0,"failed":0}}`))
				default:
					if r.URL.Path != "/_search" || r.URL.Query().Get("allow_partial_search_results") != "false" || body["from"] != nil || body["size"] != float64(500) || body["track_total_hits"] != true {
						t.Error("快照分页请求不符合契约")
					}
					fields := fmt.Sprint(body["_source"])
					if strings.Contains(fields, "original") || !strings.Contains(fields, "event_id") {
						t.Error("导出请求没有限制载荷字段")
					}
					expectedPIT := "pit_first"
					if searches > 0 {
						expectedPIT = "pit_latest"
						if fmt.Sprint(body["search_after"]) != "[499]" {
							t.Error("没有使用前页完整排序值")
						}
					}
					if body["pit"].(map[string]any)["id"] != expectedPIT {
						t.Error("未使用最新快照身份")
					}
					hits := []any{}
					for id := searches * 500; id < min(searches*500+500, 501); id++ {
						hit := snapshotHit(id)
						if dataset == "context" {
							hit["_index"] = "sb-context-tenant_owned-2026.10.09"
							hit["_source"].(map[string]any)["event"] = map[string]string{"kind": "flow"}
						}
						hits = append(hits, hit)
					}
					searches++
					_ = json.NewEncoder(w).Encode(snapshotBody(501, hits...))
				}
			}))
			defer server.Close()
			es, _ := OpenES(server.URL, "")
			raw, rows, err := es.ExportEvents(context.Background(), "tenant_owned", dataset, snapshotQuery(), func(context.Context) error { checked++; return nil })
			if err != nil || rows != 501 || len(raw) == 0 || searches != 2 || !closed || checked != 5 {
				t.Fatal("快照读取、授权回读或释放未完成", rows, err, searches, closed, checked)
			}
		})
	}
}

func TestSnapshotRejectsIncompleteOrUntrustedResultsWithoutFile(t *testing.T) {
	mutations := map[string]func(map[string]any){
		"timeout":           func(v map[string]any) { v["timed_out"] = true },
		"timeout_missing":   func(v map[string]any) { delete(v, "timed_out") },
		"shards_missing":    func(v map[string]any) { delete(v, "_shards") },
		"shard_failed":      func(v map[string]any) { v["_shards"].(map[string]int)["failed"] = 1 },
		"shard_incomplete":  func(v map[string]any) { v["_shards"].(map[string]int)["successful"] = 0 },
		"skip_missing":      func(v map[string]any) { delete(v["_shards"].(map[string]int), "skipped") },
		"skip_negative":     func(v map[string]any) { v["_shards"].(map[string]int)["skipped"] = -1 },
		"skip_over_total":   func(v map[string]any) { v["_shards"].(map[string]int)["skipped"] = 2 },
		"pit_missing":       func(v map[string]any) { delete(v, "pit_id") },
		"approximate_count": func(v map[string]any) { v["hits"].(map[string]any)["total"].(map[string]any)["relation"] = "gte" },
		"count_negative":    func(v map[string]any) { v["hits"].(map[string]any)["total"].(map[string]any)["value"] = -1 },
		"count_missing":     func(v map[string]any) { delete(v["hits"].(map[string]any)["total"].(map[string]any), "value") },
		"rows_missing":      func(v map[string]any) { delete(v["hits"].(map[string]any), "hits") },
		"rows_partial":      func(v map[string]any) { v["hits"].(map[string]any)["hits"] = []any{} },
		"too_many":          func(v map[string]any) { v["hits"].(map[string]any)["total"].(map[string]any)["value"] = 10001 },
	}
	for name, alter := range map[string]func(map[string]any){
		"foreign_index":  func(h map[string]any) { h["_index"] = "sb-alerts-other-2026.10.09" },
		"invalid_index":  func(h map[string]any) { h["_index"] = "not_a_partition" },
		"mismatched_id":  func(h map[string]any) { h["_id"] = "other" },
		"invalid_id":     func(h map[string]any) { h["_id"] = "../id" },
		"foreign_source": func(h map[string]any) { h["_source"].(map[string]any)["tenant_id"] = "other" },
		"before_time": func(h map[string]any) {
			h["_source"].(map[string]any)["@timestamp"] = snapshotQuery().Start.Add(-time.Nanosecond)
		},
		"at_end":     func(h map[string]any) { h["_source"].(map[string]any)["@timestamp"] = snapshotQuery().End },
		"wrong_kind": func(h map[string]any) { h["_source"].(map[string]any)["event"] = map[string]string{"kind": "flow"} },
		"raw_payload": func(h map[string]any) {
			h["_source"].(map[string]any)["event"] = map[string]string{"kind": "alert", "original": "secret"}
		},
		"sort_absent":   func(h map[string]any) { delete(h, "sort") },
		"sort_string":   func(h map[string]any) { h["sort"] = []string{"0"} },
		"sort_negative": func(h map[string]any) { h["sort"] = []int{-1} },
		"sort_float":    func(h map[string]any) { h["sort"] = []float64{0.5} },
	} {
		mutations[name] = func(v map[string]any) { alter(v["hits"].(map[string]any)["hits"].([]any)[0].(map[string]any)) }
	}
	for name, alter := range mutations {
		t.Run(name, func(t *testing.T) {
			closed := false
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "DELETE" {
					closed = true
					_, _ = w.Write([]byte(`{"succeeded":true,"num_freed":1}`))
				} else if strings.HasSuffix(r.URL.Path, "/_pit") {
					_, _ = w.Write([]byte(`{"id":"pit_first","_shards":{"total":1,"successful":1,"skipped":0,"failed":0}}`))
				} else {
					v := snapshotBody(1, snapshotHit(0))
					alter(v)
					_ = json.NewEncoder(w).Encode(v)
				}
			}))
			defer server.Close()
			es, _ := OpenES(server.URL, "")
			raw, rows, err := es.ExportEvents(context.Background(), "tenant_owned", "alerts", snapshotQuery(), func(context.Context) error { return nil })
			if err == nil || raw != nil || rows != 0 || !closed {
				t.Fatal("不完整快照暴露文件或未释放", rows, err, closed)
			}
			if name == "too_many" && !errors.Is(err, searchsnapshot.ErrLimit) {
				t.Fatal("超限被错误分类", err)
			}
		})
	}
}

func TestSnapshotPrunedContextsAndUnavailableShards(t *testing.T) {
	for _, mode := range []string{"partial_pruning", "all_pruned", "context_lost", "context_added", "open_skip_missing", "open_skip_negative", "open_skip_over_total", "open_failed"} {
		t.Run(mode, func(t *testing.T) {
			closed, searches := false, 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == "DELETE":
					closed = true
					_, _ = w.Write([]byte(`{"succeeded":true,"num_freed":0}`))
				case strings.HasSuffix(r.URL.Path, "/_pit"):
					shards := map[string]int{"total": 3, "successful": 3, "skipped": 2, "failed": 0}
					switch mode {
					case "all_pruned":
						shards["skipped"] = 3
					case "open_skip_missing":
						delete(shards, "skipped")
					case "open_skip_negative":
						shards["skipped"] = -1
					case "open_skip_over_total":
						shards["skipped"] = 4
					case "open_failed":
						shards["successful"], shards["failed"] = 2, 1
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"id": "pit_first", "_shards": shards})
				default:
					searches++
					body := snapshotBody(1, snapshotHit(0))
					if mode == "all_pruned" {
						body = snapshotBody(0)
						body["_shards"] = map[string]int{"total": 0, "successful": 0, "skipped": 0, "failed": 0}
					}
					if mode == "context_lost" || mode == "context_added" {
						count := 0
						if mode == "context_added" {
							count = 2
						}
						body["_shards"] = map[string]int{"total": count, "successful": count, "skipped": 0, "failed": 0}
					}
					_ = json.NewEncoder(w).Encode(body)
				}
			}))
			defer server.Close()
			es, err := OpenES(server.URL, "")
			if err != nil {
				t.Fatal(err)
			}
			raw, rows, err := es.ExportEvents(context.Background(), "tenant_owned", "alerts", snapshotQuery(), func(context.Context) error { return nil })
			good := mode == "partial_pruning" || mode == "all_pruned"
			if !closed || good && (err != nil || len(raw) == 0 || searches != 1) || !good && (err == nil || raw != nil || rows != 0) {
				t.Fatal("索引裁剪或不完整分片处理错误", mode, rows, err, searches, closed)
			}
			if mode == "partial_pruning" && rows != 1 || mode == "all_pruned" && (rows != 0 || strings.Count(string(raw), "\r\n") != 1) {
				t.Fatal("完整快照记录数或空表头错误", mode, rows)
			}
			if strings.HasPrefix(mode, "open_") && searches != 0 {
				t.Fatal("不完整创建响应仍进行了查询", mode)
			}
		})
	}
}

func TestSnapshotPermissionCancellationEmptyAndCloseFailure(t *testing.T) {
	for _, mode := range []string{"empty", "revoke", "cancel", "close_failure", "close_incomplete", "bad_open", "duplicate", "reverse_sort"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			closed, checks := false, 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "DELETE" {
					closed = true
					if mode == "close_failure" {
						w.WriteHeader(503)
						return
					}
					if mode == "close_incomplete" {
						_, _ = w.Write([]byte(`{"succeeded":false,"num_freed":0}`))
						return
					}
					_, _ = w.Write([]byte(`{"succeeded":true,"num_freed":1}`))
					return
				}
				if strings.HasSuffix(r.URL.Path, "/_pit") {
					if mode == "bad_open" {
						_, _ = w.Write([]byte(`{"id":"pit_first","_shards":{"total":1,"successful":0,"skipped":0,"failed":1}}`))
						return
					}
					_, _ = w.Write([]byte(`{"id":"pit_first","_shards":{"total":1,"successful":1,"skipped":0,"failed":0}}`))
					return
				}
				v := snapshotBody(1, snapshotHit(0))
				if mode == "empty" {
					v = snapshotBody(0)
				}
				if mode == "duplicate" {
					v = snapshotBody(2, snapshotHit(0), snapshotHit(0))
				}
				if mode == "reverse_sort" {
					h := snapshotHit(1)
					h["sort"] = []int{0}
					v = snapshotBody(2, snapshotHit(0), h)
				}
				_ = json.NewEncoder(w).Encode(v)
			}))
			defer server.Close()
			es, _ := OpenES(server.URL, "")
			raw, rows, err := es.ExportEvents(ctx, "tenant_owned", "alerts", snapshotQuery(), func(ctx context.Context) error {
				checks++
				if checks == 3 && mode == "revoke" {
					return model.ErrUnauthenticated
				}
				if checks == 2 && mode == "cancel" {
					cancel()
					return ctx.Err()
				}
				return nil
			})
			if !closed || mode == "empty" && (err != nil || len(raw) == 0 || rows != 0) || mode != "empty" && (err == nil || raw != nil || rows != 0) {
				t.Fatal("空快照、撤权、取消或释放失败处理错误", mode, err, closed)
			}
		})
	}
}

func TestSnapshotRejectsInvalidInputsAndMalformedResponse(t *testing.T) {
	es, _ := OpenES("http://127.0.0.1:1", "")
	valid := snapshotQuery()
	for _, input := range []struct {
		tenant, dataset string
		q               model.TrafficSearchRequest
		auth            func(context.Context) error
	}{
		{"../tenant", "alerts", valid, func(context.Context) error { return nil }},
		{"tenant_owned", "alerts", valid, nil},
		{"tenant_owned", "other", valid, func(context.Context) error { return nil }},
		{"tenant_owned", "context", model.TrafficSearchRequest{}, func(context.Context) error { return nil }},
		{"tenant_owned", "alerts", valid, func(context.Context) error { return model.ErrUnauthenticated }},
		{"tenant_owned", "alerts", model.TrafficSearchRequest{SearchRequest: valid.SearchRequest, SensorID: "sensor_owned"}, func(context.Context) error { return nil }},
	} {
		if raw, _, err := es.ExportEvents(context.Background(), input.tenant, input.dataset, input.q, input.auth); err == nil || raw != nil {
			t.Fatal("无效导出输入未拒绝")
		}
	}
	for _, id := range []string{"", "bad id", "\xff", strings.Repeat("x", 65537)} {
		if validPIT(id) {
			t.Fatal("非法 PIT 身份被接受")
		}
	}
	for _, raw := range []string{`{} {}`, strings.Repeat("x", 16*1024*1024+1)} {
		res := &esapi.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(raw))}
		if snapshotResponse(res, nil, &map[string]any{}) == nil {
			t.Fatal("无效快照响应被接受")
		}
	}
	if snapshotResponse(&esapi.Response{Body: io.NopCloser(strings.NewReader(""))}, errors.New("transport"), nil) == nil {
		t.Fatal("传输失败未保留")
	}
}
