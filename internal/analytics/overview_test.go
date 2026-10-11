package analytics

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func testWindow() Window {
	start := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	return Window{Start: start, End: start.Add(24 * time.Hour)}
}

func testResponse(t *testing.T) map[string]any {
	t.Helper()
	return map[string]any{"timed_out": false, "_shards": map[string]any{"failed": 0}, "hits": map[string]any{"total": map[string]any{"value": int64(9007199254740993), "relation": "eq"}}, "aggregations": map[string]any{
		"trend":     map[string]any{"buckets": []any{map[string]any{"key": 1790899200000, "key_as_string": "2026-10-02T00:00:00.000Z", "doc_count": int64(9007199254740993)}}},
		"severity":  map[string]any{"buckets": []any{map[string]any{"key": "high", "doc_count": int64(9007199254740993)}}, "sum_other_doc_count": 0, "doc_count_error_upper_bound": 0},
		"protocols": map[string]any{"buckets": []any{}, "sum_other_doc_count": 10, "doc_count_error_upper_bound": 2},
		"rules":     map[string]any{"buckets": []any{}, "sum_other_doc_count": 0, "doc_count_error_upper_bound": 0},
		"sensors":   map[string]any{"buckets": []any{}, "sum_other_doc_count": 0, "doc_count_error_upper_bound": 0},
	}}
}

func TestWindowAndQueryContainExplicitTenantAndBoundedTime(t *testing.T) {
	w := testWindow()
	for _, invalid := range []Window{{}, {Start: w.Start, End: w.Start}, {Start: w.Start, End: w.Start.Add(-time.Second)}, {Start: w.Start, End: w.Start.Add(31*24*time.Hour + time.Nanosecond)}} {
		if _, err := Query("tenant_valid", invalid); err == nil {
			t.Fatal("时间窗越界被接受")
		}
	}
	if _, err := Query("tenant-*", w); err == nil {
		t.Fatal("租户通配符被接受")
	}
	raw, err := Query("tenant_valid", w)
	if err != nil {
		t.Fatal(err)
	}
	var query map[string]any
	if json.Unmarshal(raw, &query) != nil {
		t.Fatal("查询 JSON 无效")
	}
	if query["size"] != float64(0) || query["track_total_hits"] != true || query["timeout"] != "8s" || !strings.Contains(string(raw), `"tenant_id":"tenant_valid"`) {
		t.Fatal("查询没有明确范围", string(raw))
	}
	if !strings.Contains(string(raw), `"calendar_interval":"hour"`) || !strings.Contains(string(raw), `"show_term_doc_count_error":true`) {
		t.Fatal("统计粒度或误差口径缺失")
	}
	w.End = w.Start.Add(72 * time.Hour)
	raw, err = Query("tenant_valid", w)
	if err != nil || !strings.Contains(string(raw), `"calendar_interval":"day"`) {
		t.Fatal("长范围未限制时间桶")
	}
}

func TestCountsKeepIntegerPrecisionAndUnknownDistribution(t *testing.T) {
	raw, _ := json.Marshal(testResponse(t))
	result, err := Decode(raw, testWindow())
	if err != nil {
		t.Fatal(err)
	}
	if result.Total != "9007199254740993" || result.Trend[0].Count != result.Total || result.Severity.Buckets[0].Count != result.Total || result.Protocols.Other != "10" || result.Protocols.ErrorUpperBound != "2" {
		t.Fatal("计数精度或 Top N 尾部丢失", result)
	}
	data := testResponse(t)
	data["hits"].(map[string]any)["total"].(map[string]any)["value"] = 0
	for _, value := range data["aggregations"].(map[string]any) {
		value.(map[string]any)["buckets"] = []any{}
		value.(map[string]any)["sum_other_doc_count"] = 0
		value.(map[string]any)["doc_count_error_upper_bound"] = 0
	}
	raw, _ = json.Marshal(data)
	result, err = Decode(raw, testWindow())
	if err != nil || result.Total != "0" || result.Trend == nil || result.Severity.Buckets == nil {
		t.Fatal("真实空结果未保留明确空数组")
	}
}

func TestIncompleteOrInvalidStatisticsNeverBecomeHealthyZero(t *testing.T) {
	for _, mutate := range []func(map[string]any){
		func(v map[string]any) { v["timed_out"] = true },
		func(v map[string]any) { v["_shards"].(map[string]any)["failed"] = 1 },
		func(v map[string]any) { v["hits"].(map[string]any)["total"].(map[string]any)["relation"] = "gte" },
		func(v map[string]any) { v["hits"].(map[string]any)["total"].(map[string]any)["value"] = -1 },
		func(v map[string]any) { delete(v["aggregations"].(map[string]any), "trend") },
		func(v map[string]any) { delete(v["aggregations"].(map[string]any), "severity") },
		func(v map[string]any) {
			v["aggregations"].(map[string]any)["trend"].(map[string]any)["buckets"] = []any{map[string]any{"key_as_string": "bad-time", "doc_count": 1}}
		},
		func(v map[string]any) {
			v["aggregations"].(map[string]any)["severity"].(map[string]any)["buckets"] = []any{map[string]any{"key": "high", "doc_count": -1}}
		},
		func(v map[string]any) {
			v["aggregations"].(map[string]any)["severity"].(map[string]any)["buckets"] = []any{map[string]any{"key": 42, "doc_count": 1}}
		},
		func(v map[string]any) {
			v["aggregations"].(map[string]any)["severity"].(map[string]any)["sum_other_doc_count"] = -1
		},
		func(v map[string]any) {
			v["aggregations"].(map[string]any)["severity"].(map[string]any)["doc_count_error_upper_bound"] = -1
		},
		func(v map[string]any) {
			v["aggregations"].(map[string]any)["severity"].(map[string]any)["buckets"] = make([]any, 11)
		},
	} {
		data := testResponse(t)
		mutate(data)
		raw, _ := json.Marshal(data)
		if _, err := Decode(raw, testWindow()); !errors.Is(err, ErrIncomplete) {
			t.Fatal("不完整统计没有拒绝", string(raw), err)
		}
	}
	if _, err := Decode([]byte("invalid"), testWindow()); err == nil {
		t.Fatal("无效 JSON 没有拒绝")
	}
	if _, err := Decode([]byte(`{}`), Window{}); err == nil {
		t.Fatal("无效时间窗没有拒绝")
	}
}
