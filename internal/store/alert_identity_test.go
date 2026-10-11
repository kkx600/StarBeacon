package store

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/assessment"
)

func TestAlertEvidenceAllowsHistoricalEventAndRejectsMissingTimesOrPayload(t *testing.T) {
	digest := strings.Repeat("b", 64)
	source := map[string]any{"tenant_id": "tenant_owned", "event_id": "historical_event", "raw_sha256": digest, "@timestamp": "2026-09-01T00:00:00Z", "observed_at": "2026-10-02T00:00:00Z", "sensor_id": "sensor_owned", "sensor_registration_id": "registration_owned", "event": map[string]any{"kind": "alert"}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Source []string `json:"_source"`
		}
		if json.NewDecoder(r.Body).Decode(&request) != nil {
			t.Error("研判来源请求无法解码")
		}
		fields := map[string]bool{}
		for _, field := range request.Source {
			fields[field] = true
		}
		if !fields["@timestamp"] || !fields["observed_at"] || !fields["sensor_registration_id"] || fields["event.original"] {
			t.Error("研判来源没有按白名单读取必要字段")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"timed_out": false, "_shards": map[string]int{"total": 1, "successful": 1, "failed": 0}, "hits": map[string]any{"total": map[string]any{"value": 1, "relation": "eq"}, "hits": []any{map[string]any{"_id": "historical_event", "_index": "sb-alerts-tenant_owned-2026.10.03", "_source": source}}}})
	}))
	defer server.Close()
	es, err := OpenES(server.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	read := func() error {
		_, err := es.ReadAlertEvidence(context.Background(), "tenant_owned", "historical_event", digest)
		return err
	}
	alert, err := es.ReadAlertEvidence(context.Background(), "tenant_owned", "historical_event", digest)
	if err != nil || alert.Timestamp != time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC) || alert.SensorID != "sensor_owned" {
		t.Fatal("历史事件日期被索引路由日期错误约束", err)
	}
	for _, field := range []string{"@timestamp", "observed_at"} {
		old := source[field]
		delete(source, field)
		if !errors.Is(read(), ErrAlertIdentity) {
			t.Fatal("缺失必要时间仍返回研判材料", field)
		}
		source[field] = old
	}
	source["event"].(map[string]any)["original"] = "unrequested payload"
	if !errors.Is(read(), ErrAlertIdentity) {
		t.Fatal("研判材料接受了非白名单载荷")
	}
}

func TestAssessmentSourceRejectsAmbiguousPartialOrChangedFacts(t *testing.T) {
	digest := strings.Repeat("a", 64)
	hit := map[string]any{"_id": "event_owned", "_index": "sb-alerts-tenant_owned-2026.10.03", "_source": map[string]any{"tenant_id": "tenant_owned", "event_id": "event_owned", "raw_sha256": digest, "event": map[string]string{"kind": "alert"}}}
	var body any
	status := 200
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Query().Get("allow_partial_search_results") != "false" {
			t.Error("研判身份检索没有拒绝不完整结果")
		}
		var request struct {
			Size   int             `json:"size"`
			Source []string        `json:"_source"`
			Query  json.RawMessage `json:"query"`
		}
		if json.NewDecoder(r.Body).Decode(&request) != nil || request.Size != 2 || strings.Contains(string(request.Query), "foreign") || !strings.Contains(string(request.Query), `"tenant_id":"tenant_owned"`) || !strings.Contains(string(request.Query), `"event_id":"event_owned"`) {
			t.Error("身份检索没有限定当前租户、告警和歧义上限")
		}
		for _, field := range request.Source {
			if field == "event.original" {
				t.Error("身份核验读取了原始载荷")
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	}))
	defer server.Close()
	es, err := OpenES(server.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	responseBody := func(hits []any, value int) map[string]any {
		return map[string]any{"timed_out": false, "_shards": map[string]int{"total": 1, "successful": 1, "failed": 0}, "hits": map[string]any{"total": map[string]any{"value": value, "relation": "eq"}, "hits": hits}}
	}
	body = responseBody([]any{hit}, 1)
	if err := es.VerifyAlertIdentity(context.Background(), "tenant_owned", "event_owned", digest); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(map[string]any){func(v map[string]any) { v["timed_out"] = true }, func(v map[string]any) { delete(v, "timed_out") }, func(v map[string]any) { v["_shards"] = map[string]int{"failed": 1} }, func(v map[string]any) { delete(v, "_shards") }, func(v map[string]any) {
		v["_shards"] = map[string]int{"total": 2, "successful": 1, "failed": 0}
	}, func(v map[string]any) {
		v["_shards"] = map[string]int{"successful": 1, "failed": 0}
	}, func(v map[string]any) {
		v["_shards"] = map[string]int{"total": 1, "failed": 0}
	}, func(v map[string]any) {
		v["_shards"] = map[string]int{"total": -1, "successful": -1, "failed": 0}
	}, func(v map[string]any) {
		v["hits"] = map[string]any{"total": map[string]any{"value": 3, "relation": "eq"}, "hits": []any{hit, hit}}
	}, func(v map[string]any) {
		v["hits"] = map[string]any{"total": map[string]any{"value": 1, "relation": "gte"}, "hits": []any{hit}}
	}} {
		v := responseBody([]any{hit}, 1)
		mutate(v)
		body = v
		if err := es.VerifyAlertIdentity(context.Background(), "tenant_owned", "event_owned", digest); !errors.Is(err, ErrAlertIdentity) {
			t.Fatal("不完整来源被接受", err)
		}
	}
	for _, field := range []string{"_index", "_id", "tenant_id", "event_id", "raw_sha256", "kind"} {
		encoded, _ := json.Marshal(hit)
		var changed map[string]any
		_ = json.Unmarshal(encoded, &changed)
		if field == "_index" || field == "_id" {
			changed[field] = "foreign"
		} else if field == "kind" {
			changed["_source"].(map[string]any)["event"].(map[string]any)[field] = "flow"
		} else {
			changed["_source"].(map[string]any)[field] = "foreign"
		}
		body = responseBody([]any{changed}, 1)
		if err := es.VerifyAlertIdentity(context.Background(), "tenant_owned", "event_owned", digest); !errors.Is(err, ErrAlertIdentity) {
			t.Fatal("被修改的来源被接受", field, err)
		}
	}
	body = responseBody([]any{hit, hit}, 2)
	if err := es.VerifyAlertIdentity(context.Background(), "tenant_owned", "event_owned", digest); !errors.Is(err, ErrAlertIdentity) {
		t.Fatal("重复来源被接受", err)
	}
	body = responseBody([]any{}, 0)
	if err := es.VerifyAlertIdentity(context.Background(), "tenant_owned", "event_owned", digest); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("没有来源也返回成功", err)
	}
	status = 403
	if err := es.VerifyAlertIdentity(context.Background(), "tenant_owned", "event_owned", digest); err == nil {
		t.Fatal("ES 拒绝访问被当成空数据")
	}
	for _, input := range [][3]string{{"tenant*", "event_owned", digest}, {"tenant_owned", "bad/id", digest}, {"tenant_owned", "event_owned", "digest"}} {
		if err := es.VerifyAlertIdentity(context.Background(), input[0], input[1], input[2]); !errors.Is(err, assessment.ErrInput) {
			t.Fatal("无效检索身份未拒绝", err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := es.VerifyAlertIdentity(ctx, "tenant_owned", "event_owned", digest); err == nil {
		t.Fatal("取消来源核验仍然成功")
	}
}
