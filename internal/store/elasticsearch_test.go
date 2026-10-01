package store

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/model"
)

func TestBulkDoesNotUseHTTP200AsWholeBatchSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"errors":true,"items":[{"create":{"_id":"one","status":201}},{"create":{"_id":"two","status":429}}]}`))
	}))
	defer server.Close()
	es, e := OpenES(server.URL, "")
	if e != nil {
		t.Fatal(e)
	}
	errs := es.Bulk(context.Background(), "index", []model.Alert{{EventID: "one"}, {EventID: "two"}})
	if len(errs) != 2 || errs[0] != nil || errs[1] == nil {
		t.Fatal("部分写入失败被全批确认")
	}
}
func TestConflictMustVerifyImmutableSource(t *testing.T) {
	for _, matches := range []bool{true, false} {
		t.Run(map[bool]string{true: "同一来源重投", false: "标识冲突"}[matches], func(t *testing.T) {
			want := model.Alert{TenantID: "tenant_a", EventID: "one", RawSHA256: "digest", SourceGenerationID: "src_a", SourceOffset: "0"}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.Method == "POST" {
					_, _ = w.Write([]byte(`{"items":[{"create":{"_id":"one","status":409}}]}`))
					return
				}
				stored := want
				if !matches {
					stored.TenantID = "tenant_b"
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"_source": stored})
			}))
			defer server.Close()
			es, _ := OpenES(server.URL, "")
			errs := es.Bulk(context.Background(), "index", []model.Alert{want})
			if (errs[0] == nil) != matches {
				t.Fatal("409 未校验原始身份")
			}
		})
	}
}
func TestSearchBoundsPreventUnboundedRequests(t *testing.T) {
	valid := model.SearchRequest{Start: time.Now().Add(-time.Hour), End: time.Now(), Page: 1, PageSize: 20}
	for _, mutate := range []func(*model.SearchRequest){func(q *model.SearchRequest) { q.Page = int(^uint(0) >> 1) }, func(q *model.SearchRequest) { q.PageSize = 101 }, func(q *model.SearchRequest) { q.Start = q.End.Add(-32 * 24 * time.Hour) }, func(q *model.SearchRequest) { q.SourceIP = "x OR tenant_id:*" }} {
		q := valid
		mutate(&q)
		if ValidateSearch(&q) == nil {
			t.Fatal("无效检索没有被限制")
		}
	}
}
func TestSearchPinsTenantAndSearchesTransport(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sb-alerts-tenant_a-*/_search" {
			t.Errorf("索引范围未固定租户：%s", r.URL.Path)
		}
		var body map[string]any
		if e := json.NewDecoder(r.Body).Decode(&body); e != nil {
			t.Error(e)
		}
		filters := body["query"].(map[string]any)["bool"].(map[string]any)["filter"].([]any)
		if filters[0].(map[string]any)["term"].(map[string]any)["tenant_id"] != "tenant_a" {
			t.Error("缺少租户过滤")
		}
		protocol := filters[2].(map[string]any)["bool"].(map[string]any)["should"].([]any)
		if protocol[1].(map[string]any)["term"].(map[string]any)["network.transport"] != "tcp" {
			t.Error("TCP 无法按传输层协议筛选")
		}
		_, _ = w.Write([]byte(`{"hits":{"total":{"value":0},"hits":[]}}`))
	}))
	defer server.Close()
	es, _ := OpenES(server.URL, "")
	_, e := es.Search(context.Background(), "tenant_a", model.SearchRequest{Start: time.Now().Add(-time.Hour), End: time.Now(), Protocol: "TCP"})
	if e != nil {
		t.Fatal(e)
	}
}

func TestPermanentMappingFailureIsClassified(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"errors":true,"items":[{"create":{"_id":"one","status":400,"error":{"type":"document_parsing_exception"}}}]}`))
	}))
	defer server.Close()
	es, e := OpenES(server.URL, "")
	if e != nil {
		t.Fatal(e)
	}
	errs := es.Bulk(context.Background(), "index", []model.Alert{{EventID: "one"}})
	var failure *IndexItemError
	if len(errs) != 1 || !errors.As(errs[0], &failure) || failure.Status != 400 {
		t.Fatal("永久映射错误不能与瞬时拒绝区分")
	}
}
