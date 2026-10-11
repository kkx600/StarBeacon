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
)

type failedResponseBody struct{}

func (failedResponseBody) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
func (failedResponseBody) Close() error             { return nil }

func TestESBulkRejectsMalformedPartialAndMissingResponses(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
	}{{"missing_items", `{"items":[]}`, 200}, {"wrong_identity", `{"items":[{"create":{"_id":"other","status":201}}]}`, 200}, {"bad_json", `{`, 200}, {"whole_index_missing", `{}`, 404}, {"duplicate_missing", `{"items":[{"create":{"_id":"owned","status":409}}]}`, 200}, {"item_missing", `{"items":[{"create":{"_id":"owned","status":404}}]}`, 200}} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					w.WriteHeader(404)
					return
				}
				w.WriteHeader(tc.status)
				io.WriteString(w, tc.body)
			}))
			defer server.Close()
			es, err := OpenES(server.URL, "")
			if err != nil {
				t.Fatal(err)
			}
			es.indices["owned-index"] = true
			errs := es.Bulk(context.Background(), "owned-index", []model.Alert{{EventID: "owned", TenantID: "tenant_owned"}})
			if len(errs) != 1 || errs[0] == nil {
				t.Fatal("损坏或缺失分项结果被当作持久成功", errs)
			}
			if strings.Contains(tc.name, "missing") && tc.name != "missing_items" && tc.name != "duplicate_missing" && es.IndexKnown("owned-index") {
				t.Fatal("已丢失索引仍保留缓存")
			}
		})
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(403) }))
	es, err := OpenES(server.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	if es.Ping(context.Background()) == nil {
		t.Fatal("无健康权限仍认为就绪")
	}
	server.Close()
	if es.Ping(context.Background()) == nil {
		t.Fatal("ES 不可达仍认为就绪")
	}
	if es.Bulk(context.Background(), "index", []model.Alert{{EventID: "owned"}})[0] == nil {
		t.Fatal("连接失败被确认")
	}
	bad := model.Alert{Timestamp: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)}
	errs := es.Bulk(context.Background(), "index", []model.Alert{bad, {EventID: "second"}})
	if len(errs) != 2 || errs[0] == nil || errs[1] == nil {
		t.Fatal("编码失败未拒绝整批")
	}
	if len(es.Bulk(context.Background(), "index", nil)) != 0 {
		t.Fatal("空批次产生结果")
	}
	for _, address := range []string{"relative", "%invalid"} {
		if _, err := OpenES(address, ""); err == nil {
			t.Fatal("无效 ES 地址被接受")
		}
	}
	if response(&esapi.Response{StatusCode: 200, Body: failedResponseBody{}}, nil, nil) == nil {
		t.Fatal("响应读取失败被吞掉")
	}
	if response(nil, io.ErrClosedPipe, nil) != io.ErrClosedPipe {
		t.Fatal("传输异常未原样传递")
	}
	if !strings.Contains((&IndexItemError{Status: 429}).Error(), "429") {
		t.Fatal("分项错误没有包含状态码")
	}
}

func TestSearchAllFiltersAndDependencyFailure(t *testing.T) {
	stamp := time.Now().UTC().Add(-time.Minute)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		for _, value := range []string{`"tenant_id":"tenant_owned"`, `"source.ip":"192.0.2.1"`, `"destination.ip":"2001:db8::1"`, `"http.method":"POST"`, `"severity":"high"`, `"http.path":"/login"`, `"match_phrase"`, `"rule.name":"登录"`, `"source.port":443`} {
			if !strings.Contains(string(body), value) {
				t.Error("组合筛选遗漏条件", value)
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"timed_out": false, "_shards": map[string]int{"total": 1, "successful": 1, "failed": 0}, "hits": map[string]any{"total": map[string]any{"value": 1, "relation": "eq"}, "hits": []any{map[string]any{"_id": "event_owned", "_index": "sb-alerts-tenant_owned-2026.10.03", "_source": map[string]any{"event_id": "event_owned", "tenant_id": "tenant_owned", "@timestamp": stamp, "event": map[string]string{"kind": "alert"}}}}}})
	}))
	defer server.Close()
	es, err := OpenES(server.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	query := model.SearchRequest{Start: time.Now().Add(-time.Hour), End: time.Now(), SourceIP: "192.0.2.1", DestinationIP: "2001:db8::1", Method: "post", Severity: "high", Protocol: "HTTP", Path: "/login", Keyword: "登录", Filter: "tcp.srcport == 443"}
	result, err := es.Search(context.Background(), "tenant_owned", query)
	if err != nil || result.Total != 1 || len(result.Items) != 1 || result.Page != 1 || result.PageSize != 20 {
		t.Fatal("组合检索结果不正确", result, err)
	}
	if _, err = es.Search(context.Background(), "../foreign", query); err == nil {
		t.Fatal("无效租户进入 ES 检索")
	}
	for _, change := range []func(*model.SearchRequest){func(q *model.SearchRequest) { q.Method = strings.Repeat("x", 17) }, func(q *model.SearchRequest) { q.Severity = "fatal" }, func(q *model.SearchRequest) { q.Filter = "not.a.field == 1" }, func(q *model.SearchRequest) { q.End = q.Start }} {
		q := query
		change(&q)
		if _, err = es.Search(context.Background(), "tenant_owned", q); err == nil {
			t.Fatal("无效检索被发送")
		}
	}
	server.Close()
	if _, err = es.Search(context.Background(), "tenant_owned", query); err == nil {
		t.Fatal("存储错误被伪装为空列表")
	}
}

func TestLifecycleFailuresNeverCacheUnconfirmedCreation(t *testing.T) {
	for _, mode := range []string{"lookup_denied", "put_denied", "unconfirmed", "confirm_denied", "index_denied", "index_disconnected"} {
		t.Run(mode, func(t *testing.T) {
			lookups := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.HasPrefix(r.URL.Path, "/_index_template/"):
					fmt.Fprintf(w, `{"index_templates":[{"name":"%s","index_template":{"index_patterns":["sb-alerts-*","sb-context-*"],"allow_auto_create":false,"priority":150,"version":1,"_meta":{"owner":"starbeacon","schema":1},"template":{"mappings":%s}}}]}`, eventTemplateName, mapping)
				case strings.HasPrefix(r.URL.Path, "/_ilm/policy/"):
					if r.Method == http.MethodGet {
						lookups++
						if mode == "lookup_denied" || (mode == "confirm_denied" && lookups > 1) {
							w.WriteHeader(403)
							return
						}
						if lookups == 1 || mode == "unconfirmed" {
							w.WriteHeader(404)
							return
						}
						io.WriteString(w, `{"sb-default-180d":{"policy":{"phases":{"delete":{"min_age":"180d","actions":{"delete":{}}}}}}}`)
						return
					}
					if mode == "put_denied" {
						w.WriteHeader(403)
					} else {
						io.WriteString(w, `{"acknowledged":true}`)
					}
				default:
					if mode == "index_disconnected" {
						c, _, err := w.(http.Hijacker).Hijack()
						if err == nil {
							c.Close()
						}
						return
					}
					w.WriteHeader(403)
					io.WriteString(w, `{"error":{"type":"security_exception"}}`)
				}
			}))
			defer server.Close()
			es, err := OpenES(server.URL, "")
			if err != nil {
				t.Fatal(err)
			}
			ctx, stop := context.WithTimeout(context.Background(), 3*time.Second)
			defer stop()
			if err = es.EnsureIndex(ctx, "sb-alerts-tenant_owned-2026.10.03", "2026-10-03"); err == nil {
				t.Fatal("未确认生命周期或索引仍被采用")
			}
			if es.IndexKnown("sb-alerts-tenant_owned-2026.10.03") {
				t.Fatal("失败的索引被写入成功缓存")
			}
		})
	}
	if err := (&Elasticsearch{}).ensureRetentionPolicy(context.Background(), 0); err == nil {
		t.Fatal("无效生命周期期限被接受")
	}
	var e *IndexItemError
	if errors.As(fmt.Errorf("wrap: %w", &IndexItemError{Status: 400}), &e) == false {
		t.Fatal("分项错误不可识别")
	}
}
