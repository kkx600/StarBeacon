package store

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/model"
)

func TestSharedIndexUsesFrozenNameLayoutAndAtLeastRetentionLifecycle(t *testing.T) {
	var mu sync.Mutex
	templates := map[string]json.RawMessage{}
	policies := map[string]string{}
	created := map[string]map[string]any{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasPrefix(r.URL.Path, "/_index_template/"):
			name := strings.TrimPrefix(r.URL.Path, "/_index_template/")
			if r.Method == "GET" {
				if templates[name] == nil {
					w.WriteHeader(404)
					return
				}
				json.NewEncoder(w).Encode(map[string]any{"index_templates": []any{map[string]any{"name": name, "index_template": templates[name]}}})
				return
			}
			if r.URL.Query().Get("create") != "true" || name != "sb-v2-events" {
				t.Error("共享模板被覆盖或使用了旧版模板", name)
			}
			templates[name], _ = io.ReadAll(r.Body)
			fmt.Fprint(w, `{"acknowledged":true}`)
		case strings.HasPrefix(r.URL.Path, "/_ilm/policy/"):
			name := strings.TrimPrefix(r.URL.Path, "/_ilm/policy/")
			if r.Method == "GET" {
				if policies[name] == "" {
					w.WriteHeader(404)
					return
				}
				fmt.Fprintf(w, `{%q:{"policy":{"phases":{"delete":{"min_age":%q,"actions":{"delete":{}}}}}}}`, name, policies[name])
				return
			}
			var body struct {
				Policy struct {
					Phases map[string]struct {
						MinAge string `json:"min_age"`
					} `json:"phases"`
				} `json:"policy"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			policies[name] = body.Policy.Phases["delete"].MinAge
			fmt.Fprint(w, `{"acknowledged":true}`)
		case strings.HasSuffix(r.URL.Path, "/_bulk"):
			fmt.Fprint(w, `{"items":[{"create":{"_id":"event_owned","status":201}}]}`)
		case r.Method == "PUT":
			var body struct {
				Settings map[string]any `json:"settings"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			created[r.URL.Path] = body.Settings
			fmt.Fprint(w, `{"acknowledged":true}`)
		default:
			t.Error("意外请求", r.Method, r.URL.Path)
			w.WriteHeader(400)
		}
	}))
	defer server.Close()
	es, err := OpenES(server.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	es.Layout = contract.IndexLayout{Alerts: contract.StreamLayout{Period: contract.PeriodWeek, Shards: 3}, Replicas: 2}
	index, err := contract.EventIndexName("alerts", 180, contract.PeriodWeek, "2026-11-05")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, day := range []string{"2026-11-05", "2026-11-02", "2026-11-08"} {
		if err := es.EnsureIndex(ctx, index, day); err != nil {
			t.Fatal(err)
		}
	}
	for _, day := range []string{"2026-11-01", "2026-11-09", "bad"} {
		if es.EnsureIndex(ctx, index, day) == nil {
			t.Fatal("分区以外的路由日写入了共享索引", day)
		}
	}
	if errs := es.Bulk(ctx, index, []model.Alert{{EventID: "event_owned", TenantID: "tenant_owned"}}); errs[0] != nil {
		t.Fatal(errs[0])
	}
	mu.Lock()
	defer mu.Unlock()
	settings := created["/"+index]
	start := time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC).UnixMilli()
	if len(created) != 1 || settings["number_of_shards"] != float64(3) || settings["number_of_replicas"] != float64(2) || settings["index.lifecycle.name"] != "sb-retention-187d" || settings["index.lifecycle.origination_date"] != float64(start) {
		t.Fatalf("共享索引布局或生命周期错误：%v", created)
	}
	if policies["sb-retention-187d"] != "187d" {
		t.Fatal("周分区没有额外保留一个分区跨度", policies)
	}
	var template struct {
		Patterns        []string `json:"index_patterns"`
		AllowAutoCreate bool     `json:"allow_auto_create"`
	}
	if json.Unmarshal(templates["sb-v2-events"], &template) != nil || template.AllowAutoCreate || strings.Join(template.Patterns, ",") != "sb-v2-alerts-*,sb-v2-context-*" {
		t.Fatal("共享模板允许自动建索引或范围错误", string(templates["sb-v2-events"]))
	}
}

func TestSharedIndexSearchRejectsOtherTenantDocuments(t *testing.T) {
	now := time.Now().UTC()
	index, _ := contract.EventIndexName("alerts", 180, contract.PeriodWeek, now.Format("2006-01-02"))
	week, err := contract.ParseEventIndex(index)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, tenant, index string
		ok                  bool
	}{
		{"共享索引本租户", "tenant_owned", index, true},
		{"共享索引其他租户", "tenant_other", index, false},
		{"旧版租户索引", "tenant_owned", "sb-alerts-tenant_owned-" + now.Format("2006.01.02"), false},
		{"其他数据流共享索引", "tenant_owned", strings.Replace(index, "alerts", "context", 1), false},
		{"非分区起点共享索引", "tenant_owned", "sb-v2-alerts-r180-w" + week.Start.AddDate(0, 0, 1).Format("2006.01.02"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hit := map[string]any{"_id": "event_owned", "_index": tc.index, "_source": map[string]any{"event_id": "event_owned", "tenant_id": tc.tenant, "@timestamp": now.Add(-time.Minute), "event": map[string]any{"kind": "alert"}}}
				json.NewEncoder(w).Encode(map[string]any{"timed_out": false, "_shards": map[string]int{"total": 2, "successful": 2, "failed": 0}, "hits": map[string]any{"total": map[string]any{"value": 1, "relation": "eq"}, "hits": []any{hit}}})
			}))
			defer server.Close()
			es, _ := OpenES(server.URL, "")
			result, err := es.Search(context.Background(), "tenant_owned", model.SearchRequest{Start: now.Add(-time.Hour), End: now})
			if tc.ok != (err == nil) || tc.ok && len(result.Items) != 1 || !tc.ok && len(result.Items) != 0 {
				t.Fatalf("共享索引隔离结果错误：%v %v", result.Items, err)
			}
		})
	}
}
