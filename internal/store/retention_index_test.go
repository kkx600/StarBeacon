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

	"github.com/kkx600/StarBeacon/internal/model"
)

func TestConcurrentIndexCreationFreezesExpiryAndRejectsAutomaticDrift(t *testing.T) {
	var mu sync.Mutex
	var template json.RawMessage
	templateWrites := 0
	policies := map[string]int{}
	policyBodies := map[string]json.RawMessage{}
	indices := map[string]string{}
	requests := 0
	missing := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		requests++
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/_index_template/"+eventTemplateName:
			if r.Method == "GET" {
				if template == nil {
					w.WriteHeader(404)
					return
				}
				json.NewEncoder(w).Encode(map[string]any{"index_templates": []any{map[string]any{"name": eventTemplateName, "index_template": template}}})
				return
			}
			if r.URL.Query().Get("create") != "true" {
				t.Error("模板发布允许覆盖既有对象")
			}
			templateWrites++
			template, _ = io.ReadAll(r.Body)
			fmt.Fprint(w, `{"acknowledged":true}`)
		case strings.HasPrefix(r.URL.Path, "/_ilm/policy/"):
			name := strings.TrimPrefix(r.URL.Path, "/_ilm/policy/")
			if r.Method == "GET" {
				if policyBodies[name] == nil {
					w.WriteHeader(404)
					return
				}
				var stored any
				json.Unmarshal(policyBodies[name], &stored)
				json.NewEncoder(w).Encode(map[string]any{name: stored})
				return
			}
			policies[name]++
			raw, _ := io.ReadAll(r.Body)
			policyBodies[name] = raw
			var body struct {
				Policy struct {
					Phases map[string]struct {
						MinAge string `json:"min_age"`
					}
				}
			}
			if json.Unmarshal(raw, &body) != nil || len(body.Policy.Phases) != 1 {
				t.Error("生命周期内容不完整")
			}
			if name == "sb-retention-210d" && body.Policy.Phases["delete"].MinAge != "210d" {
				t.Error("保留期未进入实际生命周期")
			}
			fmt.Fprint(w, `{"acknowledged":true}`)
		case strings.HasSuffix(r.URL.Path, "/_bulk"):
			if missing {
				fmt.Fprint(w, `{"items":[{"create":{"_id":"owned","status":404}}]}`)
			} else {
				fmt.Fprint(w, `{"items":[{"create":{"_id":"owned","status":201}}]}`)
			}
		case r.Method == "PUT":
			var body struct {
				Settings map[string]any `json:"settings"`
			}
			if json.NewDecoder(r.Body).Decode(&body) != nil {
				t.Error("索引请求不完整")
			}
			if _, exists := indices[r.URL.Path]; exists {
				w.WriteHeader(400)
				fmt.Fprint(w, `{"error":{"type":"resource_already_exists_exception"}}`)
				return
			}
			indices[r.URL.Path] = fmt.Sprint(body.Settings["index.lifecycle.name"])
			fmt.Fprint(w, `{"acknowledged":true}`)
		default:
			w.WriteHeader(400)
		}
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	es, err := OpenES(server.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	errors := make(chan error, 24)
	for i := 0; i < 24; i++ {
		workers.Go(func() { errors <- es.EnsureIndexRetention(ctx, "sb-alerts-tenant_owned-2026.10.03", "2026-10-03", 210) })
	}
	workers.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	mu.Lock()
	if templateWrites != 1 || policies["sb-retention-210d"] != 1 || len(indices) != 1 {
		t.Fatal("并发重复创建了模板、策略或索引")
	}
	before := requests
	mu.Unlock()
	if es.EnsureIndexRetention(ctx, "sb-alerts-tenant_owned-2026.10.03", "2026-10-03", 365) != nil {
		t.Fatal("既有索引未保持首次策略")
	}
	for _, days := range []int{0, -1, 3651} {
		if es.EnsureIndexRetention(ctx, "sb-alerts-tenant_owned-2026.10.03", "2026-10-03", days) == nil {
			t.Fatal("无效期限未拒绝")
		}
	}
	for _, test := range []struct{ index, partition string }{{"other-owned-2026.10.03", "2026-10-03"}, {"sb-alerts-tenant_owned-2026.10.03", "bad"}, {"sb-alerts-tenant_owned-2026.10.03", "2026-10-04"}} {
		if es.EnsureIndexRetention(ctx, test.index, test.partition, 180) == nil {
			t.Fatal("无效身份或分区未拒绝")
		}
	}
	mu.Lock()
	if requests != before {
		t.Fatal("无效配置或缓存命中仍访问存储")
	}
	missing = true
	mu.Unlock()
	errs := es.Bulk(ctx, "sb-alerts-tenant_owned-2026.10.03", []model.Alert{{EventID: "owned"}})
	if errs[0] == nil || es.IndexKnown("sb-alerts-tenant_owned-2026.10.03") {
		t.Fatal("索引丢失没有失效缓存")
	}
	fresh, err := OpenES(server.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	if fresh.EnsureIndexRetention(ctx, "sb-alerts-tenant_owned-2026.10.03", "2026-10-03", 365) != nil {
		t.Fatal("重启后既有索引不能使用")
	}
	mu.Lock()
	defer mu.Unlock()
	if indices["/sb-alerts-tenant_owned-2026.10.03"] != "sb-retention-210d" {
		t.Fatal("重启或策略调整修改了存量索引")
	}
}

func TestIndexTemplateRejectsUnownedMalformedOrPermissiveDefinitions(t *testing.T) {
	for _, body := range []string{`{}`, `{"index_templates":[{"name":"other","index_template":{}}]}`, `{"index_templates":[{"name":"sb-events-v1","index_template":{"template":{"mappings":{}}}}]}`, `{"index_templates":[{"name":"sb-events-v1","index_template":{"index_patterns":["sb-alerts-*","sb-context-*"],"allow_auto_create":true,"priority":150,"version":1,"_meta":{"owner":"other","schema":1},"template":{"mappings":{}}}}]}`} {
		t.Run(body, func(t *testing.T) {
			writes := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" {
					writes++
				}
				fmt.Fprint(w, body)
			}))
			defer server.Close()
			es, err := OpenES(server.URL, "")
			if err != nil {
				t.Fatal(err)
			}
			if es.EnsureEventTemplate(context.Background()) == nil || writes != 0 {
				t.Fatal("不受信任或不完整模板被采用／覆盖")
			}
		})
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(403) }))
	es, _ := OpenES(server.URL, "")
	if es.EnsurePolicy(context.Background()) == nil {
		t.Fatal("缺少模板权限时继续启动")
	}
	server.Close()
	if es.EnsureEventTemplate(context.Background()) == nil {
		t.Fatal("依赖故障被忽略")
	}
}
