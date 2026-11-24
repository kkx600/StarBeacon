package store

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/model"
)

func TestConcurrentIndexCreationFreezesExpiryAndRejectsAutomaticDrift(t *testing.T) {
	// 日分区 210 天保留：生命周期为保留期加一个分区跨度。
	const index = "sb-v2-alerts-r210-d2026.10.03"
	type storedIndex struct {
		policy   string
		origin   json.Number
		mappings json.RawMessage
	}
	var mu sync.Mutex
	var template json.RawMessage
	templateWrites := 0
	policies := map[string]int{}
	policyBodies := map[string]json.RawMessage{}
	indices := map[string]storedIndex{}
	requests := 0
	missing := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		requests++
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/_index_template/"+sharedEventTemplate.name:
			if r.Method == "GET" {
				if template == nil {
					w.WriteHeader(404)
					return
				}
				json.NewEncoder(w).Encode(map[string]any{"index_templates": []any{map[string]any{"name": sharedEventTemplate.name, "index_template": template}}})
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
			if name == "sb-retention-211d" && body.Policy.Phases["delete"].MinAge != "211d" {
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
				Settings struct {
					Policy string      `json:"index.lifecycle.name"`
					Origin json.Number `json:"index.lifecycle.origination_date"`
				} `json:"settings"`
				Mappings json.RawMessage `json:"mappings"`
			}
			if json.NewDecoder(r.Body).Decode(&body) != nil || body.Settings.Policy == "" || body.Settings.Origin == "" || body.Mappings == nil {
				t.Error("索引请求不完整")
			}
			if _, exists := indices[r.URL.Path]; exists {
				w.WriteHeader(400)
				fmt.Fprint(w, `{"error":{"type":"resource_already_exists_exception"}}`)
				return
			}
			indices[r.URL.Path] = storedIndex{body.Settings.Policy, body.Settings.Origin, body.Mappings}
			fmt.Fprint(w, `{"acknowledged":true}`)
		case r.Method == "GET" && indices[r.URL.Path].policy != "":
			// 与 ES 一致：生命周期设置位于 settings.index 下，数值以字符串返回。
			v := indices[r.URL.Path]
			json.NewEncoder(w).Encode(map[string]any{strings.TrimPrefix(r.URL.Path, "/"): map[string]any{"mappings": v.mappings, "settings": map[string]any{"index": map[string]any{"lifecycle": map[string]any{"name": v.policy, "origination_date": v.origin.String()}}}}})
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
		workers.Go(func() { errors <- es.EnsureIndex(ctx, index, "2026-10-03") })
	}
	workers.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	origin := strconv.FormatInt(time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC).UnixMilli(), 10)
	mu.Lock()
	if templateWrites != 1 || policies["sb-retention-211d"] != 1 || len(policies) != 1 || len(indices) != 1 {
		t.Fatal("并发重复创建了模板、策略或索引")
	}
	if created := indices["/"+index]; created.policy != "sb-retention-211d" || created.origin.String() != origin {
		t.Fatal("索引生命周期未按名称冻结的保留期与分区起点建立", created.policy, created.origin)
	}
	before := requests
	mu.Unlock()
	if es.EnsureIndex(ctx, index, "2026-10-03") != nil {
		t.Fatal("已确认的索引缓存失效")
	}
	// 保留期取自索引名称；超出 1–3650 天的名称在访问存储前拒绝。
	for _, name := range []string{"sb-v2-alerts-r0-d2026.10.03", "sb-v2-alerts-r-1-d2026.10.03", "sb-v2-alerts-r3651-d2026.10.03"} {
		if es.EnsureIndex(ctx, name, "2026-10-03") == nil {
			t.Fatal("无效期限未拒绝", name)
		}
	}
	for _, test := range []struct{ index, partition string }{{"other-owned-2026.10.03", "2026-10-03"}, {"sb-alerts-tenant_owned-2026.10.03", "2026-10-03"}, {"sb-v2-alerts-r210-w2026.10.03", "2026-10-03"}, {index, "bad"}, {index, "2026-10-04"}} {
		if es.EnsureIndex(ctx, test.index, test.partition) == nil {
			t.Fatal("无效身份或分区未拒绝", test)
		}
	}
	mu.Lock()
	if requests != before {
		t.Fatal("无效配置或缓存命中仍访问存储")
	}
	missing = true
	mu.Unlock()
	errs := es.Bulk(ctx, index, []model.Alert{{EventID: "owned"}})
	if errs[0] == nil || es.IndexKnown(index) {
		t.Fatal("索引丢失没有失效缓存")
	}
	fresh, err := OpenES(server.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	if fresh.EnsureIndex(ctx, index, "2026-10-03") != nil || !fresh.IndexKnown(index) {
		t.Fatal("重启后既有索引不能使用")
	}
	mu.Lock()
	original := indices["/"+index]
	if templateWrites != 1 || policies["sb-retention-211d"] != 1 || len(indices) != 1 || original.policy != "sb-retention-211d" {
		t.Fatal("重启修改了模板、策略或存量索引")
	}
	mu.Unlock()
	// 同名既有索引的映射、生命周期或分区起点不一致时拒绝写入，且不自动修正。
	for name, drift := range map[string]func(*storedIndex){
		"lifecycle": func(v *storedIndex) { v.policy = "sb-retention-365d" },
		"origin": func(v *storedIndex) {
			v.origin = json.Number(strconv.FormatInt(time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC).UnixMilli(), 10))
		},
		"mapping": func(v *storedIndex) {
			v.mappings = json.RawMessage(strings.Replace(string(v.mappings), `"dynamic":"strict"`, `"dynamic":"true"`, 1))
		},
	} {
		mu.Lock()
		changed := original
		drift(&changed)
		indices["/"+index] = changed
		mu.Unlock()
		drifted, err := OpenES(server.URL, "")
		if err != nil {
			t.Fatal(err)
		}
		if drifted.EnsureIndex(ctx, index, "2026-10-03") == nil || drifted.IndexKnown(index) {
			t.Fatal("既有索引漂移后仍被采用", name)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	// 映射或设置的任何改写请求都会以新路径记入 indices。
	if templateWrites != 1 || policies["sb-retention-211d"] != 1 || len(policies) != 1 || len(indices) != 1 {
		t.Fatal("核对失败时改写了模板、策略或存量索引")
	}
}

func TestIndexTemplateRejectsUnownedMalformedOrPermissiveDefinitions(t *testing.T) {
	valid := sharedEventTemplate.body()
	bodies := map[string]string{"empty": `{}`, "other_name": `{"index_templates":[{"name":"other","index_template":{}}]}`, "incomplete": `{"index_templates":[{"name":"sb-v2-events","index_template":{"template":{"mappings":{}}}}]}`, "permissive_unowned": `{"index_templates":[{"name":"sb-v2-events","index_template":{"index_patterns":["sb-v2-alerts-*","sb-v2-context-*"],"allow_auto_create":true,"priority":161,"version":1,"_meta":{"owner":"other","schema":1},"template":{"mappings":{}}}}]}`}
	// 逐项偏离固定契约：每一项单独出现都必须拒绝，且不覆盖既有模板。
	for _, change := range [][3]string{{"auto_create", `"allow_auto_create":false`, `"allow_auto_create":true`}, {"owner", `"owner":"starbeacon"`, `"owner":"other"`}, {"priority", `"priority":161`, `"priority":151`}, {"version", `"version":1`, `"version":2`}, {"schema", `"schema":1`, `"schema":2`}, {"patterns", `"sb-v2-context-*"`, `"sb-v2-*"`}, {"mapping", `"dynamic":"strict"`, `"dynamic":"true"`}} {
		if !strings.Contains(valid, change[1]) {
			t.Fatal("模板契约变体未命中", change[0])
		}
		bodies[change[0]] = fmt.Sprintf(`{"index_templates":[{"name":%q,"index_template":%s}]}`, sharedEventTemplate.name, strings.Replace(valid, change[1], change[2], 1))
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
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
			if es.ensureSharedTemplate(context.Background(), sharedEventTemplate) == nil || writes != 0 {
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
	for _, template := range []sharedTemplate{sharedEventTemplate, sharedLogTemplate} {
		if es.ensureSharedTemplate(context.Background(), template) == nil {
			t.Fatal("依赖故障被忽略", template.name)
		}
	}
}

func TestEnsurePolicyPublishesOnlySharedTemplates(t *testing.T) {
	var mu sync.Mutex
	templates := map[string]json.RawMessage{}
	writes := map[string]int{}
	other := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		name, ok := strings.CutPrefix(r.URL.Path, "/_index_template/")
		switch {
		case !ok:
			// 生命周期策略随共享索引按保留期建立，启动时不应创建。
			other = append(other, r.Method+" "+r.URL.Path)
			w.WriteHeader(400)
		case r.Method == "GET" && templates[name] == nil:
			w.WriteHeader(404)
		case r.Method == "GET":
			json.NewEncoder(w).Encode(map[string]any{"index_templates": []any{map[string]any{"name": name, "index_template": templates[name]}}})
		default:
			if r.URL.Query().Get("create") != "true" {
				t.Error("模板发布允许覆盖既有对象", name)
			}
			writes[name]++
			templates[name], _ = io.ReadAll(r.Body)
			fmt.Fprint(w, `{"acknowledged":true}`)
		}
	}))
	defer server.Close()
	es, err := OpenES(server.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := es.EnsurePolicy(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(other) != 0 || len(writes) != 4 {
		t.Fatal("启动时创建了非预期模板或生命周期", other, writes)
	}
	for _, template := range []sharedTemplate{sharedEventTemplate, sharedLogTemplate, contextLogsDBTemplate, logsLogsDBTemplate} {
		if writes[template.name] != 1 || string(templates[template.name]) != template.body() {
			t.Fatal("启动时未按固定契约发布模板", template.name)
		}
	}
}

func TestExistingLogIndexMustMatchLogMappingAndFrozenLifecycle(t *testing.T) {
	// 周分区 30 天保留的共享日志索引：生命周期 37 天，从周一起算。
	const index = "sb-v2-logs-r30-w2026.09.28"
	origin := time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC).UnixMilli()
	for name, tc := range map[string]struct {
		mapping, policy string
		origin          int64
		ok              bool
	}{
		"matching":        {logMapping, "sb-retention-37d", origin, true},
		"event_mapping":   {mapping, "sb-retention-37d", origin, false},
		"other_lifecycle": {logMapping, "sb-retention-30d", origin, false},
		"other_origin":    {logMapping, "sb-retention-37d", origin + 1, false},
	} {
		t.Run(name, func(t *testing.T) {
			unexpected := []string{}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch {
				case r.Method == "GET" && r.URL.Path == "/_index_template/"+sharedLogTemplate.name:
					fmt.Fprintf(w, `{"index_templates":[{"name":%q,"index_template":%s}]}`, sharedLogTemplate.name, sharedLogTemplate.body())
				case r.Method == "GET" && r.URL.Path == "/_ilm/policy/sb-retention-37d":
					fmt.Fprint(w, `{"sb-retention-37d":{"policy":{"phases":{"delete":{"min_age":"37d","actions":{"delete":{}}}}}}}`)
				case r.Method == "PUT" && r.URL.Path == "/"+index:
					w.WriteHeader(400)
					fmt.Fprint(w, `{"error":{"type":"resource_already_exists_exception"}}`)
				case r.Method == "GET" && r.URL.Path == "/"+index:
					fmt.Fprintf(w, `{%q:{"mappings":%s,"settings":{"index":{"lifecycle":{"name":%q,"origination_date":"%d"}}}}}`, index, tc.mapping, tc.policy, tc.origin)
				default:
					// 其他模板、生命周期或映射改写请求都不应发生。
					unexpected = append(unexpected, r.Method+" "+r.URL.Path)
					w.WriteHeader(400)
				}
			}))
			defer server.Close()
			es, err := OpenES(server.URL, "")
			if err != nil {
				t.Fatal(err)
			}
			err = es.EnsureIndex(context.Background(), index, "2026-10-01")
			if (err == nil) != tc.ok || es.IndexKnown(index) != tc.ok || len(unexpected) != 0 {
				t.Fatal("既有日志索引核对结果错误", err, unexpected)
			}
		})
	}
}
