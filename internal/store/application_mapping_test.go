package store

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestApplicationMappingOnlyMigratesKnownOwnedTemplate(t *testing.T) {
	var legacy map[string]any
	if json.Unmarshal([]byte(mapping), &legacy) != nil {
		t.Fatal("当前映射无效")
	}
	delete(legacy["properties"].(map[string]any), "application")
	legacyJSON, _ := json.Marshal(legacy)
	for _, mode := range []string{"owned_v1", "current_v2", "foreign_owner", "unknown_v1", "put_denied", "unconfirmed", "read_failed", "identity_failed"} {
		t.Run(mode, func(t *testing.T) {
			puts, gets := 0, 0
			upgraded := mode == "current_v2"
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/_index_template/"+eventTemplateName {
					t.Error("迁移访问其他模板", r.URL.Path)
					w.WriteHeader(400)
					return
				}
				if r.Method == http.MethodPut {
					puts++
					if mode == "put_denied" {
						w.WriteHeader(403)
						return
					}
					var body map[string]any
					if json.NewDecoder(r.Body).Decode(&body) != nil || body["version"] != float64(2) || body["allow_auto_create"] != false {
						t.Error("模板升级范围错误")
					}
					if mode != "unconfirmed" {
						upgraded = true
					}
					w.Write([]byte(`{"acknowledged":true}`))
					return
				}
				gets++
				if gets > 1 && mode == "read_failed" {
					w.WriteHeader(503)
					return
				}
				if upgraded {
					name := eventTemplateName
					if mode == "identity_failed" {
						name = "foreign"
					}
					fmt.Fprintf(w, `{"index_templates":[{"name":"%s","index_template":%s}]}`, name, eventTemplateBody())
					return
				}
				owner := "starbeacon"
				mappings := string(legacyJSON)
				if mode == "foreign_owner" {
					owner = "external"
				}
				if mode == "unknown_v1" {
					mappings = strings.Replace(mappings, `"strict"`, `"true"`, 1)
				}
				fmt.Fprintf(w, `{"index_templates":[{"name":"%s","index_template":{"index_patterns":["sb-alerts-*","sb-context-*"],"allow_auto_create":false,"priority":151,"version":1,"_meta":{"owner":"%s","schema":1},"template":{"mappings":%s}}}]}`, eventTemplateName, owner, mappings)
			}))
			defer server.Close()
			es, err := OpenES(server.URL, "")
			if err != nil {
				t.Fatal(err)
			}
			ready, err := es.eventTemplateExists(context.Background())
			if mode == "owned_v1" || mode == "current_v2" {
				if !ready || err != nil {
					t.Fatal("已知映射未取得确认", err)
				}
			} else if ready || err == nil {
				t.Fatal("未知或未确认映射被接受")
			}
			if (mode == "foreign_owner" || mode == "unknown_v1" || mode == "current_v2") && puts != 0 {
				t.Fatal("覆盖了外部或已一致模板")
			}
			if mode == "owned_v1" && (puts != 1 || gets != 2) {
				t.Fatal("升级没有独立回读")
			}
		})
	}
}
