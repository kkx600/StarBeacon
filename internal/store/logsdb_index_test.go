package store

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestLogsDBTemplateRejectsSourceModeSortAndUnexpectedSettings(t *testing.T) {
	for _, tc := range []struct{ name, old, replacement string }{
		{"来源模式", `"index.mapping.source.mode":"stored"`, `"index.mapping.source.mode":"synthetic"`},
		{"排序字段", `"tenant_id","sensor_id","@timestamp"`, `"sensor_id","tenant_id","@timestamp"`},
		{"额外设置", `"index.mode":"logsdb"`, `"index.mode":"logsdb","index.blocks.write":"true"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			template := contextLogsDBTemplate
			body := strings.Replace(template.body(), tc.old, tc.replacement, 1)
			if body == template.body() {
				t.Fatal("测试没有构造模板漂移")
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/_index_template/"+template.name || r.URL.Query().Get("flat_settings") != "true" {
					t.Error("漂移时尝试改写模板或未按静态设置回读", r.Method, r.URL.Path)
					w.WriteHeader(400)
					return
				}
				fmt.Fprintf(w, `{"index_templates":[{"name":%q,"index_template":%s}]}`, template.name, body)
			}))
			defer server.Close()
			es, err := OpenES(server.URL, "")
			if err != nil {
				t.Fatal(err)
			}
			if err = es.ensureSharedTemplate(context.Background(), template); err == nil {
				t.Fatal("漂移模板被接纳")
			}
		})
	}
}

func TestLogsDBIndexRejectsAnUnverifiedModeOrLifecycle(t *testing.T) {
	template := logsLogsDBTemplate
	const index = "sb-v2-logs-logsdb-r180-d2026.11.25"
	origin := time.Date(2026, 11, 25, 0, 0, 0, 0, time.UTC)
	var mapping map[string]any
	if err := json.Unmarshal([]byte(template.mapping), &mapping); err != nil {
		t.Fatal(err)
	}
	mapping["_data_stream_timestamp"] = map[string]any{"enabled": true}
	for _, field := range []string{"index.mode", "index.mapping.source.mode", "index.lifecycle.origination_date"} {
		t.Run(field, func(t *testing.T) {
			settings := template.settings()
			settings["index.lifecycle.name"] = retentionPolicyName(181)
			settings["index.lifecycle.origination_date"] = fmt.Sprint(origin.UnixMilli())
			settings[field] = "drifted"
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/"+index || r.URL.Query().Get("flat_settings") != "true" {
					t.Error("未先拒绝无法确认的索引设置", r.URL.Path)
					w.WriteHeader(400)
					return
				}
				json.NewEncoder(w).Encode(map[string]any{index: map[string]any{"mappings": mapping, "settings": settings}})
			}))
			defer server.Close()
			es, err := OpenES(server.URL, "")
			if err != nil {
				t.Fatal(err)
			}
			if err = es.verifyIndex(context.Background(), index, template, origin, 181); err == nil ||
				!strings.Contains(err.Error(), "静态设置或生命周期") {
				t.Fatal("静态设置或时间起点漂移没有被明确拒绝", err)
			}
		})
	}
}
