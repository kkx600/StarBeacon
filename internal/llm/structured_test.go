package llm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestStructuredOutputUsesOfficialProtocolsWithoutDowngradeOrRetry(t *testing.T) {
	schema := map[string]any{"type": "object", "additionalProperties": false, "required": []string{"value"}, "properties": map[string]any{"value": map[string]any{"type": "string"}}}
	for _, kind := range []string{"openai_responses", "openai_chat"} {
		for _, reject := range []bool{false, true} {
			var calls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				var body map[string]any
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
				}
				var format map[string]any
				if kind == "openai_responses" {
					format = body["text"].(map[string]any)["format"].(map[string]any)
				} else {
					outer := body["response_format"].(map[string]any)
					if outer["type"] != "json_schema" {
						t.Error("Chat 格式不是 JSON Schema")
					}
					format = outer["json_schema"].(map[string]any)
				}
				if format["name"] != "owned_schema" || format["strict"] != true || format["schema"].(map[string]any)["additionalProperties"] != false || body["store"] != false {
					t.Error("严格契约或存储策略丢失")
				}
				w.Header().Set("Content-Type", "application/json")
				if reject {
					w.WriteHeader(400)
					_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"message": "unsupported json_schema", "type": "invalid_request_error"}})
					return
				}
				_ = json.NewEncoder(w).Encode(fixtureResponse(kind))
			}))
			defer server.Close()
			result := (Client{Policy: fixturePolicy(server)}).GenerateJSON(context.Background(), fixtureConfig(kind, server.URL), "仅返回指定结构", "合法材料", 128, "owned_schema", schema)
			if calls.Load() != 1 || (reject && (result.State != "failed" || result.Code != "provider_rejected" || result.HTTPStatus != 400 || result.Text != "")) || (!reject && result.State != "succeeded") {
				t.Fatal("结构化协议被降级或重复调用", kind, reject, result, calls.Load())
			}
		}
	}
}

func TestStructuredOutputRejectsInvalidSchemaBeforeSending(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer server.Close()
	client := Client{Policy: fixturePolicy(server)}
	config := fixtureConfig("openai_responses", server.URL)
	valid := func() map[string]any { return map[string]any{"type": "object", "additionalProperties": false} }
	for _, name := range []string{"", "invalid space", "异常名称", strings.Repeat("a", 65)} {
		if result := client.GenerateJSON(context.Background(), config, "", "合法材料", 128, name, valid()); result.Code != "invalid_config" {
			t.Fatal("非法格式名被发送")
		}
	}
	for _, schema := range []map[string]any{nil, {}, {"type": "array", "additionalProperties": false}, {"type": "object", "additionalProperties": true}, {"type": "object", "additionalProperties": false, "invalid": func() {}}, {"type": "object", "additionalProperties": false, "description": strings.Repeat("a", 8193)}} {
		if result := client.GenerateJSON(context.Background(), config, "", "合法材料", 128, "owned", schema); result.Code != "invalid_config" {
			t.Fatal("非法 Schema 被发送")
		}
	}
	if calls.Load() != 0 {
		t.Fatal("无效结构化输入消耗了模型调用")
	}
}
