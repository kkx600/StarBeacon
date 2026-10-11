package llm

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/outbound"
)

const fixtureKey = "owned-model-fixture-secret"

func fixtureConfig(kind, url string) Config {
	return Config{Name: "生成接口", Kind: kind, BaseURL: url + "/v1", Model: "owned-model", APIKey: fixtureKey, Enabled: true, MaxOutputTokens: 256, TimeoutSeconds: 5, DailyRequests: 10}
}

func fixturePolicy(server *httptest.Server) outbound.Policy {
	networks, _ := outbound.ParseNetworks("127.0.0.0/8")
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	return outbound.Policy{PrivateNetworks: networks, Roots: roots}
}

func fixtureResponse(kind string) map[string]any {
	if kind == "openai_chat" {
		return map[string]any{"id": "owned-completion", "object": "chat.completion", "model": "owned-model", "choices": []any{map[string]any{"index": 0, "finish_reason": "stop", "message": map[string]any{"role": "assistant", "content": "连接成功。"}}}, "usage": map[string]any{"prompt_tokens": 3, "completion_tokens": 4, "total_tokens": 7}}
	}
	return map[string]any{"id": "owned-response", "object": "response", "status": "completed", "model": "owned-model", "output": []any{map[string]any{"type": "message", "role": "assistant", "id": "owned-message", "status": "completed", "content": []any{map[string]any{"type": "output_text", "text": "连接成功。", "annotations": []any{}}}}}, "usage": map[string]any{"input_tokens": 3, "output_tokens": 4, "total_tokens": 7}}
}

func TestOfficialSDKRequestsAndUsage(t *testing.T) {
	t.Setenv("OPENAI_ORG_ID", "must-not-cross-tenant")
	t.Setenv("OPENAI_PROJECT_ID", "must-not-cross-tenant")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	for _, kind := range []string{"openai_responses", "openai_chat"} {
		t.Run(kind, func(t *testing.T) {
			requests := make(chan map[string]any, 1)
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer "+fixtureKey || r.Header.Get("OpenAI-Organization") != "" || r.Header.Get("OpenAI-Project") != "" {
					t.Error("提供方身份不正确或继承了其他租户的环境身份")
				}
				path := "/v1/responses"
				if kind == "openai_chat" {
					path = "/v1/chat/completions"
				}
				if r.Method != "POST" || r.URL.Path != path {
					t.Error("生成协议路径错误", r.Method, r.URL.Path)
				}
				var payload map[string]any
				if err := json.NewDecoder(io.LimitReader(r.Body, 32769)).Decode(&payload); err != nil {
					t.Error(err)
				}
				requests <- payload
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(fixtureResponse(kind))
			}))
			defer server.Close()
			result := (Client{Policy: fixturePolicy(server)}).Generate(context.Background(), fixtureConfig(kind, server.URL), "只验证连接", "连接验证", 64)
			if result.State != "succeeded" || result.Code != "completed" || result.Text != "连接成功。" || result.ReturnedModel != "owned-model" || result.Usage == nil || *result.Usage != (Usage{3, 4, 7}) {
				t.Fatalf("协议响应解析错误：%+v", result)
			}
			payload := <-requests
			if payload["store"] != false || payload["model"] != "owned-model" {
				t.Fatal("存储策略或请求模型错误", payload)
			}
			if kind == "openai_responses" {
				if payload["truncation"] != "disabled" || payload["input"] != "连接验证" || payload["max_output_tokens"] != float64(64) {
					t.Fatal("Responses 请求边界错误", payload)
				}
			} else if payload["max_completion_tokens"] != float64(64) {
				t.Fatal("Chat 请求输出上限错误", payload)
			}
		})
	}
}

func TestGenerationRejectsIncompleteRefusedAndUntrustedResults(t *testing.T) {
	cases := []struct {
		name, kind, state, code string
		change                  func(map[string]any)
	}{
		{"responses_incomplete", "openai_responses", "incomplete", "incomplete_output", func(v map[string]any) { v["status"] = "incomplete" }},
		{"responses_refusal", "openai_responses", "refused", "provider_refused", func(v map[string]any) {
			v["output"] = []any{map[string]any{"type": "message", "content": []any{map[string]any{"type": "refusal", "refusal": "拒绝"}}}}
		}},
		{"responses_tool", "openai_responses", "failed", "unexpected_tool_call", func(v map[string]any) {
			v["output"] = []any{map[string]any{"type": "function_call", "name": "execute", "arguments": "{}"}}
		}},
		{"chat_incomplete", "openai_chat", "incomplete", "incomplete_output", func(v map[string]any) { v["choices"].([]any)[0].(map[string]any)["finish_reason"] = "length" }},
		{"chat_filter", "openai_chat", "refused", "provider_refused", func(v map[string]any) { v["choices"].([]any)[0].(map[string]any)["finish_reason"] = "content_filter" }},
		{"chat_refusal", "openai_chat", "refused", "provider_refused", func(v map[string]any) {
			v["choices"].([]any)[0].(map[string]any)["message"].(map[string]any)["refusal"] = "拒绝"
		}},
		{"chat_tool", "openai_chat", "failed", "unexpected_tool_call", func(v map[string]any) { v["choices"].([]any)[0].(map[string]any)["finish_reason"] = "tool_calls" }},
		{"chat_no_choices", "openai_chat", "failed", "invalid_response", func(v map[string]any) { v["choices"] = []any{} }},
		{"bad_model", "openai_responses", "failed", "invalid_response", func(v map[string]any) { v["model"] = "untrusted\nmodel" }},
		{"missing_model", "openai_chat", "failed", "invalid_response", func(v map[string]any) { delete(v, "model") }},
		{"secret_model", "openai_chat", "failed", "invalid_response", func(v map[string]any) { v["model"] = fixtureKey }},
		{"secret_echo", "openai_chat", "failed", "invalid_response", func(v map[string]any) {
			v["choices"].([]any)[0].(map[string]any)["message"].(map[string]any)["content"] = fixtureKey
		}},
		{"oversized_text", "openai_chat", "failed", "invalid_response", func(v map[string]any) {
			v["choices"].([]any)[0].(map[string]any)["message"].(map[string]any)["content"] = strings.Repeat("x", 65537)
		}},
		{"nul_text", "openai_chat", "failed", "invalid_response", func(v map[string]any) {
			v["choices"].([]any)[0].(map[string]any)["message"].(map[string]any)["content"] = "a\x00b"
		}},
		{"empty_text", "openai_chat", "failed", "empty_response", func(v map[string]any) {
			v["choices"].([]any)[0].(map[string]any)["message"].(map[string]any)["content"] = "  "
		}},
		{"bad_usage", "openai_responses", "failed", "invalid_usage", func(v map[string]any) {
			v["usage"] = map[string]any{"input_tokens": -1, "output_tokens": 4, "total_tokens": 3}
		}},
		{"inconsistent_usage", "openai_chat", "failed", "invalid_usage", func(v map[string]any) {
			v["usage"] = map[string]any{"prompt_tokens": 3, "completion_tokens": 4, "total_tokens": 0}
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				v := fixtureResponse(test.kind)
				test.change(v)
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(v)
			}))
			defer server.Close()
			result := (Client{Policy: fixturePolicy(server)}).Generate(context.Background(), fixtureConfig(test.kind, server.URL), "连接验证", "连接验证", 64)
			if result.State != test.state || result.Code != test.code || result.Text != "" || strings.Contains(result.ReturnedModel, fixtureKey) {
				t.Fatalf("未拒绝不可信响应：%+v", result)
			}
		})
	}
}

func TestMissingUsageRemainsUnknown(t *testing.T) {
	for _, kind := range []string{"openai_responses", "openai_chat"} {
		for _, missing := range []string{"whole", "null", "input", "total", "zero"} {
			t.Run(kind+"_"+missing, func(t *testing.T) {
				server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					v := fixtureResponse(kind)
					switch missing {
					case "whole":
						delete(v, "usage")
					case "null":
						v["usage"] = nil
					case "input":
						key := "input_tokens"
						if kind == "openai_chat" {
							key = "prompt_tokens"
						}
						delete(v["usage"].(map[string]any), key)
					case "total":
						delete(v["usage"].(map[string]any), "total_tokens")
					case "zero":
						for key := range v["usage"].(map[string]any) {
							v["usage"].(map[string]any)[key] = 0
						}
					}
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(v)
				}))
				defer server.Close()
				result := (Client{Policy: fixturePolicy(server)}).Generate(context.Background(), fixtureConfig(kind, server.URL), "连接验证", "连接验证", 64)
				if result.State != "succeeded" {
					t.Fatal(result)
				}
				if missing == "zero" {
					if result.Usage == nil || *result.Usage != (Usage{}) {
						t.Fatal("真实零用量丢失", result)
					}
				} else if result.Usage != nil {
					t.Fatal("缺失用量被伪造为零", result)
				}
			})
		}
	}
}

func TestRequestFailuresNeverRetryOrExposeProviderErrors(t *testing.T) {
	for _, test := range []struct {
		status      int
		state, code string
	}{{400, "failed", "provider_rejected"}, {401, "failed", "provider_rejected"}, {408, "uncertain", "provider_result_unknown"}, {429, "failed", "provider_rate_limited"}, {500, "uncertain", "provider_result_unknown"}, {503, "uncertain", "provider_result_unknown"}, {302, "failed", "provider_redirect"}} {
		t.Run(http.StatusText(test.status), func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Location", "https://127.0.0.1:1/credential-leak")
				w.WriteHeader(test.status)
				_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"message": fixtureKey, "type": "owned_error"}})
			}))
			defer server.Close()
			result := (Client{Policy: fixturePolicy(server)}).Generate(context.Background(), fixtureConfig("openai_responses", server.URL), "连接验证", "连接验证", 64)
			if result.State != test.state || result.Code != test.code || result.HTTPStatus != test.status || calls.Load() != 1 {
				t.Fatal("状态或重试次数错误", result, calls.Load())
			}
			raw, _ := json.Marshal(result)
			if strings.Contains(string(raw), fixtureKey) {
				t.Fatal("提供方错误泄漏凭据")
			}
		})
	}
}

func TestResponseLimitsAndCancellation(t *testing.T) {
	for _, test := range []struct{ name, body, code string }{{"malformed", "{broken", "provider_result_unknown"}, {"large", strings.Repeat("x", 1024*1024+1), "response_too_large"}} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, test.body)
			}))
			defer server.Close()
			result := (Client{Policy: fixturePolicy(server)}).Generate(context.Background(), fixtureConfig("openai_chat", server.URL), "连接验证", "连接验证", 64)
			if result.Code != test.code {
				t.Fatal("响应限制未执行", result)
			}
		})
	}
	started := make(chan struct{}, 1)
	released := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		started <- struct{}{}
		select {
		case <-r.Context().Done():
		case <-released:
		}
	}))
	defer server.Close()
	defer close(released)
	ctx, cancel := context.WithCancel(context.Background())
	results := make(chan Result, 1)
	go func() {
		results <- (Client{Policy: fixturePolicy(server)}).Generate(ctx, fixtureConfig("openai_chat", server.URL), "连接验证", "连接验证", 64)
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("请求未到达提供方")
	}
	cancel()
	select {
	case result := <-results:
		if result.State != "uncertain" || result.Code != "provider_result_unknown" {
			t.Fatal("取消后错误宣称未执行", result)
		}
	case <-time.After(time.Second):
		t.Fatal("模型请求不响应取消")
	}
}

func TestConfigAndOutboundRestrictions(t *testing.T) {
	config := fixtureConfig("openai_chat", "https://models.example")
	for _, mutate := range []func(*Config){func(c *Config) { c.Kind = "unknown" }, func(c *Config) { c.Name = "" }, func(c *Config) { c.Model = "\n" }, func(c *Config) { c.MaxOutputTokens = 63 }, func(c *Config) { c.MaxOutputTokens = 8193 }, func(c *Config) { c.TimeoutSeconds = 4 }, func(c *Config) { c.TimeoutSeconds = 121 }, func(c *Config) { c.DailyRequests = 0 }, func(c *Config) { c.DailyRequests = 10001 }, func(c *Config) { c.BaseURL = "https://model.example?key=secret" }, func(c *Config) { c.BaseURL = "http://model.example" }, func(c *Config) { c.BaseURL = "https://model.example/a/../v1" }, func(c *Config) { c.APIKey = " key" }} {
		invalid := config
		mutate(&invalid)
		if invalid.Validate(outbound.Policy{}) == nil {
			t.Fatal("无效配置被接受", invalid.Public())
		}
	}
	public := config.Public()
	raw, _ := json.Marshal(public)
	if !public.HasKey || strings.Contains(string(raw), fixtureKey) {
		t.Fatal("公开配置凭据处理错误")
	}
	encoded, err := Encode(config)
	if err != nil || !strings.Contains(string(encoded), fixtureKey) {
		t.Fatal("加密前配置编码失败")
	}
	for _, target := range []string{"https://127.0.0.1:1", "https://169.254.169.254", "https://8.8.8.8:1"} {
		config.BaseURL = target
		result := (Client{}).Generate(context.Background(), config, "连接验证", "连接验证", 64)
		if result.Code != "target_denied" {
			t.Fatal("模型未阻止未授权访问", target, result)
		}
	}
	config = fixtureConfig("openai_chat", "https://models.example")
	for _, test := range []struct {
		instructions, prompt string
		tokens               int64
		disabled             bool
	}{{"连接", "\x00", 64, false}, {"连接", strings.Repeat("a", 24577), 64, false}, {"连接", "连接", 257, false}, {"连接", "连接", 0, false}, {"连接", "连接", 64, true}, {"连接", string([]byte{0xff}), 64, false}} {
		config.Enabled = !test.disabled
		result := (Client{}).Generate(context.Background(), config, test.instructions, test.prompt, test.tokens)
		if result.Code != "invalid_config" {
			t.Fatal("无效生成请求被接受", result)
		}
	}
}

func TestBoundedBodyExactSizeAndZeroRead(t *testing.T) {
	reader := &boundedBody{ReadCloser: io.NopCloser(strings.NewReader("abc")), remaining: 3}
	if n, err := reader.Read(nil); n != 0 || err != nil {
		t.Fatal("空缓冲读取错误", n, err)
	}
	data, err := io.ReadAll(reader)
	if err != nil || string(data) != "abc" {
		t.Fatal("恰好达到上限的响应被拒绝", string(data), err)
	}
}
