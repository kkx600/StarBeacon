// Package llm 使用官方 SDK 接入生成式模型，连接验证与安全领域评测分别记录。
package llm

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptrace"
	"strings"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/kkx600/StarBeacon/internal/outbound"
	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	"github.com/openai/openai-go/v3/responses"
	"github.com/openai/openai-go/v3/shared"
)

var ErrConfig = errors.New("模型提供方配置无效")
var ErrResponseLimit = errors.New("模型响应超过资源限制")

type Config struct {
	Name            string `json:"name"`
	Kind            string `json:"kind"`
	BaseURL         string `json:"base_url"`
	Model           string `json:"model"`
	APIKey          string `json:"api_key"`
	Enabled         bool   `json:"enabled"`
	AllowExternal   bool   `json:"allow_external"`
	MaxOutputTokens int64  `json:"max_output_tokens"`
	TimeoutSeconds  int    `json:"timeout_seconds"`
	DailyRequests   int    `json:"daily_requests"`
}

func clean(value string, limit int) bool {
	return utf8.ValidString(value) && strings.TrimSpace(value) == value && len([]rune(value)) <= limit && strings.IndexFunc(value, unicode.IsControl) == -1
}

func (c Config) Validate(policy outbound.Policy) error {
	u, err := policy.URL(c.BaseURL)
	if err != nil {
		return err
	}
	if u.RawQuery != "" || u.RawPath != "" || strings.Contains(u.Path, "..") || !clean(c.Name, 128) || c.Name == "" || !clean(c.Model, 128) || c.Model == "" || !clean(c.APIKey, 4096) || c.MaxOutputTokens < 64 || c.MaxOutputTokens > 8192 || c.TimeoutSeconds < 5 || c.TimeoutSeconds > 120 || c.DailyRequests < 1 || c.DailyRequests > 10000 {
		return ErrConfig
	}
	if c.Kind != "openai_responses" && c.Kind != "openai_chat" {
		return ErrConfig
	}
	return nil
}

type Provider struct {
	ID              string    `json:"id"`
	Revision        int64     `json:"revision"`
	Name            string    `json:"name"`
	Kind            string    `json:"kind"`
	BaseURL         string    `json:"base_url"`
	Model           string    `json:"model"`
	Enabled         bool      `json:"enabled"`
	AllowExternal   bool      `json:"allow_external"`
	MaxOutputTokens int64     `json:"max_output_tokens"`
	TimeoutSeconds  int       `json:"timeout_seconds"`
	DailyRequests   int       `json:"daily_requests"`
	HasKey          bool      `json:"has_key"`
	UpdatedAt       time.Time `json:"updated_at"`
	Check           *Check    `json:"check"`
}

func (c Config) Public() Provider {
	return Provider{Name: c.Name, Kind: c.Kind, BaseURL: c.BaseURL, Model: c.Model, Enabled: c.Enabled, AllowExternal: c.AllowExternal, MaxOutputTokens: c.MaxOutputTokens, TimeoutSeconds: c.TimeoutSeconds, DailyRequests: c.DailyRequests, HasKey: c.APIKey != ""}
}

type Usage struct {
	InputTokens  int64 `json:"input_tokens"`
	OutputTokens int64 `json:"output_tokens"`
	TotalTokens  int64 `json:"total_tokens"`
}

type Result struct {
	State         string `json:"state"`
	Code          string `json:"code"`
	ReturnedModel string `json:"returned_model,omitempty"`
	Text          string `json:"text,omitempty"`
	Usage         *Usage `json:"usage"`
	HTTPStatus    int    `json:"http_status,omitempty"`
	DurationMS    *int64 `json:"duration_ms"`
}

type Check struct {
	ID               string     `json:"id"`
	ProviderRevision int64      `json:"provider_revision"`
	State            string     `json:"state"`
	Result           Result     `json:"result"`
	CreatedAt        time.Time  `json:"created_at"`
	FinishedAt       *time.Time `json:"finished_at"`
}

type boundedBody struct {
	io.ReadCloser
	remaining int64
}

func (b *boundedBody) Read(buffer []byte) (int, error) {
	if len(buffer) == 0 {
		return 0, nil
	}
	if b.remaining == 0 {
		var extra [1]byte
		n, err := b.ReadCloser.Read(extra[:])
		if n > 0 {
			return 0, ErrResponseLimit
		}
		return 0, err
	}
	if int64(len(buffer)) > b.remaining {
		buffer = buffer[:b.remaining]
	}
	n, err := b.ReadCloser.Read(buffer)
	b.remaining -= int64(n)
	return n, err
}

type boundedTransport struct{ base http.RoundTripper }

type redirectError struct{ status int }

func (redirectError) Error() string { return "模型提供方返回重定向" }

func (b boundedTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := b.base.RoundTrip(request)
	if err == nil {
		if response.StatusCode >= 300 && response.StatusCode < 400 {
			_ = response.Body.Close()
			return nil, redirectError{response.StatusCode}
		}
		response.Body = &boundedBody{ReadCloser: response.Body, remaining: 1024 * 1024}
	}
	return response, err
}

type Client struct{ Policy outbound.Policy }

// 请求可能已由提供方执行时，不自动重试或推断费用为零。
func (c Client) Generate(ctx context.Context, config Config, instructions, prompt string, maxTokens int64) (out Result) {
	return c.generate(ctx, config, instructions, prompt, maxTokens, "", nil)
}

// GenerateJSON 要求提供方支持严格 JSON Schema。拒绝不支持的协议，不静默降级或重复计费。
// Schema 由业务代码定义，不接收模型返回的工具、远程引用或用户提供的协议配置。
func (c Client) GenerateJSON(ctx context.Context, config Config, instructions, prompt string, maxTokens int64, name string, schema map[string]any) Result {
	if name == "" || schema == nil {
		duration := int64(0)
		return Result{State: "failed", Code: "invalid_config", DurationMS: &duration}
	}
	return c.generate(ctx, config, instructions, prompt, maxTokens, name, schema)
}

func (c Client) generate(ctx context.Context, config Config, instructions, prompt string, maxTokens int64, name string, schema map[string]any) (out Result) {
	started := time.Now()
	out = Result{State: "failed", Code: "invalid_config"}
	defer func() {
		duration := time.Since(started).Milliseconds()
		out.DurationMS = &duration
	}()
	if config.Validate(c.Policy) != nil || !config.Enabled || !utf8.ValidString(prompt) || !utf8.ValidString(instructions) || len(prompt)+len(instructions) > 24576 || strings.ContainsAny(prompt+instructions, "\x00") || maxTokens < 1 || maxTokens > config.MaxOutputTokens {
		return out
	}
	if schema != nil || name != "" {
		raw, err := json.Marshal(schema)
		if err != nil || schema == nil || name == "" || len(name) > 64 || strings.IndexFunc(name, func(r rune) bool {
			return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-')
		}) >= 0 || len(raw) > 8192 || schema["type"] != "object" || schema["additionalProperties"] != false {
			return out
		}
	}
	work, cancel := context.WithTimeout(ctx, time.Duration(config.TimeoutSeconds)*time.Second)
	defer cancel()
	var sent atomic.Bool
	work = httptrace.WithClientTrace(work, &httptrace.ClientTrace{WroteRequest: func(info httptrace.WroteRequestInfo) { sent.Store(info.Err == nil) }})
	policy := c.Policy
	policy.PrivateOnly = !config.AllowExternal
	httpClient := policy.HTTPClient()
	transport := httpClient.Transport.(*http.Transport)
	transport.ResponseHeaderTimeout = time.Duration(config.TimeoutSeconds) * time.Second
	httpClient.Timeout = time.Duration(config.TimeoutSeconds) * time.Second
	httpClient.Transport = boundedTransport{transport}
	defer transport.CloseIdleConnections()
	client := openai.NewClient(option.WithAPIKey(config.APIKey), option.WithOrganization(""), option.WithProject(""), option.WithBaseURL(strings.TrimRight(config.BaseURL, "/")+"/"), option.WithHTTPClient(httpClient), option.WithMaxRetries(0))
	var failure error
	if config.Kind == "openai_responses" {
		var response *responses.Response
		params := responses.ResponseNewParams{Model: config.Model, Instructions: openai.String(instructions), Input: responses.ResponseNewParamsInputUnion{OfString: openai.String(prompt)}, MaxOutputTokens: openai.Int(maxTokens), Store: openai.Bool(false), Truncation: responses.ResponseNewParamsTruncationDisabled}
		if schema != nil {
			params.Text = responses.ResponseTextConfigParam{Format: responses.ResponseFormatTextConfigUnionParam{OfJSONSchema: &responses.ResponseFormatTextJSONSchemaConfigParam{Name: name, Schema: schema, Strict: openai.Bool(true)}}}
		}
		response, failure = client.Responses.New(work, params)
		if failure == nil {
			out.ReturnedModel = response.Model
			if response.JSON.Usage.Valid() && response.Usage.JSON.InputTokens.Valid() && response.Usage.JSON.OutputTokens.Valid() && response.Usage.JSON.TotalTokens.Valid() {
				out.Usage = &Usage{response.Usage.InputTokens, response.Usage.OutputTokens, response.Usage.TotalTokens}
			}
			out.Text = response.OutputText()
			out.State, out.Code = "succeeded", "completed"
			if response.Status != responses.ResponseStatusCompleted {
				out.State, out.Code = "incomplete", "incomplete_output"
			}
			for _, item := range response.Output {
				if item.Type == "message" {
					for _, part := range item.Content {
						if part.Type == "refusal" {
							out.State, out.Code = "refused", "provider_refused"
						}
					}
				} else if item.Type != "reasoning" {
					out.State, out.Code = "failed", "unexpected_tool_call"
				}
			}
		}
	} else {
		var response *openai.ChatCompletion
		params := openai.ChatCompletionNewParams{Model: config.Model, Messages: []openai.ChatCompletionMessageParamUnion{openai.SystemMessage(instructions), openai.UserMessage(prompt)}, MaxCompletionTokens: openai.Int(maxTokens), Store: openai.Bool(false)}
		if schema != nil {
			params.ResponseFormat = openai.ChatCompletionNewParamsResponseFormatUnion{OfJSONSchema: &shared.ResponseFormatJSONSchemaParam{JSONSchema: shared.ResponseFormatJSONSchemaJSONSchemaParam{Name: name, Schema: schema, Strict: openai.Bool(true)}}}
		}
		response, failure = client.Chat.Completions.New(work, params)
		if failure == nil {
			out.ReturnedModel = response.Model
			if response.JSON.Usage.Valid() && response.Usage.JSON.PromptTokens.Valid() && response.Usage.JSON.CompletionTokens.Valid() && response.Usage.JSON.TotalTokens.Valid() {
				out.Usage = &Usage{response.Usage.PromptTokens, response.Usage.CompletionTokens, response.Usage.TotalTokens}
			}
			out.State, out.Code = "failed", "invalid_response"
			if len(response.Choices) == 1 {
				choice := response.Choices[0]
				out.Text = choice.Message.Content
				switch choice.FinishReason {
				case "stop":
					out.State, out.Code = "succeeded", "completed"
				case "length":
					out.State, out.Code = "incomplete", "incomplete_output"
				case "content_filter":
					out.State, out.Code = "refused", "provider_refused"
				default:
					out.State, out.Code = "failed", "unexpected_tool_call"
				}
				if choice.Message.Refusal != "" {
					out.State, out.Code = "refused", "provider_refused"
				}
				if len(choice.Message.ToolCalls) > 0 {
					out.State, out.Code = "failed", "unexpected_tool_call"
				}
			}
		}
	}
	if failure != nil {
		out.State, out.Code = "failed", "provider_unavailable"
		var api *openai.Error
		var redirect redirectError
		switch {
		case errors.Is(failure, outbound.ErrTarget):
			out.Code = "target_denied"
		case errors.Is(failure, ErrResponseLimit):
			out.Code = "response_too_large"
		case errors.As(failure, &redirect):
			out.Code, out.HTTPStatus = "provider_redirect", redirect.status
		case errors.As(failure, &api):
			out.HTTPStatus = api.StatusCode
			out.Code = "provider_rejected"
			if api.StatusCode >= 500 || api.StatusCode == 408 {
				out.State, out.Code = "uncertain", "provider_result_unknown"
			}
			if api.StatusCode == 429 {
				out.Code = "provider_rate_limited"
			}
		case sent.Load():
			out.State, out.Code = "uncertain", "provider_result_unknown"
		case work.Err() != nil:
			out.Code = "request_cancelled"
		}
		return out
	}
	if !clean(out.ReturnedModel, 128) || out.ReturnedModel == "" || len(out.Text) > 65536 || !utf8.ValidString(out.Text) || strings.ContainsRune(out.Text, 0) || (config.APIKey != "" && (strings.Contains(out.Text, config.APIKey) || strings.Contains(out.ReturnedModel, config.APIKey))) {
		out.State, out.Code, out.Text, out.ReturnedModel = "failed", "invalid_response", "", ""
	}
	if out.Usage != nil && (out.Usage.InputTokens < 0 || out.Usage.OutputTokens < 0 || out.Usage.InputTokens > 10_000_000 || out.Usage.OutputTokens > 10_000_000 || out.Usage.TotalTokens != out.Usage.InputTokens+out.Usage.OutputTokens) {
		out.State, out.Code, out.Usage = "failed", "invalid_usage", nil
	}
	if out.State == "succeeded" && strings.TrimSpace(out.Text) == "" {
		out.State, out.Code = "failed", "empty_response"
	}
	if out.State != "succeeded" {
		out.Text = ""
	}
	return out
}

func Encode(config Config) ([]byte, error) { return json.Marshal(config) }
