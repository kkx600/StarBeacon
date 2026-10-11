package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/mcpaccess"
	"github.com/kkx600/StarBeacon/internal/searchfilter"
	"github.com/kkx600/StarBeacon/internal/traffic"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func decodeToolData[T any](t *testing.T, result *mcp.CallToolResult) T {
	t.Helper()
	raw, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Data T `json:"data"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	return envelope.Data
}

func TestOfficialClientProtocolSearchCatalogAndExpressionValidation(t *testing.T) {
	_, backend, endpoint, _ := fixture(t)
	ctx, stop := context.WithTimeout(context.Background(), 20*time.Second)
	defer stop()
	client := endpoint.Client()
	client.Transport = bearerTransport{"owned-token", client.Transport}
	session, err := mcp.NewClient(&mcp.Implementation{Name: "protocol-agent", Version: "test"}, nil).Connect(ctx, &mcp.StreamableClientTransport{Endpoint: endpoint.URL + "/mcp", HTTPClient: client, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	call := func(name string, args any) *mcp.CallToolResult {
		t.Helper()
		result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
		if err != nil || result.IsError {
			t.Fatal(name, err, result)
		}
		return result
	}
	for _, dataset := range []string{"alerts", "context"} {
		prefix := "alerts"
		if dataset == "context" {
			prefix = "traffic"
		}
		catalog := decodeToolData[FieldCatalog](t, call(prefix+".fields", map[string]any{}))
		if catalog.Dataset != dataset || catalog.Version != searchfilter.Version || len(catalog.Fields) < 30 {
			t.Fatal("字段目录身份或完整性错误", catalog)
		}
		for _, field := range catalog.Fields {
			if dataset == "context" && (strings.HasPrefix(field.Name, "rule.") || field.Name == "severity") {
				t.Fatal("协议目录包含告警专属字段", field)
			}
			if len(field.Operators) == 0 {
				t.Fatal("未提供字段运算符", field)
			}
		}
		for _, expression := range []string{"", "tcp.port in {80 443} && not ip.addr == 192.0.2.1", "dns"} {
			validation := decodeToolData[FilterValidation](t, call(prefix+".filter.validate", FilterInput{Filter: expression}))
			if !validation.Valid || validation.Error != nil || validation.Dataset != dataset {
				t.Fatal("有效表达式未通过", expression, validation)
			}
		}
		for _, expression := range []string{"tcp and (", "tenant_id == foreign", strings.Repeat("a", 4097)} {
			validation := decodeToolData[FilterValidation](t, call(prefix+".filter.validate", FilterInput{Filter: expression}))
			if validation.Valid || validation.Error == nil || validation.Error.Line < 1 || validation.Error.Column < 1 || validation.Error.Message == "" {
				t.Fatal("无效表达式未返回位置及原因", expression[:min(len(expression), 30)], validation)
			}
		}
	}
	if backend.queries != 0 {
		t.Fatal("目录或表达式校验执行了业务查询")
	}
	validation := decodeToolData[FilterValidation](t, call("traffic.filter.validate", FilterInput{Filter: "tcp or (suricata.sid == 1)"}))
	if validation.Valid || validation.Error == nil {
		t.Fatal("告警别名绕过协议数据集限制")
	}
	window := map[string]any{"start": "2026-10-02T00:00:00Z", "end": "2026-10-03T00:00:00Z", "event_kind": "tls", "sensor_id": "probe_owned", "flow_id": "18446744073709551615"}
	result := call("traffic.search", window)
	data := decodeToolData[struct {
		Items    []traffic.Record `json:"items"`
		Total    string           `json:"total"`
		Page     int              `json:"page"`
		PageSize int              `json:"page_size"`
	}](t, result)
	if backend.queries != 1 || data.Total != "9007199254740993" || data.Page != 1 || data.PageSize != 20 || len(data.Items) != 1 || data.Items[0].Details.TLS == nil || data.Items[0].Details.TLS.SNI != "service.example" || data.Items[0].Details.Flow == nil || data.Items[0].Details.Flow.BytesToServer != "18446744073709551615" {
		t.Fatal("协议元数据或计数精度错误", data)
	}
	raw, _ := json.Marshal(result.StructuredContent)
	if strings.Contains(string(raw), "private-payload") || strings.Contains(string(raw), "private-registration") || !strings.Contains(string(raw), "\"truncated\":true") || !strings.Contains(string(raw), "TLS 已解密") || !strings.Contains(string(raw), "实时带宽") {
		t.Fatal("结果缺少权限或统计语义边界", string(raw))
	}
	for _, change := range []map[string]any{{"tenant_id": "foreign"}, {"sensor_registration_id": "private-registration"}, {"keyword": "alert"}, {"severity": "high"}, {"page": 101}, {"page": -1}, {"page_size": 101}, {"event_kind": "alert"}, {"filter": "rule.id == 1"}, {"flow_id": "01"}, {"end": "2026-11-03T00:00:00Z"}} {
		input := mapsClone(window)
		for key, value := range change {
			input[key] = value
		}
		result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "traffic.search", Arguments: input})
		if err == nil && !result.IsError {
			t.Fatal("接受了越界或未声明的协议输入", change)
		}
	}
	for _, name := range []string{"alerts.fields", "traffic.fields"} {
		result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: map[string]string{"tenant_id": "foreign"}})
		if err == nil && !result.IsError {
			t.Fatal("目录接受了调用方租户")
		}
	}
	if backend.queries != 1 {
		t.Fatal("无效输入访问了业务数据", backend.queries)
	}
	backend.errorQuery = errors.New("private-database-error")
	result, err = session.CallTool(ctx, &mcp.CallToolParams{Name: "traffic.search", Arguments: window})
	raw, _ = json.Marshal(result)
	if err != nil || !result.IsError || strings.Contains(string(raw), "private-database-error") || strings.Contains(string(raw), "protocol_owned") {
		t.Fatal("业务故障泄露数据或内部错误", err, string(raw))
	}
}

func TestTrafficScopesAndResultsCannotSurviveRevocationOrTokenExpiry(t *testing.T) {
	s, b, _, data := fixture(t)
	ctx := context.Background()
	request := httptest.NewRequest("POST", "/mcp", nil)
	token, err := s.verify(ctx, "owned-token", request)
	if err != nil {
		t.Fatal(err)
	}
	query := func(context.Context, mcpaccess.Identity) (any, bool, error) {
		b.queries++
		return "owned-protocol", false, nil
	}
	b.identity.Binding.Scopes = []string{"alerts:read"}
	if _, err := s.invoke(ctx, token, catalog[6], query); !errors.Is(err, mcpaccess.ErrDenied) || b.queries != 0 {
		t.Fatal("告警权限隐式授予协议检索", err)
	}
	b.identity.Binding.Scopes = []string{"traffic:read"}
	if _, err := s.invoke(ctx, token, catalog[4], query); !errors.Is(err, mcpaccess.ErrDenied) || b.queries != 0 {
		t.Fatal("协议权限隐式授予告警目录", err)
	}
	(*data)["scope"] = "alerts:read"
	if _, err := s.verify(ctx, "owned-token", request); err == nil {
		t.Fatal("令牌和登记权限没有交集仍通过认证")
	}
	(*data)["scope"] = "traffic:read"
	token, err = s.verify(ctx, "owned-token", request)
	if err != nil {
		t.Fatal(err)
	}
	b.revokeAfterQuery = true
	result, err := s.invoke(ctx, token, catalog[6], query)
	if !errors.Is(err, mcpaccess.ErrDenied) || result.Data != nil {
		t.Fatal("授权撤回后仍释放已读取数据", result, err)
	}
	b.revokeAfterQuery = false
	result, err = s.invoke(ctx, token, catalog[6], func(context.Context, mcpaccess.Identity) (any, bool, error) {
		token.Expiration = time.Now().Add(-time.Second)
		return "expired-protocol", false, nil
	})
	if !errors.Is(err, mcpaccess.ErrDenied) || result.Data != nil {
		t.Fatal("令牌在读取期间到期仍返回结果", result, err)
	}
}
