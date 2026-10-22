package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/mcpaccess"
	"github.com/kkx600/StarBeacon/internal/searchfilter"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func resourceSession(t *testing.T, endpoint *httptest.Server) *mcp.ClientSession {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	client := endpoint.Client()
	client.Transport = bearerTransport{"owned-token", client.Transport}
	session, err := mcp.NewClient(&mcp.Implementation{Name: "metadata-agent", Version: "test"}, nil).Connect(ctx, &mcp.StreamableClientTransport{Endpoint: endpoint.URL + "/mcp", HTTPClient: client, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

func resourceData[T any](t *testing.T, result *mcp.ReadResourceResult, uri string) T {
	t.Helper()
	if result == nil || len(result.Contents) != 1 || result.Contents[0].URI != uri || result.Contents[0].MIMEType != "application/json" || result.Contents[0].Blob != nil || len(result.Contents[0].Text) > 256*1024 {
		t.Fatal("资源内容身份、类型或预算错误", result)
	}
	var envelope struct {
		Data        T        `json:"data"`
		Limitations []string `json:"limitations"`
		ObservedAt  string   `json:"observed_at"`
		Truncated   bool     `json:"truncated"`
	}
	if err := json.Unmarshal([]byte(result.Contents[0].Text), &envelope); err != nil {
		t.Fatal(err)
	}
	if len(envelope.Limitations) < 4 || envelope.ObservedAt == "" || envelope.Truncated {
		t.Fatal("元数据没有保留观测限制或错误标记截断")
	}
	return envelope.Data
}

func TestOfficialClientListsAndReadsAuthorizedMetadataResources(t *testing.T) {
	_, backend, endpoint, _ := fixture(t)
	session := resourceSession(t, endpoint)
	ctx := context.Background()
	resources, err := session.ListResources(ctx, nil)
	if err != nil || len(resources.Resources) != 3 || resources.NextCursor != "" {
		t.Fatal("资源发现未返回有界目录", err, resources)
	}
	templates, err := session.ListResourceTemplates(ctx, nil)
	if err != nil || len(templates.ResourceTemplates) != 1 || templates.ResourceTemplates[0].URITemplate != FieldsResourceTemplate || templates.NextCursor != "" {
		t.Fatal("模板未通过官方协议发现", err, templates)
	}
	for _, entry := range []struct{ uri, dataset string }{{AlertsFieldsURI, "alerts"}, {TrafficFieldsURI, "context"}} {
		result, err := session.ReadResource(ctx, &mcp.ReadResourceParams{URI: entry.uri})
		if err != nil {
			t.Fatal(err)
		}
		catalog := resourceData[FieldCatalog](t, result, entry.uri)
		fields, err := searchfilter.CatalogForDataset(entry.dataset)
		expected, _ := json.Marshal(FieldCatalog{Version: searchfilter.Version, Dataset: entry.dataset, Fields: fields})
		actual, _ := json.Marshal(catalog)
		if err != nil || string(actual) != string(expected) {
			t.Fatal("资源字段与实际编译器目录不一致", entry, err)
		}
	}
	result, err := session.ReadResource(ctx, &mcp.ReadResourceParams{URI: CapabilitiesURI})
	if err != nil {
		t.Fatal(err)
	}
	capabilities := resourceData[MetadataCapabilities](t, result, CapabilitiesURI)
	if capabilities.SchemaVersion != "mcp-metadata.v1" || len(capabilities.Tools) != 9 || len(capabilities.Resources) != 3 || len(capabilities.Datasets) != 2 || len(capabilities.Templates) != 1 || capabilities.MaxContentBytes != 256*1024 || capabilities.MaxRequestBytes != 65536 || capabilities.ReadTimeoutSeconds != 10 || capabilities.RawPayloads || capabilities.PCAPDownloads || capabilities.DeviceActions {
		t.Fatal("能力说明夸大实际授权或下载能力", capabilities)
	}
	if backend.queries != 0 {
		t.Fatal("元数据读取调用了业务查询")
	}
	for _, name := range []string{"resources.list", "resources.templates.list", "resources.read.alerts.search-fields", "resources.read.traffic.search-fields", "resources.read.analysis.capabilities"} {
		if !slices.Contains(backend.audits, name+".started") || !slices.Contains(backend.audits, name+".succeeded") {
			t.Fatal("资源操作未执行独立审计", name, backend.audits)
		}
	}

	backend.identity.Binding.Scopes = []string{"assets:read"}
	resources, err = session.ListResources(ctx, nil)
	if err != nil || len(resources.Resources) != 1 || resources.Resources[0].URI != CapabilitiesURI {
		t.Fatal("资源发现泄露已撤回范围", err, resources)
	}
	templates, err = session.ListResourceTemplates(ctx, nil)
	if err != nil || len(templates.ResourceTemplates) != 0 {
		t.Fatal("无数据集授权仍列出检索模板", err, templates)
	}
	result, err = session.ReadResource(ctx, &mcp.ReadResourceParams{URI: CapabilitiesURI})
	if err != nil {
		t.Fatal(err)
	}
	capabilities = resourceData[MetadataCapabilities](t, result, CapabilitiesURI)
	if !reflect.DeepEqual(capabilities.Scopes, []string{"assets:read"}) || len(capabilities.Tools) != 1 || capabilities.Tools[0].Name != "assets.get" || len(capabilities.Datasets) != 0 || len(capabilities.Templates) != 0 || len(capabilities.Resources) != 1 {
		t.Fatal("能力说明保留已撤回授权", capabilities)
	}
	for _, uri := range []string{AlertsFieldsURI, TrafficFieldsURI} {
		result, err := session.ReadResource(ctx, &mcp.ReadResourceParams{URI: uri})
		if err == nil || result != nil {
			t.Fatal("未授权资源被转换为成功空内容", uri, result, err)
		}
	}
	backend.identity.Binding.Scopes = []string{"traffic:read"}
	resources, err = session.ListResources(ctx, nil)
	if err != nil || len(resources.Resources) != 2 {
		t.Fatal(err, resources)
	}
	for _, resource := range resources.Resources {
		if resource.URI == AlertsFieldsURI {
			t.Fatal("协议权限隐式授权告警字段资源")
		}
	}
}

func TestResourceURIsRejectUnknownDatasetsFilesAndAlternativeEncodings(t *testing.T) {
	server, _, endpoint, _ := fixture(t)
	session := resourceSession(t, endpoint)
	for _, uri := range []string{"starbeacon://catalog/logs/fields", "starbeacon://catalog/traffic/fields", "starbeacon://catalog/../fields", "starbeacon://catalog/%61lerts/fields", "starbeacon://catalog/alerts%2fother/fields", AlertsFieldsURI + "?tenant_id=foreign", AlertsFieldsURI + "#secret", "file:///etc/passwd", "http://127.0.0.1/private", "starbeacon://foreign/catalog/alerts/fields"} {
		result, err := session.ReadResource(context.Background(), &mcp.ReadResourceParams{URI: uri})
		var protocolError *jsonrpc.Error
		if err == nil || result != nil || !errors.As(err, &protocolError) || protocolError.Code != mcp.CodeResourceNotFound {
			t.Fatal("未知资源未返回 SDK 标准错误", uri, result, err)
		}
	}
	for _, request := range []*mcp.ReadResourceRequest{nil, {}} {
		if result, err := server.readResource(context.Background(), request); err == nil || result != nil {
			t.Fatal("缺少资源请求仍成功", result, err)
		}
	}
	if requestResourceToken(nil) != nil || requestResourceToken(&mcp.ReadResourceRequest{}) != nil {
		t.Fatal("缺少协议身份不应产生令牌")
	}
}

type mutableResourceBackend struct {
	*mockBackend
	started func()
}

func (b *mutableResourceBackend) MCPAudit(ctx context.Context, identity mcpaccess.Identity, name, state string) error {
	err := b.mockBackend.MCPAudit(ctx, identity, name, state)
	if err == nil && state == "started" && b.started != nil {
		b.started()
	}
	return err
}

func TestResourceReadBudgetsAuditRevocationAndCancellationFailClosed(t *testing.T) {
	for _, mode := range []string{"quota", "audit", "revision", "scope", "expiry", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			server, backend, _, _ := fixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			token, err := server.verify(ctx, "owned-token", httptest.NewRequest("POST", "/mcp", nil))
			if err != nil {
				t.Fatal(err)
			}
			wrapper := &mutableResourceBackend{mockBackend: backend}
			server.backend = wrapper
			switch mode {
			case "quota":
				backend.errorBudget = mcpaccess.ErrQuota
			case "audit":
				backend.errorAudit = errors.New("private-audit-error")
			case "revision":
				wrapper.started = func() { backend.identity.Binding.Revision++ }
			case "scope":
				wrapper.started = func() { backend.identity.Binding.Scopes = []string{"assets:read"} }
			case "expiry":
				wrapper.started = func() { token.Expiration = time.Now().Add(-time.Second) }
			case "cancel":
				wrapper.started = cancel
			}
			result, err := server.readResource(ctx, &mcp.ReadResourceRequest{Params: &mcp.ReadResourceParams{URI: CapabilitiesURI}, Extra: &mcp.RequestExtra{TokenInfo: token}})
			if err == nil || result != nil || strings.Contains(err.Error(), "private-audit-error") {
				t.Fatal("资源失败路径释放内容或泄露内部错误", mode, result, err)
			}
			if mode == "quota" && !errors.Is(err, mcpaccess.ErrQuota) || mode == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatal("预算或取消失败语义丢失", err)
			}
		})
	}
}
