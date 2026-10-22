package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"slices"

	"github.com/kkx600/StarBeacon/internal/mcpaccess"
	"github.com/kkx600/StarBeacon/internal/searchfilter"
	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	AlertsFieldsURI        = "starbeacon://catalog/alerts/fields"
	TrafficFieldsURI       = "starbeacon://catalog/context/fields"
	CapabilitiesURI        = "starbeacon://catalog/capabilities"
	FieldsResourceTemplate = "starbeacon://catalog/{dataset}/fields"
)

type metadataResource struct {
	resource mcp.Resource
	scope    string
	dataset  string
}

var metadataResources = []metadataResource{
	{mcp.Resource{URI: AlertsFieldsURI, Name: "alerts.search-fields", Title: "告警检索字段", Description: "当前软件支持的告警字段、别名、类型与运算符；不包含业务记录或原始载荷。", MIMEType: "application/json"}, "alerts:read", "alerts"},
	{mcp.Resource{URI: TrafficFieldsURI, Name: "traffic.search-fields", Title: "协议检索字段", Description: "当前软件支持的协议数据集字段、别名、类型与运算符；不证明字段已采集或已索引。", MIMEType: "application/json"}, "traffic:read", "context"},
	{mcp.Resource{URI: CapabilitiesURI, Name: "analysis.capabilities", Title: "分析能力说明", Description: "本次身份获授权的只读工具、数据集和元数据资源，以及实际请求与输出限制。", MIMEType: "application/json"}, "", ""},
}

type MetadataDataset struct {
	Dataset   string `json:"dataset"`
	Scope     string `json:"scope"`
	FieldsURI string `json:"fields_uri"`
}

// MetadataCapabilities 只说明当前身份可发现的软件能力，不代表数据覆盖或生产兼容验收。
type MetadataCapabilities struct {
	SchemaVersion      string            `json:"schema_version"`
	Scopes             []string          `json:"scopes"`
	ProtocolVersions   []string          `json:"protocol_versions"`
	Tools              []ToolInfo        `json:"tools"`
	Datasets           []MetadataDataset `json:"datasets"`
	Resources          []string          `json:"resources"`
	Templates          []string          `json:"resource_templates"`
	MaxRequestBytes    int               `json:"max_request_bytes"`
	MaxContentBytes    int               `json:"max_content_bytes"`
	ReadTimeoutSeconds int               `json:"read_timeout_seconds"`
	RawPayloads        bool              `json:"raw_payloads"`
	PCAPDownloads      bool              `json:"pcap_downloads"`
	DeviceActions      bool              `json:"device_actions"`
}

func supportedScopes(scopes []string) bool {
	return len(mcpaccess.Intersect(scopes, mcpaccess.Scopes)) > 0
}

func resourceAllowed(resource metadataResource, scopes []string) bool {
	return resource.scope == "" && supportedScopes(scopes) || slices.Contains(scopes, resource.scope)
}

func requestResourceToken(request mcp.Request) *auth.TokenInfo {
	if request == nil || request.GetExtra() == nil {
		return nil
	}
	return request.GetExtra().TokenInfo
}

func (s *Server) addResources(server *mcp.Server) {
	for _, entry := range metadataResources {
		resource := entry.resource
		server.AddResource(&resource, s.readResource)
	}
	server.AddResourceTemplate(&mcp.ResourceTemplate{Name: "search-fields", Title: "检索字段目录", URITemplate: FieldsResourceTemplate, MIMEType: "application/json", Description: "按本次授权的数据集读取字段目录；有效数据集由分析能力说明提供。"}, s.readResource)
	server.AddReceivingMiddleware(s.resourceDiscovery)
}

// SDK 负责资源注册、模板匹配和协议参数；发现结果按当前授权裁剪，不修改全局目录。
func (s *Server) resourceDiscovery(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, request mcp.Request) (mcp.Result, error) {
		if method != "resources/list" && method != "resources/templates/list" {
			return next(ctx, method, request)
		}
		name := "resources.list"
		if method == "resources/templates/list" {
			name = "resources.templates.list"
		}
		result, err := s.invokeAuthorized(ctx, requestResourceToken(request), name, supportedScopes, func(work context.Context, identity mcpaccess.Identity) (any, bool, error) {
			original, err := next(work, method, request)
			if err != nil {
				return nil, false, err
			}
			switch original := original.(type) {
			case *mcp.ListResourcesResult:
				filtered := *original
				filtered.Resources = []*mcp.Resource{}
				for _, resource := range original.Resources {
					for _, entry := range metadataResources {
						if resource.URI == entry.resource.URI && resourceAllowed(entry, identity.GrantedScopes) {
							filtered.Resources = append(filtered.Resources, resource)
						}
					}
				}
				return &filtered, false, nil
			case *mcp.ListResourceTemplatesResult:
				filtered := *original
				filtered.ResourceTemplates = []*mcp.ResourceTemplate{}
				if slices.Contains(identity.GrantedScopes, "alerts:read") || slices.Contains(identity.GrantedScopes, "traffic:read") {
					filtered.ResourceTemplates = original.ResourceTemplates
				}
				return &filtered, false, nil
			default:
				return nil, false, errUnavailable
			}
		})
		if err != nil {
			return nil, err
		}
		return result.Data.(mcp.Result), nil
	}
}

func (s *Server) readResource(ctx context.Context, request *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
	if request == nil || request.Params == nil {
		return nil, mcp.ResourceNotFoundError("")
	}
	var entry *metadataResource
	for index := range metadataResources {
		if metadataResources[index].resource.URI == request.Params.URI {
			entry = &metadataResources[index]
			break
		}
	}
	// 精确匹配限定模板变量；不解码替代 URI，也不打开文件、网络或客户端根目录。
	if entry == nil {
		return nil, mcp.ResourceNotFoundError(request.Params.URI)
	}
	result, err := s.invokeAuthorized(ctx, requestResourceToken(request), "resources.read."+entry.resource.Name, func(scopes []string) bool { return resourceAllowed(*entry, scopes) }, func(_ context.Context, identity mcpaccess.Identity) (any, bool, error) {
		if entry.dataset != "" {
			fields, err := searchfilter.CatalogForDataset(entry.dataset)
			return FieldCatalog{Version: searchfilter.Version, Dataset: entry.dataset, Fields: fields}, false, err
		}
		return s.metadataCapabilities(identity.GrantedScopes), false, nil
	})
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(result)
	if err != nil || len(raw) > 256*1024 {
		return nil, errors.New("资源内容超过输出预算或无法编码")
	}
	return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: entry.resource.URI, MIMEType: "application/json", Text: string(raw)}}}, nil
}

func (s *Server) metadataCapabilities(scopes []string) MetadataCapabilities {
	result := MetadataCapabilities{SchemaVersion: "mcp-metadata.v1", Scopes: slices.Clone(scopes), ProtocolVersions: slices.Clone(s.Info.ProtocolVersions), Tools: []ToolInfo{}, Datasets: []MetadataDataset{}, Resources: []string{}, Templates: []string{}, MaxRequestBytes: 65536, MaxContentBytes: 256 * 1024, ReadTimeoutSeconds: 10}
	for _, tool := range catalog {
		if slices.Contains(scopes, tool.Scope) {
			result.Tools = append(result.Tools, tool)
		}
	}
	for _, entry := range metadataResources {
		if resourceAllowed(entry, scopes) {
			result.Resources = append(result.Resources, entry.resource.URI)
			if entry.dataset != "" {
				result.Datasets = append(result.Datasets, MetadataDataset{Dataset: entry.dataset, Scope: entry.scope, FieldsURI: entry.resource.URI})
			}
		}
	}
	if len(result.Datasets) > 0 {
		result.Templates = append(result.Templates, FieldsResourceTemplate)
	}
	return result
}
