package platform

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/inventory"
	"github.com/kkx600/StarBeacon/internal/mcpaccess"
	"github.com/kkx600/StarBeacon/internal/mcpserver"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/store"
)

func (a *API) registerMCP(m *http.ServeMux) {
	m.HandleFunc("GET /api/v1/mcp", a.Auth.Require(true, a.mcpInfo))
	m.HandleFunc("GET /api/v1/mcp/bindings", a.Auth.Require(true, a.mcpBindings))
	m.HandleFunc("POST /api/v1/mcp/bindings", a.Auth.Require(true, a.mcpSave))
	m.HandleFunc("DELETE /api/v1/mcp/bindings/{id}", a.Auth.Require(true, a.mcpDelete))
}
func (a *API) mcpInfo(w http.ResponseWriter, r *http.Request) {
	info := mcpserver.Info{ProtocolVersions: []string{}, Tools: mcpserver.Catalog()}
	if a.MCP != nil {
		info = a.MCP.Info
	}
	httpapi.JSON(w, 200, info)
}
func (a *API) mcpBindings(w http.ResponseWriter, r *http.Request) {
	items, err := a.DB.MCPBindings(r.Context(), httpapi.Principal(r).TenantID)
	if err != nil {
		httpapi.Fail(w, r, 503, "mcp_unavailable", "服务身份暂时无法读取")
		return
	}
	httpapi.JSON(w, 200, map[string]any{"items": items})
}
func (a *API) mcpSave(w http.ResponseWriter, r *http.Request) {
	if a.MCP == nil {
		httpapi.Fail(w, r, 503, "mcp_disabled", "MCP 服务尚未配置授权方")
		return
	}
	var change mcpaccess.Change
	if httpapi.Decode(w, r, &change) != nil {
		httpapi.Fail(w, r, 400, "invalid_request", "服务身份参数无效")
		return
	}
	if change.ID == "" {
		change.ID = store.RandomID("mcp_")
	}
	if err := change.Validate(time.Now().UTC()); err != nil {
		httpapi.Fail(w, r, 400, "invalid_mcp_binding", err.Error())
		return
	}
	result, err := a.DB.SaveMCPBinding(r.Context(), httpapi.Principal(r), a.MCP.Info.Issuer, change, httpapi.RequestID(r))
	if errors.Is(err, mcpaccess.ErrConflict) {
		httpapi.Fail(w, r, 409, "mcp_binding_conflict", "身份绑定已存在或修订发生变化，请刷新后核对")
		return
	}
	if errors.Is(err, mcpaccess.ErrQuota) {
		httpapi.Fail(w, r, 429, "mcp_binding_quota", "服务身份数量已达到 100 个上限")
		return
	}
	if err != nil {
		httpapi.Fail(w, r, 503, "mcp_unavailable", "服务身份暂时无法保存")
		return
	}
	httpapi.JSON(w, 200, result)
}
func (a *API) MCPIdentity(ctx context.Context, issuer, subject, clientID string) (mcpaccess.Identity, error) {
	if a.DB == nil {
		return mcpaccess.Identity{}, errors.New("MCP 身份存储不可用")
	}
	return a.DB.MCPIdentity(ctx, issuer, subject, clientID)
}
func (a *API) MCPAudit(ctx context.Context, i mcpaccess.Identity, tool, result string) error {
	if a.DB == nil {
		return errors.New("MCP 审计存储不可用")
	}
	return a.DB.MCPAudit(ctx, i, tool, result)
}

func (a *API) mcpDelete(w http.ResponseWriter, r *http.Request) {
	var input struct {
		ExpectedRevision int64 `json:"expected_revision"`
	}
	if httpapi.Decode(w, r, &input) != nil || input.ExpectedRevision < 1 || !contract.ValidID(r.PathValue("id")) {
		httpapi.Fail(w, r, 400, "invalid_mcp_binding", "服务身份标识或修订无效")
		return
	}
	err := a.DB.DeleteMCPBinding(r.Context(), httpapi.Principal(r), r.PathValue("id"), input.ExpectedRevision, httpapi.RequestID(r))
	if errors.Is(err, mcpaccess.ErrConflict) {
		httpapi.Fail(w, r, 409, "mcp_binding_conflict", "身份不存在或修订发生变化，请刷新后核对")
		return
	}
	if err != nil {
		httpapi.Fail(w, r, 503, "mcp_unavailable", "服务身份暂时无法删除")
		return
	}
	httpapi.JSON(w, 200, map[string]bool{"ok": true})
}
func (a *API) InventoryAsset(ctx context.Context, u model.Principal, id string) (inventory.Record, error) {
	if !contract.ValidID(id) || a.DB == nil {
		return inventory.Record{}, mcpaccess.ErrDenied
	}
	return a.DB.InventoryObject(ctx, u.TenantID, "assets", id)
}
func (a *API) ListSensors(ctx context.Context, u model.Principal) ([]model.Sensor, error) {
	if a.DB == nil {
		return nil, mcpaccess.ErrDenied
	}
	return a.DB.Sensors(ctx, u.TenantID)
}
func (a *API) MCPAllow(ctx context.Context, tenant, binding string, limit int) error {
	if a.Redis == nil {
		return errors.New("MCP 调用预算服务不可用")
	}
	window := time.Now().UTC().Format("200601021504")
	keys := []string{"sb:mcp:quota:global:" + window}
	limits := []any{600}
	if tenant != "" || binding != "" {
		if !contract.ValidID(tenant) || !contract.ValidID(binding) || limit < 1 || limit > 120 {
			return mcpaccess.ErrDenied
		}
		keys = []string{"sb:mcp:quota:tenant:" + tenant + ":" + window, "sb:mcp:quota:binding:" + tenant + ":" + binding + ":" + window}
		limits = []any{300, limit}
	}
	// 每次工具执行都计入调用预算；HTTP 协议的批量调用不能绕开租户或身份的原子额度。
	n, err := a.Redis.Eval(ctx, `local allow=1; for i,key in ipairs(KEYS) do local n=redis.call('INCR',key);if n==1 then redis.call('EXPIRE',key,120) end;if n>tonumber(ARGV[i]) then allow=0 end end;return allow`, keys, limits...).Int()
	if err != nil {
		return errors.New("MCP 调用预算服务不可用")
	}
	if n != 1 {
		return mcpaccess.ErrQuota
	}
	return nil
}
