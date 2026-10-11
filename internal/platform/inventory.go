package platform

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/inventory"
	"github.com/kkx600/StarBeacon/internal/store"
)

func (a *API) registerInventory(m *http.ServeMux) {
	m.HandleFunc("GET /api/v1/inventory/{kind}", a.Auth.Require(false, a.inventoryList))
	m.HandleFunc("POST /api/v1/inventory/{kind}", a.Auth.Require(true, a.inventorySave))
	m.HandleFunc("GET /api/v1/inventory/{kind}/{id}", a.Auth.Require(false, a.inventoryObject))
	m.HandleFunc("GET /api/v1/inventory/{kind}/{id}/history", a.Auth.Require(false, a.inventoryHistory))
}
func (a *API) inventoryList(w http.ResponseWriter, r *http.Request) {
	limit := 20
	if raw := r.URL.Query().Get("limit"); raw != "" {
		var err error
		limit, err = strconv.Atoi(raw)
		if err != nil {
			httpapi.Fail(w, r, 400, "invalid_page", "列表大小无效")
			return
		}
	}
	kind, cursor, keyword := r.PathValue("kind"), r.URL.Query().Get("cursor"), r.URL.Query().Get("keyword")
	if !inventory.ValidKind(kind) || limit < 1 || limit > 100 || len([]rune(keyword)) > 128 || strings.ContainsAny(keyword, "\x00\r\n") || (cursor != "" && !contract.ValidID(cursor)) {
		httpapi.Fail(w, r, 400, "invalid_inventory_query", "对象类型、游标或列表大小无效")
		return
	}
	result, err := a.DB.Inventory(r.Context(), httpapi.Principal(r).TenantID, kind, cursor, keyword, limit)
	if err != nil {
		operationError(w, r, err)
		return
	}
	httpapi.JSON(w, 200, result)
}
func (a *API) inventoryObject(w http.ResponseWriter, r *http.Request) {
	if !inventory.ValidKind(r.PathValue("kind")) || !contract.ValidID(r.PathValue("id")) {
		httpapi.Fail(w, r, 400, "invalid_inventory", "对象类型或标识无效")
		return
	}
	value, err := a.DB.InventoryObject(r.Context(), httpapi.Principal(r).TenantID, r.PathValue("kind"), r.PathValue("id"))
	if err != nil {
		operationError(w, r, err)
		return
	}
	httpapi.JSON(w, 200, value)
}
func (a *API) inventorySave(w http.ResponseWriter, r *http.Request) {
	var input struct {
		ID               string          `json:"id"`
		ExpectedRevision int64           `json:"expected_revision"`
		Data             json.RawMessage `json:"data"`
	}
	if err := httpapi.Decode(w, r, &input); err != nil {
		httpapi.Fail(w, r, 400, "invalid_request", "对象参数无效")
		return
	}
	kind := r.PathValue("kind")
	if input.ID == "" {
		input.ID = store.RandomID("obj_")
	}
	if !contract.ValidID(input.ID) || input.ExpectedRevision < 0 {
		httpapi.Fail(w, r, 400, "invalid_inventory", "对象标识或修订无效")
		return
	}
	normalized, err := inventory.Validate(kind, input.Data)
	if err != nil {
		httpapi.Fail(w, r, 400, "invalid_inventory", err.Error())
		return
	}
	if normalized.GroupID != "" && !contract.ValidID(normalized.GroupID) {
		httpapi.Fail(w, r, 400, "invalid_group", "资产组标识无效")
		return
	}
	result, err := a.DB.SaveInventory(r.Context(), httpapi.Principal(r), kind, input.ID, input.ExpectedRevision, normalized.Data, httpapi.RequestID(r))
	if err != nil {
		operationError(w, r, err)
		return
	}
	httpapi.JSON(w, 201, result)
}
func (a *API) inventoryHistory(w http.ResponseWriter, r *http.Request) {
	at := time.Now().UTC()
	if value := r.URL.Query().Get("at"); value != "" {
		var err error
		at, err = time.Parse(time.RFC3339Nano, value)
		if err != nil {
			httpapi.Fail(w, r, 400, "invalid_time", "历史时间必须包含时区")
			return
		}
	}
	if !inventory.ValidKind(r.PathValue("kind")) || !contract.ValidID(r.PathValue("id")) {
		httpapi.Fail(w, r, 400, "invalid_inventory", "对象类型或标识无效")
		return
	}
	items, err := a.DB.InventoryHistory(r.Context(), httpapi.Principal(r).TenantID, r.PathValue("kind"), r.PathValue("id"), at)
	if err != nil {
		operationError(w, r, err)
		return
	}
	httpapi.JSON(w, 200, map[string]any{"items": items, "as_of": at})
}
