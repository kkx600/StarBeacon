package platform

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/response"
	"github.com/kkx600/StarBeacon/internal/store"
)

func (a *API) registerResponsePlugins(m *http.ServeMux) {
	m.HandleFunc("GET /api/v1/response-plugins", a.Auth.Require(true, a.responsePlugins))
	m.HandleFunc("POST /api/v1/response-plugins", a.Auth.Require(true, a.saveResponsePlugin))
	m.HandleFunc("GET /api/v1/response-plugins/{id}/versions/{version}", a.Auth.Require(true, a.responsePluginVersion))
}

func responsePluginFailure(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, response.ErrInput):
		httpapi.Fail(w, r, 400, "invalid_response_plugin", "请核对联动插件、版本、幂等键及模板字段")
	case errors.Is(err, response.ErrPermission):
		httpapi.Fail(w, r, 403, "response_plugin_forbidden", "当前账号没有管理联动插件的权限")
	case errors.Is(err, response.ErrPluginQuota):
		httpapi.Fail(w, r, 429, "response_plugin_quota", err.Error())
	case errors.Is(err, store.ErrConflict):
		httpapi.Fail(w, r, 409, "response_plugin_conflict", "联动插件当前版本或原提交参数已有变化，请刷新后核对")
	case errors.Is(err, pgx.ErrNoRows):
		httpapi.Fail(w, r, 404, "not_found", "联动插件版本不存在或不可访问")
	default:
		httpapi.Fail(w, r, 503, "response_plugin_unavailable", "联动插件目录暂时无法核验或保存")
	}
}

func pluginPageParameters(r *http.Request) (string, int, error) {
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return "", 0, response.ErrInput
	}
	after, limit := "", contract.DefaultListLimit
	for key, value := range values {
		if len(value) != 1 {
			return "", 0, response.ErrInput
		}
		switch key {
		case "after":
			if !contract.ValidID(value[0]) {
				return "", 0, response.ErrInput
			}
			after = value[0]
		case "limit":
			limit, err = parseListLimit(value)
			if err != nil {
				return "", 0, response.ErrInput
			}
		default:
			return "", 0, response.ErrInput
		}
	}
	return after, limit, nil
}

func (a *API) responsePlugins(w http.ResponseWriter, r *http.Request) {
	after, limit, err := pluginPageParameters(r)
	if err != nil {
		responsePluginFailure(w, r, err)
		return
	}
	if a.DB == nil {
		responsePluginFailure(w, r, response.ErrUnavailable)
		return
	}
	page, err := a.DB.ResponsePlugins(r.Context(), httpapi.Principal(r), after, limit)
	if err != nil {
		responsePluginFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, page)
}

func (a *API) responsePluginVersion(w http.ResponseWriter, r *http.Request) {
	id, raw := r.PathValue("id"), r.PathValue("version")
	version, err := strconv.Atoi(raw)
	if err != nil || raw != strconv.Itoa(version) || r.URL.RawQuery != "" || version < 1 || version > response.MaxPluginVersions || !contract.ValidID(id) {
		responsePluginFailure(w, r, response.ErrInput)
		return
	}
	if a.DB == nil {
		responsePluginFailure(w, r, response.ErrUnavailable)
		return
	}
	item, err := a.DB.ResponsePluginVersion(r.Context(), httpapi.Principal(r), id, version)
	if err != nil {
		responsePluginFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, item)
}

func (a *API) saveResponsePlugin(w http.ResponseWriter, r *http.Request) {
	key := r.Header.Get("Idempotency-Key")
	r.Body = http.MaxBytesReader(w, r.Body, response.MaxPluginDraftBytes)
	var draft response.PluginDraft
	if r.URL.RawQuery != "" || len(r.Header.Values("Idempotency-Key")) != 1 || len(key) < 8 || !contract.ValidID(key) || httpapi.Decode(w, r, &draft) != nil {
		responsePluginFailure(w, r, response.ErrInput)
		return
	}
	if a.DB == nil {
		responsePluginFailure(w, r, response.ErrUnavailable)
		return
	}
	item, err := a.DB.SaveResponsePluginDraft(r.Context(), httpapi.Principal(r), key, draft)
	if err != nil {
		responsePluginFailure(w, r, err)
		return
	}
	httpapi.JSON(w, http.StatusCreated, item)
}
