package platform

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"

	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/plugingen"
	"github.com/kkx600/StarBeacon/internal/response"
)

func (a *API) registerPluginGeneration(m *http.ServeMux) {
	m.HandleFunc("POST /api/v1/response-plugin-generation/jobs", a.Auth.Require(true, a.createPluginGeneration))
	m.HandleFunc("GET /api/v1/response-plugin-generation/jobs", a.Auth.Require(true, a.pluginGenerations))
	m.HandleFunc("GET /api/v1/response-plugin-generation/jobs/{id}", a.Auth.Require(true, a.pluginGeneration))
}

func pluginGenerationFailure(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, plugingen.ErrInput):
		httpapi.Fail(w, r, http.StatusBadRequest, "invalid_plugin_generation", "请核对设备类型、能力、文档、模型修订与本次数据使用许可")
	case errors.Is(err, plugingen.ErrCredentials):
		httpapi.Fail(w, r, http.StatusBadRequest, "plugin_document_credentials", err.Error())
	case errors.Is(err, response.ErrPermission):
		httpapi.Fail(w, r, http.StatusForbidden, "plugin_generation_forbidden", "当前账号没有生成联动插件的权限")
	default:
		modelFailure(w, r, err)
	}
}

func (a *API) pluginGenerationAvailable() bool {
	return a.Jobs != nil && a.Vault != nil && (a.JobsReady == nil || a.JobsReady())
}

func (a *API) createPluginGeneration(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 32*1024)
	key := r.Header.Get("Idempotency-Key")
	var raw json.RawMessage
	var input plugingen.Request
	fields := []string{"provider_id", "provider_revision", "device_type", "abilities", "documentation", "allow_context"}
	if r.URL.RawQuery != "" || len(r.Header.Values("Idempotency-Key")) != 1 || len(key) < 8 || !contract.ValidID(key) ||
		httpapi.Decode(w, r, &raw) != nil || contract.JSONFields(string(raw), fields, 32*1024) != nil || json.Unmarshal(raw, &input) != nil {
		pluginGenerationFailure(w, r, plugingen.ErrInput)
		return
	}
	if err := input.Validate(); err != nil {
		pluginGenerationFailure(w, r, err)
		return
	}
	if a.DB == nil {
		httpapi.Fail(w, r, http.StatusServiceUnavailable, "plugin_generation_unavailable", "插件生成记录暂时无法读取")
		return
	}
	queue := a.Jobs
	if !a.pluginGenerationAvailable() {
		queue = nil
	}
	job, created, err := a.DB.CreatePluginGeneration(r.Context(), httpapi.Principal(r), input, key, queue, a.Vault, httpapi.RequestID(r))
	if err != nil {
		pluginGenerationFailure(w, r, err)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusAccepted
	}
	httpapi.JSON(w, status, job)
}

func (a *API) pluginGeneration(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" || !contract.ValidID(r.PathValue("id")) {
		pluginGenerationFailure(w, r, plugingen.ErrInput)
		return
	}
	if a.DB == nil {
		httpapi.Fail(w, r, http.StatusServiceUnavailable, "plugin_generation_unavailable", "插件生成记录暂时无法读取")
		return
	}
	job, err := a.DB.PluginGeneration(r.Context(), httpapi.Principal(r), r.PathValue("id"))
	if err != nil {
		pluginGenerationFailure(w, r, err)
		return
	}
	httpapi.JSON(w, http.StatusOK, job)
}

func (a *API) pluginGenerations(w http.ResponseWriter, r *http.Request) {
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		pluginGenerationFailure(w, r, plugingen.ErrInput)
		return
	}
	for key, value := range query {
		if (key != "before" && key != "limit") || len(value) != 1 {
			pluginGenerationFailure(w, r, plugingen.ErrInput)
			return
		}
	}
	limit, ok := requestListLimit(w, r)
	if !ok {
		return
	}
	if a.DB == nil {
		httpapi.Fail(w, r, http.StatusServiceUnavailable, "plugin_generation_unavailable", "插件生成记录暂时无法读取")
		return
	}
	page, err := a.DB.PluginGenerations(r.Context(), httpapi.Principal(r), query.Get("before"), limit)
	if err != nil {
		pluginGenerationFailure(w, r, err)
		return
	}
	page.Available = a.pluginGenerationAvailable()
	httpapi.JSON(w, http.StatusOK, page)
}
