package platform

import (
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/retention"
	"github.com/kkx600/StarBeacon/internal/store"
)

func (a *API) registerRetention(m *http.ServeMux) {
	m.HandleFunc("GET /api/v1/retention-policies", a.Auth.Require(true, a.retentionPolicies))
	m.HandleFunc("POST /api/v1/retention-policies/preview", a.Auth.Require(true, a.retentionPreview))
	m.HandleFunc("PUT /api/v1/retention-policies/{category}", a.Auth.Require(true, a.retentionSave))
}
func (a *API) retentionPolicies(w http.ResponseWriter, r *http.Request) {
	items, err := a.DB.RetentionPolicies(r.Context(), httpapi.Principal(r).TenantID)
	if err != nil {
		retentionFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, map[string]any{"items": items, "catalog": retention.Catalog(), "default_days": retention.DefaultDays})
}
func (a *API) retentionPreview(w http.ResponseWriter, r *http.Request) {
	var input retention.Candidate
	if err := httpapi.Decode(w, r, &input); err != nil {
		httpapi.Fail(w, r, 400, "invalid_retention", "留存策略参数无效")
		return
	}
	if err := input.Validate(); err != nil {
		httpapi.Fail(w, r, 400, "invalid_retention", err.Error())
		return
	}
	result, err := a.DB.PreviewRetention(r.Context(), httpapi.Principal(r), input)
	if err != nil {
		retentionFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, result)
}
func (a *API) retentionSave(w http.ResponseWriter, r *http.Request) {
	var input retention.Change
	if err := httpapi.Decode(w, r, &input); err != nil {
		httpapi.Fail(w, r, 400, "invalid_retention", "留存策略参数无效")
		return
	}
	if input.Candidate.Category != r.PathValue("category") || !contract.ValidID(input.PreviewID) || !contract.ValidID(r.Header.Get("Idempotency-Key")) {
		httpapi.Fail(w, r, 400, "invalid_retention", "需要匹配的类别、有效预览和幂等键")
		return
	}
	if err := input.Candidate.Validate(); err != nil {
		httpapi.Fail(w, r, 400, "invalid_retention", err.Error())
		return
	}
	result, _, err := a.DB.SaveRetention(r.Context(), httpapi.Principal(r), input, r.Header.Get("Idempotency-Key"))
	if err != nil {
		retentionFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, result)
}
func retentionFailure(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, store.ErrConflict) {
		httpapi.Fail(w, r, 409, "retention_conflict", "策略修订或提交内容已改变，请刷新后重新预览")
		return
	}
	if errors.Is(err, pgx.ErrNoRows) {
		httpapi.Fail(w, r, 404, "retention_preview_unavailable", "预览已失效或不可访问，请重新预览")
		return
	}
	httpapi.Fail(w, r, 503, "retention_unavailable", "留存策略暂不可用，请稍后重试")
}
