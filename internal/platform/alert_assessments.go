package platform

import (
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/assessment"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/store"
)

func (a *API) registerAlertAssessments(m *http.ServeMux) {
	m.HandleFunc("GET /api/v1/alerts/{id}/assessment", a.Auth.Require(true, a.alertAssessment))
	m.HandleFunc("POST /api/v1/alerts/{id}/assessment", a.Auth.Require(true, a.saveAlertAssessment))
	m.HandleFunc("GET /api/v1/alerts/{id}/assessment/history", a.Auth.Require(true, a.alertAssessmentHistory))
}

func assessmentFailure(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, assessment.ErrInput):
		httpapi.Fail(w, r, 400, "invalid_assessment", "研判输入无效，请核对状态、结论、依据、原始摘要和修订")
	case errors.Is(err, pgx.ErrNoRows):
		httpapi.Fail(w, r, 404, "not_found", "告警不存在、已到保留期限或不可访问")
	case errors.Is(err, store.ErrAlertIdentity):
		httpapi.Fail(w, r, 409, "alert_identity_conflict", "告警来源不唯一或原始摘要已变化，未提交研判，请刷新后核对")
	case errors.Is(err, store.ErrConflict):
		httpapi.Fail(w, r, 409, "assessment_conflict", "研判修订或原请求已变化，请刷新后核对；相同请求键不能改变输入")
	case errors.Is(err, store.ErrAssessmentExpired):
		httpapi.Fail(w, r, 410, "assessment_expired", "研判记录已到保留期限，正在等待回收，请稍后刷新；原始告警不受影响")
	case errors.Is(err, store.ErrAssessmentQuota):
		w.Header().Set("Retry-After", "60")
		httpapi.Fail(w, r, 429, "assessment_quota_exceeded", "研判变更额度已用尽，请稍后重试或核对该告警的操作记录")
	default:
		httpapi.Fail(w, r, 503, "assessment_unavailable", "研判服务暂不可用，保存结果需核对后确认")
	}
}

func (a *API) checkAssessmentSource(w http.ResponseWriter, r *http.Request) bool {
	if a.DB == nil || a.ES == nil {
		assessmentFailure(w, r, errors.New("研判依赖不可用"))
		return false
	}
	user := httpapi.Principal(r)
	if err := a.ES.VerifyAlertIdentity(r.Context(), user.TenantID, r.PathValue("id"), r.URL.Query().Get("sha256")); err != nil {
		assessmentFailure(w, r, err)
		return false
	}
	return true
}

func (a *API) alertAssessment(w http.ResponseWriter, r *http.Request) {
	if !a.checkAssessmentSource(w, r) {
		return
	}
	result, err := a.DB.AlertAssessment(r.Context(), httpapi.Principal(r), r.PathValue("id"), r.URL.Query().Get("sha256"))
	if err != nil {
		assessmentFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, result)
}

func (a *API) saveAlertAssessment(w http.ResponseWriter, r *http.Request) {
	var change assessment.Change
	if httpapi.Decode(w, r, &change) != nil || change.Validate() != nil {
		assessmentFailure(w, r, assessment.ErrInput)
		return
	}
	if !a.checkAssessmentSource(w, r) {
		return
	}
	result, err := a.DB.SaveAlertAssessment(r.Context(), httpapi.Principal(r), r.PathValue("id"), r.URL.Query().Get("sha256"), r.Header.Get("Idempotency-Key"), change, httpapi.RequestID(r))
	if err != nil {
		assessmentFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, result)
}

func (a *API) alertAssessmentHistory(w http.ResponseWriter, r *http.Request) {
	if !a.checkAssessmentSource(w, r) {
		return
	}
	result, err := a.DB.AlertAssessmentHistory(r.Context(), httpapi.Principal(r), r.PathValue("id"), r.URL.Query().Get("sha256"), r.URL.Query().Get("before"))
	if err != nil {
		assessmentFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, result)
}
