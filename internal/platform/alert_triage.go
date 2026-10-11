package platform

import (
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/triage"
)

func (a *API) registerAlertTriage(m *http.ServeMux) {
	capacity := make(chan struct{}, 2)
	m.HandleFunc("POST /api/v1/alerts/{id}/triage", a.Auth.Require(true, func(w http.ResponseWriter, r *http.Request) {
		select {
		case capacity <- struct{}{}:
			defer func() { <-capacity }()
			a.createAlertTriage(w, r)
		default:
			httpapi.Fail(w, r, 429, "triage_capacity_exceeded", "告警材料准备正在处理其他请求，请稍后重试")
		}
	}))
	m.HandleFunc("GET /api/v1/alerts/{id}/triage", a.Auth.Require(true, a.alertTriages))
	m.HandleFunc("GET /api/v1/alert-triage/jobs/{id}", a.Auth.Require(true, a.alertTriage))
	m.HandleFunc("POST /api/v1/alert-triage/jobs/{id}/cancel", a.Auth.Require(true, a.cancelAlertTriage))
}

func triageFailure(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, triage.ErrInput):
		httpapi.Fail(w, r, 400, "invalid_triage", "请核对告警标识、原始摘要、模型修订、说明与本次数据使用许可")
	case errors.Is(err, store.ErrAlertIdentity):
		httpapi.Fail(w, r, 409, "alert_identity_conflict", "告警来源不唯一或摘要已变化，未提交模型研判，请刷新后核对")
	case errors.Is(err, pgx.ErrNoRows):
		httpapi.Fail(w, r, 404, "not_found", "告警、研判作业或模型不存在、已过期或不可访问")
	case errors.Is(err, store.ErrConflict):
		httpapi.Fail(w, r, 409, "triage_conflict", "输入、模型修订或执行资格已变化；相同请求键不能改变输入")
	default:
		modelFailure(w, r, err)
	}
}

func (a *API) triageData(w http.ResponseWriter, r *http.Request) bool {
	if a.DB == nil {
		httpapi.Fail(w, r, 503, "triage_unavailable", "模型研判数据服务暂不可用")
		return false
	}
	return true
}

func (a *API) createAlertTriage(w http.ResponseWriter, r *http.Request) {
	var input triage.Request
	if httpapi.Decode(w, r, &input) != nil || input.Validate() != nil || input.EventID != r.PathValue("id") {
		triageFailure(w, r, triage.ErrInput)
		return
	}
	if !a.triageData(w, r) {
		return
	}
	u := httpapi.Principal(r)
	key := r.Header.Get("Idempotency-Key")
	prior, err := a.DB.ExistingAlertTriage(r.Context(), u, key, triage.InputHash(input))
	if err == nil {
		httpapi.JSON(w, 200, prior)
		return
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		triageFailure(w, r, err)
		return
	}
	if a.Jobs == nil || a.Vault == nil || a.ES == nil || (a.JobsReady != nil && !a.JobsReady()) {
		httpapi.Fail(w, r, 503, "triage_unavailable", "模型执行、告警检索或凭据服务暂不可用，研判尚未提交")
		return
	}
	alert, err := a.ES.ReadAlertEvidence(r.Context(), u.TenantID, input.EventID, input.RawSHA256)
	if err != nil {
		triageFailure(w, r, err)
		return
	}
	evidence, err := triage.Freeze(alert)
	if err != nil {
		triageFailure(w, r, err)
		return
	}
	job, err := a.DB.CreateAlertTriage(r.Context(), u, input, key, evidence, a.Jobs, a.Vault, httpapi.RequestID(r))
	if err != nil {
		triageFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 202, job)
}

func (a *API) alertTriages(w http.ResponseWriter, r *http.Request) {
	if !a.triageData(w, r) {
		return
	}
	page, err := a.DB.AlertTriages(r.Context(), httpapi.Principal(r), r.PathValue("id"), r.URL.Query().Get("sha256"), r.URL.Query().Get("before"))
	if err != nil {
		triageFailure(w, r, err)
		return
	}
	page.Available = a.Jobs != nil && a.Vault != nil && a.ES != nil && (a.JobsReady == nil || a.JobsReady())
	httpapi.JSON(w, 200, page)
}

func (a *API) alertTriage(w http.ResponseWriter, r *http.Request) {
	if !a.triageData(w, r) {
		return
	}
	job, err := a.DB.AlertTriage(r.Context(), httpapi.Principal(r), r.PathValue("id"))
	if err != nil {
		triageFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, job)
}

func (a *API) cancelAlertTriage(w http.ResponseWriter, r *http.Request) {
	var empty struct{}
	if httpapi.Decode(w, r, &empty) != nil {
		triageFailure(w, r, triage.ErrInput)
		return
	}
	if !a.triageData(w, r) {
		return
	}
	job, err := a.DB.CancelAlertTriage(r.Context(), httpapi.Principal(r), r.PathValue("id"), a.Jobs, httpapi.RequestID(r))
	if err != nil {
		triageFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, job)
}
