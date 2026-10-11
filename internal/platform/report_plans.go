package platform

import (
	"errors"
	"net/http"

	"github.com/kkx600/StarBeacon/internal/assistant"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/store"
)

func (a *API) registerReportPlans(m *http.ServeMux) {
	m.HandleFunc("GET /api/v1/analysis/plans", a.Auth.Require(true, a.reportPlans))
	m.HandleFunc("POST /api/v1/analysis/plans", a.Auth.Require(true, a.saveReportPlan))
	m.HandleFunc("GET /api/v1/analysis/plans/{id}/runs", a.Auth.Require(true, a.reportPlanRuns))
}

func planFailure(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, store.ErrPlanQuota) {
		httpapi.Fail(w, r, 429, "report_plan_quota_exceeded", "报告计划数量或操作额度已达到上限，请核对已有计划")
		return
	}
	analysisFailure(w, r, err)
}

func (a *API) reportPlans(w http.ResponseWriter, r *http.Request) {
	if a.DB == nil {
		httpapi.Fail(w, r, 503, "analysis_unavailable", "报告计划数据服务暂不可用")
		return
	}
	items, err := a.DB.ReportPlans(r.Context(), httpapi.Principal(r))
	if err != nil {
		planFailure(w, r, err)
		return
	}
	available := a.Jobs != nil && (a.JobsReady == nil || a.JobsReady())
	httpapi.JSON(w, 200, map[string]any{"items": items, "execution_available": available, "model_execution_available": available && a.Vault != nil, "limit": 32})
}

func (a *API) saveReportPlan(w http.ResponseWriter, r *http.Request) {
	var input assistant.PlanChange
	if httpapi.Decode(w, r, &input) != nil || input.Spec.Validate() != nil {
		planFailure(w, r, assistant.ErrInput)
		return
	}
	if a.DB == nil || (input.Spec.Enabled && (a.Jobs == nil || (a.JobsReady != nil && !a.JobsReady()))) {
		httpapi.Fail(w, r, 503, "analysis_unavailable", "报告计划执行服务暂不可用，可保存停用计划")
		return
	}
	item, err := a.DB.SaveReportPlan(r.Context(), httpapi.Principal(r), input, a.Jobs, a.Vault, httpapi.RequestID(r))
	if err != nil {
		planFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, item)
}

func (a *API) reportPlanRuns(w http.ResponseWriter, r *http.Request) {
	if a.DB == nil {
		httpapi.Fail(w, r, 503, "analysis_unavailable", "报告计划数据服务暂不可用")
		return
	}
	page, err := a.DB.ReportPlanRuns(r.Context(), httpapi.Principal(r), r.PathValue("id"), r.URL.Query().Get("before"))
	if err != nil {
		planFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, page)
}
