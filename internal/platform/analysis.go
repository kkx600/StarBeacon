package platform

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/analytics"
	"github.com/kkx600/StarBeacon/internal/assistant"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/store"
)

func (a *API) registerAnalysis(m *http.ServeMux) {
	a.registerReportPlans(m)
	m.HandleFunc("POST /api/v1/analysis/jobs", a.Auth.Require(true, a.createAnalysis))
	m.HandleFunc("GET /api/v1/analysis/jobs", a.Auth.Require(true, a.analysisJobs))
	m.HandleFunc("GET /api/v1/analysis/jobs/{id}", a.Auth.Require(true, a.analysisJob))
	m.HandleFunc("POST /api/v1/analysis/jobs/{id}/cancel", a.Auth.Require(true, a.cancelAnalysis))
	m.HandleFunc("GET /api/v1/analysis/jobs/{id}/report", a.Auth.Require(true, a.exportAnalysisReport))
	m.HandleFunc("GET /api/v1/analysis/threads", a.Auth.Require(true, a.analysisThreads))
	m.HandleFunc("GET /api/v1/analysis/threads/{id}", a.Auth.Require(true, a.analysisConversation))
}
func analysisFailure(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, assistant.ErrInput):
		httpapi.Fail(w, r, 400, "invalid_analysis", "分析输入无效，请核对模型、范围、周期、时区与本次数据使用许可")
	case errors.Is(err, pgx.ErrNoRows):
		httpapi.Fail(w, r, 404, "not_found", "分析作业或对话不存在、已过期或不可访问")
	case errors.Is(err, store.ErrConflict):
		httpapi.Fail(w, r, 409, "analysis_conflict", "输入、模型修订或对话已变化，请刷新后核对；相同请求键不能改变输入")
	default:
		modelFailure(w, r, err)
	}
}
func (a *API) createAnalysis(w http.ResponseWriter, r *http.Request) {
	var input assistant.Request
	if httpapi.Decode(w, r, &input) != nil {
		analysisFailure(w, r, assistant.ErrInput)
		return
	}
	input, err := input.Normalize(time.Now())
	if err != nil {
		analysisFailure(w, r, err)
		return
	}
	user := httpapi.Principal(r)
	if a.DB == nil {
		httpapi.Fail(w, r, 503, "analysis_unavailable", "分析数据服务暂不可用")
		return
	}
	key := r.Header.Get("Idempotency-Key")
	prior, err := a.DB.ExistingAnalysis(r.Context(), user, key, store.AnalysisInputHash(input))
	if err == nil {
		httpapi.JSON(w, 200, prior)
		return
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		analysisFailure(w, r, err)
		return
	}
	if input.ProviderID != "" && (a.Jobs == nil || (a.JobsReady != nil && !a.JobsReady())) {
		httpapi.Fail(w, r, 503, "analysis_unavailable", "模型分析执行服务暂不可用，统计报告仍可生成")
		return
	}
	if a.ES == nil {
		httpapi.Fail(w, r, 503, "analysis_unavailable", "统计服务暂不可用，未提交模型调用")
		return
	}
	ctx, stop := context.WithTimeout(r.Context(), 12*time.Second)
	defer stop()
	snapshots := []analytics.Snapshot{}
	for _, window := range assistant.Windows(input.Window) {
		// 作业保存完整统计快照；模型不持有 ES 凭据，也不能扩大时间或租户范围。
		rawWindow, _ := json.Marshal(window)
		cacheKey := "sb:overview:" + user.TenantID + ":" + user.Role + ":" + store.Hash(string(rawWindow))
		snapshot, err := a.overviewSnapshot(ctx, user, window, cacheKey)
		if err != nil {
			if errors.Is(err, errOverviewQuota) {
				w.Header().Set("Retry-After", "60")
				httpapi.Fail(w, r, 429, "overview_quota_exceeded", "统计请求过于频繁，分析尚未提交，请稍后重试")
			} else {
				httpapi.Fail(w, r, 503, "analysis_unavailable", "统计未能完整返回，分析尚未提交")
			}
			return
		}
		snapshots = append(snapshots, snapshot)
	}
	evidence, err := assistant.Freeze(input.Window, snapshots)
	if err != nil {
		analysisFailure(w, r, err)
		return
	}
	history, err := a.DB.AnalysisHistory(ctx, user, input.ThreadID)
	if err != nil {
		analysisFailure(w, r, err)
		return
	}
	prompt := ""
	if input.ProviderID != "" {
		prompt, err = assistant.Prompt(evidence, input, history)
		if err != nil {
			analysisFailure(w, r, err)
			return
		}
	}
	job, err := a.DB.CreateAnalysis(ctx, user, input, key, evidence, prompt, a.Jobs, a.Vault, httpapi.RequestID(r))
	if err != nil {
		analysisFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 202, job)
}
func (a *API) analysisJob(w http.ResponseWriter, r *http.Request) {
	job, err := a.DB.AnalysisJob(r.Context(), httpapi.Principal(r), r.PathValue("id"))
	if err != nil {
		analysisFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, job)
}
func (a *API) analysisJobs(w http.ResponseWriter, r *http.Request) {
	limit := 20
	var err error
	if value := r.URL.Query().Get("limit"); value != "" {
		limit, err = strconv.Atoi(value)
		if err != nil {
			analysisFailure(w, r, assistant.ErrInput)
			return
		}
	}
	group := r.URL.Query().Get("group")
	if group == "" {
		group = "reports"
	}
	page, err := a.DB.AnalysisJobs(r.Context(), httpapi.Principal(r), group, r.URL.Query().Get("before"), limit)
	if err != nil {
		analysisFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, map[string]any{"items": page.Items, "next_cursor": page.Next, "model_execution_available": a.Vault != nil && a.Jobs != nil && (a.JobsReady == nil || a.JobsReady())})
}
func (a *API) cancelAnalysis(w http.ResponseWriter, r *http.Request) {
	var input struct{}
	if httpapi.Decode(w, r, &input) != nil {
		analysisFailure(w, r, assistant.ErrInput)
		return
	}
	job, err := a.DB.CancelAnalysis(r.Context(), httpapi.Principal(r), r.PathValue("id"), a.Jobs, httpapi.RequestID(r))
	if err != nil {
		analysisFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, job)
}

func (a *API) analysisThreads(w http.ResponseWriter, r *http.Request) {
	page, err := a.DB.AnalysisThreads(r.Context(), httpapi.Principal(r), r.URL.Query().Get("before"))
	if err != nil {
		analysisFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, page)
}
func (a *API) analysisConversation(w http.ResponseWriter, r *http.Request) {
	page, err := a.DB.AnalysisConversation(r.Context(), httpapi.Principal(r), r.PathValue("id"), r.URL.Query().Get("before"))
	if err != nil {
		analysisFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, page)
}
func (a *API) exportAnalysisReport(w http.ResponseWriter, r *http.Request) {
	job, err := a.DB.AnalysisJob(r.Context(), httpapi.Principal(r), r.PathValue("id"))
	if err != nil {
		analysisFailure(w, r, err)
		return
	}
	raw, err := assistant.ReportHTML(job)
	if err != nil {
		analysisFailure(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="starbeacon-%s-%s-%s.html"`, job.Request.Kind, job.Request.Period, job.ID))
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	w.WriteHeader(200)
	_, _ = w.Write(raw)
}
