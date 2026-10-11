package platform

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/llm"
	"github.com/kkx600/StarBeacon/internal/outbound"
	"github.com/kkx600/StarBeacon/internal/secrets"
	"github.com/kkx600/StarBeacon/internal/store"
)

func (a *API) registerModels(m *http.ServeMux) {
	m.HandleFunc("GET /api/v1/models/providers", a.Auth.Require(true, a.modelProviders))
	m.HandleFunc("POST /api/v1/models/providers", a.Auth.Require(true, a.saveModelProvider))
	capacity := make(chan struct{}, 4)
	m.HandleFunc("POST /api/v1/models/providers/{id}/test", a.Auth.Require(true, func(w http.ResponseWriter, r *http.Request) {
		select {
		case capacity <- struct{}{}:
			defer func() { <-capacity }()
			a.testModelProvider(w, r)
		default:
			httpapi.Fail(w, r, 429, "model_capacity_exceeded", "模型连接验证正在处理其他请求，请稍后重试")
		}
	}))
}
func modelFailure(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		httpapi.Fail(w, r, 404, "not_found", "模型提供方不存在或不可访问")
	case errors.Is(err, store.ErrConflict):
		httpapi.Fail(w, r, 409, "conflict", "模型配置修订或验证状态已变化，请刷新后核对")
	case errors.Is(err, store.ErrModelQuota):
		httpapi.Fail(w, r, 429, "model_quota_exceeded", "模型请求额度或并发名额不足，请核对用量与执行记录")
	case errors.Is(err, llm.ErrConfig), errors.Is(err, outbound.ErrTarget):
		httpapi.Fail(w, r, 400, "invalid_model_config", "模型配置或连接目标无效；改变目标时需要重新配置凭据")
	case errors.Is(err, secrets.ErrUnavailable):
		httpapi.Fail(w, r, 503, "credentials_unavailable", "模型凭据密钥未配置或凭据校验失败")
	default:
		httpapi.Fail(w, r, 503, "storage_unavailable", "模型配置服务暂时不可用")
	}
}
func (a *API) modelProviders(w http.ResponseWriter, r *http.Request) {
	items, err := a.DB.ModelProviders(r.Context(), httpapi.Principal(r).TenantID)
	if err != nil {
		modelFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, map[string]any{"items": items, "available": a.Vault != nil, "limit": 50})
}
func (a *API) saveModelProvider(w http.ResponseWriter, r *http.Request) {
	var input store.ModelChange
	if httpapi.Decode(w, r, &input) != nil {
		httpapi.Fail(w, r, 400, "invalid_request", "模型提供方参数无效")
		return
	}
	item, err := a.DB.SaveModelProvider(r.Context(), httpapi.Principal(r), input, a.Vault, a.Outbound, httpapi.RequestID(r))
	if err != nil {
		modelFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, item)
}
func (a *API) testModelProvider(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Revision int64 `json:"expected_revision"`
	}
	if httpapi.Decode(w, r, &input) != nil {
		httpapi.Fail(w, r, 400, "invalid_request", "需要提供模型配置修订")
		return
	}
	user := httpapi.Principal(r)
	lease, err := a.DB.StartModelCheck(r.Context(), user, r.PathValue("id"), r.Header.Get("Idempotency-Key"), input.Revision, a.Vault, httpapi.RequestID(r))
	if err != nil {
		modelFailure(w, r, err)
		return
	}
	if !lease.Execute {
		httpapi.JSON(w, 200, lease.Check)
		return
	}
	// 固定短输入不携带业务事实，测试只证明生成接口响应，不授予自动研判资格。
	work, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	result := (llm.Client{Policy: a.Outbound}).Generate(work, lease.Config, "你正在执行模型连接验证。请简短回复，不调用工具。", "请回复：连接成功。", 64)
	cancel()
	finish, finishStop := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
	defer finishStop()
	check, err := a.DB.FinishModelCheck(finish, user.TenantID, lease, result)
	if err != nil {
		modelFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, check)
}
