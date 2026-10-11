package platform

import (
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/notify"
	"github.com/kkx600/StarBeacon/internal/outbound"
	"github.com/kkx600/StarBeacon/internal/secrets"
	"github.com/kkx600/StarBeacon/internal/store"
)

func (a *API) registerNotifications(m *http.ServeMux) {
	m.HandleFunc("GET /api/v1/notifications/channels", a.Auth.Require(true, a.notificationChannels))
	m.HandleFunc("POST /api/v1/notifications/channels", a.Auth.Require(true, a.saveNotificationChannel))
	m.HandleFunc("POST /api/v1/notifications/channels/{id}/test", a.Auth.Require(true, a.testNotificationChannel))
	m.HandleFunc("GET /api/v1/notifications/deliveries", a.Auth.Require(true, a.notificationDeliveries))
	m.HandleFunc("POST /api/v1/notifications/deliveries/{id}/retry", a.Auth.Require(true, a.retryNotification))
}

func notificationFailure(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		httpapi.Fail(w, r, 404, "not_found", "通知渠道不存在或不可访问")
	case errors.Is(err, store.ErrConflict):
		httpapi.Fail(w, r, 409, "conflict", "通知配置或投递状态已变化，请刷新后重试")
	case errors.Is(err, store.ErrNotificationQuery):
		httpapi.Fail(w, r, 400, "invalid_query", "推送日志查询参数无效")
	case errors.Is(err, notify.ErrConfig), errors.Is(err, outbound.ErrTarget):
		httpapi.Fail(w, r, 400, "invalid_notification_config", "通知配置无效或目标不在允许范围内")
	case errors.Is(err, secrets.ErrUnavailable):
		httpapi.Fail(w, r, 503, "credentials_unavailable", "通知凭据密钥未配置或凭据无法校验")
	default:
		httpapi.Fail(w, r, 503, "storage_unavailable", "通知服务暂时不可用")
	}
}

func (a *API) notificationChannels(w http.ResponseWriter, r *http.Request) {
	items, err := a.DB.NotificationChannels(r.Context(), httpapi.Principal(r).TenantID)
	if err != nil {
		notificationFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, map[string]any{"items": items, "available": a.Vault != nil, "development": a.Outbound.Development, "limit": 50})
}

func (a *API) saveNotificationChannel(w http.ResponseWriter, r *http.Request) {
	var input store.ChannelChange
	if httpapi.Decode(w, r, &input) != nil {
		httpapi.Fail(w, r, 400, "invalid_request", "通知渠道参数无效")
		return
	}
	item, err := a.DB.SaveNotificationChannel(r.Context(), httpapi.Principal(r), input, a.Vault, a.Outbound, httpapi.RequestID(r))
	if err != nil {
		notificationFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, item)
}

func (a *API) testNotificationChannel(w http.ResponseWriter, r *http.Request) {
	err := a.DB.TestNotification(r.Context(), httpapi.Principal(r), r.PathValue("id"), r.Header.Get("Idempotency-Key"), a.Vault, httpapi.RequestID(r))
	if err != nil {
		notificationFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 202, map[string]string{"state": "queued", "message": "测试投递已受理，请在推送日志中查看渠道回执"})
}

func (a *API) notificationDeliveries(w http.ResponseWriter, r *http.Request) {
	items, next, err := a.DB.NotificationDeliveries(r.Context(), httpapi.Principal(r).TenantID, r.URL.Query().Get("cursor"), r.URL.Query().Get("state"))
	if err != nil {
		notificationFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, map[string]any{"items": items, "next_cursor": next})
}

func (a *API) retryNotification(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Version               int64 `json:"expected_version"`
		AcknowledgeDuplicates bool  `json:"acknowledge_duplicates"`
	}
	if httpapi.Decode(w, r, &input) != nil || !input.AcknowledgeDuplicates {
		httpapi.Fail(w, r, 400, "duplicate_risk_not_acknowledged", "人工重试可能重复通知，需要明确确认重复投递影响")
		return
	}
	err := a.DB.RetryNotification(r.Context(), httpapi.Principal(r), r.PathValue("id"), input.Version, httpapi.RequestID(r))
	if err != nil {
		notificationFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 202, map[string]string{"state": "queued"})
}
