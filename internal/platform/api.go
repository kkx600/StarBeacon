// Package platform 编排平台 HTTP 功能，领域数据通过持久存储读取。
package platform

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/redis/go-redis/v9"
)

type API struct {
	DB    *store.Postgres
	ES    *store.Elasticsearch
	Redis *redis.Client
	Auth  *httpapi.Auth
}

func (a *API) Handler() http.Handler {
	m := http.NewServeMux()
	a.Auth.Register(m, "/api/v1")
	httpapi.Health(m, a.Ready)
	m.HandleFunc("GET /api/v1/sensors", a.Auth.Require(false, a.sensors))
	m.HandleFunc("PATCH /api/v1/sensors/{id}", a.Auth.Require(true, a.setSensor))
	m.HandleFunc("POST /api/v1/alerts/search", a.Auth.Require(false, a.alerts))
	m.HandleFunc("GET /api/v1/platform/health", a.Auth.Require(true, a.health))
	m.HandleFunc("GET /api/v1/audits/operations", a.Auth.Require(true, a.audits))
	return m
}
func (a *API) Ready(ctx context.Context) error {
	if e := a.DB.Pool.Ping(ctx); e != nil {
		return e
	}
	if e := a.Redis.Ping(ctx).Err(); e != nil {
		return e
	}
	return a.ES.Ping(ctx)
}
func (a *API) sensors(w http.ResponseWriter, r *http.Request) {
	items, e := a.DB.Sensors(r.Context(), httpapi.Principal(r).TenantID)
	if e != nil {
		httpapi.Fail(w, r, 503, "storage_unavailable", "暂时无法读取探针")
		return
	}
	httpapi.JSON(w, 200, map[string]any{"items": items})
}
func (a *API) setSensor(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Active *bool `json:"active"`
	}
	if e := httpapi.Decode(w, r, &input); e != nil || input.Active == nil {
		httpapi.Fail(w, r, 400, "invalid_request", "需要提供探针启用状态")
		return
	}
	e := a.DB.SetSensorActive(r.Context(), httpapi.Principal(r), r.PathValue("id"), *input.Active, httpapi.RequestID(r))
	if errors.Is(e, pgx.ErrNoRows) {
		httpapi.Fail(w, r, 404, "not_found", "探针不存在或不可访问")
		return
	}
	if e != nil {
		httpapi.Fail(w, r, 503, "storage_unavailable", "暂时无法保存探针状态")
		return
	}
	httpapi.JSON(w, 200, map[string]bool{"ok": true})
}
func (a *API) alerts(w http.ResponseWriter, r *http.Request) {
	var q model.SearchRequest
	if e := httpapi.Decode(w, r, &q); e != nil {
		httpapi.Fail(w, r, 400, "invalid_request", e.Error())
		return
	}
	if e := store.ValidateSearch(&q); e != nil {
		httpapi.Fail(w, r, 400, "invalid_search", e.Error())
		return
	}
	u := httpapi.Principal(r)
	v, e := a.ES.Search(r.Context(), u.TenantID, q)
	if e != nil {
		httpapi.Fail(w, r, 503, "search_unavailable", "检索服务暂时不可用")
		return
	}
	if u.Role != "admin" {
		for i := range v.Items {
			v.Items[i].Event.Original = ""
		}
	}
	httpapi.JSON(w, 200, v)
}
func (a *API) health(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	states := map[string]string{"postgresql": "ready", "redis": "ready", "elasticsearch": "ready"}
	if a.DB.Pool.Ping(ctx) != nil {
		states["postgresql"] = "unavailable"
	}
	if a.Redis.Ping(ctx).Err() != nil {
		states["redis"] = "unavailable"
	}
	if a.ES.Ping(ctx) != nil {
		states["elasticsearch"] = "unavailable"
	}
	httpapi.JSON(w, 200, map[string]any{"services": states, "observed_at": time.Now().UTC()})
}
func (a *API) audits(w http.ResponseWriter, r *http.Request) {
	items := make([]map[string]any, 0)
	u := httpapi.Principal(r)
	e := a.DB.TenantTx(r.Context(), u.TenantID, func(tx pgx.Tx) error {
		rows, e := tx.Query(r.Context(), "SELECT id,user_id,action,object_id,request_id,created_at FROM operation_audits WHERE tenant_id=$1 ORDER BY id DESC LIMIT 200", u.TenantID)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var id int64
			var user, action, object, request string
			var at time.Time
			if e = rows.Scan(&id, &user, &action, &object, &request, &at); e != nil {
				return e
			}
			items = append(items, map[string]any{"id": strconv.FormatInt(id, 10), "user_id": user, "action": action, "object_id": object, "request_id": request, "created_at": at})
		}
		return rows.Err()
	})
	if e != nil {
		httpapi.Fail(w, r, 503, "audit_unavailable", "暂时无法读取操作日志")
		return
	}
	httpapi.JSON(w, 200, map[string]any{"items": items})
}
