package platform

import (
	"context"
	"errors"
	"net/http"

	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/searchfilter"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/traffic"
)

func (a *API) registerTraffic(m *http.ServeMux) {
	m.HandleFunc("POST /api/v1/traffic/search", a.Auth.Require(false, a.trafficSearch))
	m.HandleFunc("GET /api/v1/traffic/fields", a.Auth.Require(false, a.trafficFields))
}

func (a *API) trafficFields(w http.ResponseWriter, r *http.Request) {
	fields, _ := searchfilter.CatalogForDataset("context")
	httpapi.JSON(w, 200, map[string]any{"version": searchfilter.Version, "dataset": "context", "fields": fields})
}

func (a *API) trafficSearch(w http.ResponseWriter, r *http.Request) {
	var q model.TrafficSearchRequest
	if err := httpapi.Decode(w, r, &q); err != nil {
		httpapi.Fail(w, r, 400, "invalid_request", "流量检索参数无效")
		return
	}
	if err := store.ValidateTrafficSearch(&q); err != nil {
		httpapi.Fail(w, r, 400, "invalid_search", err.Error())
		return
	}
	if a.ES == nil {
		httpapi.Fail(w, r, 503, "search_unavailable", "流量检索服务暂时不可用")
		return
	}
	user := httpapi.Principal(r)
	result, err := a.SearchTraffic(r.Context(), user, q)
	if err != nil {
		httpapi.Fail(w, r, 503, "search_unavailable", "流量检索未完成，请稍后重试；不完整结果不会作为正常记录展示")
		return
	}
	httpapi.JSON(w, 200, result)
}

// SearchTraffic 与浏览器和 MCP 共用完整检索校验；协议展示先从原文提取，再按角色去除原文。
func (a *API) SearchTraffic(ctx context.Context, user model.Principal, q model.TrafficSearchRequest) (traffic.Result, error) {
	if err := store.ValidateTrafficSearch(&q); err != nil {
		return traffic.Result{}, err
	}
	if a.ES == nil {
		return traffic.Result{}, errors.New("流量检索服务暂时不可用")
	}
	stored, err := a.ES.SearchTraffic(ctx, user.TenantID, q)
	if err != nil {
		return traffic.Result{}, err
	}
	result := traffic.Result{Items: []traffic.Record{}, Total: stored.Total, Page: stored.Page, PageSize: stored.PageSize}
	for _, item := range stored.Items {
		details := traffic.Parse(item.Event.Original)
		if user.Role != "admin" {
			item.Event.Original = ""
		}
		result.Items = append(result.Items, traffic.Record{Alert: item, Details: details})
	}
	return result, nil
}
