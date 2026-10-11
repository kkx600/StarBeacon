package platform

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/savedsearch"
	"github.com/kkx600/StarBeacon/internal/searchfilter"
	"github.com/kkx600/StarBeacon/internal/store"
)

func (a *API) registerSavedSearches(m *http.ServeMux) {
	m.HandleFunc("GET /api/v1/saved-searches", a.Auth.Require(false, a.savedSearches))
	m.HandleFunc("GET /api/v1/saved-searches/{id}", a.Auth.Require(false, a.savedSearch))
	m.HandleFunc("POST /api/v1/saved-searches", a.Auth.Require(false, a.saveSavedSearch))
	m.HandleFunc("POST /api/v1/saved-searches/{id}/resolve", a.Auth.Require(false, a.resolveSavedSearch))
}

func savedSearchFailure(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, savedsearch.ErrInput):
		httpapi.Fail(w, r, 400, "invalid_saved_search", "请核对名称、查询条件、时间范围、实例标识与修订，并提交实际变更")
	case errors.Is(err, savedsearch.ErrVersion):
		httpapi.Fail(w, r, 409, "saved_search_version", "查询解析器版本不兼容，请按当前字段与语法核对后重新保存；查询未执行")
	case errors.Is(err, savedsearch.ErrPermission):
		httpapi.Fail(w, r, 403, "saved_search_forbidden", "个人查询仅所有者可修改；团队共享查询须由具有管理员权限的所有者维护")
	case errors.Is(err, savedsearch.ErrQuota):
		httpapi.Fail(w, r, 429, "saved_search_quota", "保存查询或最近 24 小时的变更数量已达上限")
	case errors.Is(err, savedsearch.ErrInactive):
		httpapi.Fail(w, r, 409, "saved_search_inactive", "该查询已停用，请刷新列表并选择有效查询")
	case errors.Is(err, store.ErrConflict):
		httpapi.Fail(w, r, 409, "saved_search_conflict", "查询实例、修订、数据集或原提交输入已变化，请刷新后核对")
	case errors.Is(err, pgx.ErrNoRows):
		httpapi.Fail(w, r, 404, "not_found", "查询不存在、已到期或不可访问")
	default:
		httpapi.Fail(w, r, 503, "saved_search_unavailable", "保存查询服务暂不可用；提交结果未确认时请核对原提交")
	}
}

func (a *API) savedSearchReady(w http.ResponseWriter, r *http.Request) bool {
	if a.DB != nil {
		return true
	}
	savedSearchFailure(w, r, errors.New("保存查询存储不可用"))
	return false
}

func savedSearchListQuery(r *http.Request) (savedsearch.ListQuery, error) {
	q := savedsearch.ListQuery{Limit: 20, Active: "true"}
	for key, values := range r.URL.Query() {
		if len(values) != 1 {
			return q, savedsearch.ErrInput
		}
		switch key {
		case "dataset":
			q.Dataset = values[0]
		case "visibility":
			q.Visibility = values[0]
		case "active":
			q.Active = values[0]
		case "keyword":
			q.Keyword = values[0]
		case "cursor":
			q.Cursor = values[0]
		case "limit":
			var err error
			q.Limit, err = strconv.Atoi(values[0])
			if err != nil {
				return q, savedsearch.ErrInput
			}
		default:
			return q, savedsearch.ErrInput
		}
	}
	return q, q.Validate()
}

func (a *API) savedSearches(w http.ResponseWriter, r *http.Request) {
	q, err := savedSearchListQuery(r)
	if err != nil {
		savedSearchFailure(w, r, err)
		return
	}
	if !a.savedSearchReady(w, r) {
		return
	}
	result, err := a.DB.SavedSearches(r.Context(), httpapi.Principal(r), q)
	if err != nil {
		savedSearchFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, result)
}

func (a *API) savedSearch(w http.ResponseWriter, r *http.Request) {
	if !a.savedSearchReady(w, r) {
		return
	}
	result, err := a.DB.SavedSearch(r.Context(), httpapi.Principal(r), r.PathValue("id"))
	if err != nil {
		savedSearchFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, result)
}

func (a *API) saveSavedSearch(w http.ResponseWriter, r *http.Request) {
	var c savedsearch.Change
	if httpapi.Decode(w, r, &c) != nil {
		savedSearchFailure(w, r, savedsearch.ErrInput)
		return
	}
	if err := c.Validate(); err != nil {
		savedSearchFailure(w, r, err)
		return
	}
	if !a.savedSearchReady(w, r) {
		return
	}
	result, err := a.DB.SaveSavedSearch(r.Context(), httpapi.Principal(r), r.Header.Get("Idempotency-Key"), c)
	if err != nil {
		savedSearchFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, result)
}

func (a *API) resolveSavedSearch(w http.ResponseWriter, r *http.Request) {
	var input struct {
		ExpectedRevision     int64  `json:"expected_revision"`
		ExpectedGenerationID string `json:"expected_generation_id"`
		Dataset              string `json:"dataset"`
		ParserVersion        string `json:"parser_version"`
	}
	if httpapi.Decode(w, r, &input) != nil {
		savedSearchFailure(w, r, savedsearch.ErrInput)
		return
	}
	if input.ParserVersion != searchfilter.Version {
		savedSearchFailure(w, r, savedsearch.ErrVersion)
		return
	}
	if !a.savedSearchReady(w, r) {
		return
	}
	result, err := a.DB.ResolveSavedSearch(r.Context(), httpapi.Principal(r), r.PathValue("id"), input.ExpectedGenerationID, input.Dataset, input.ExpectedRevision)
	if err != nil {
		savedSearchFailure(w, r, err)
		return
	}
	// 此接口只解析参数；数据读取必须调用原检索入口并重新检查执行者的当前会话。
	httpapi.JSON(w, 200, result)
}
