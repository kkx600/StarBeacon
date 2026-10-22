package platform

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/watchlist"
)

func (a *API) registerWatchlists(m *http.ServeMux) {
	m.HandleFunc("GET /api/v1/watchlists", a.Auth.Require(false, a.watchlists))
	m.HandleFunc("POST /api/v1/watchlists", a.Auth.Require(true, a.saveWatchlist))
	m.HandleFunc("GET /api/v1/watchlists/{id}/revisions/{revision}", a.Auth.Require(false, a.watchlistRevision))
	m.HandleFunc("POST /api/v1/watchlists/preview", a.Auth.Require(true, a.previewWatchlist))
}

func decodeWatchlist(w http.ResponseWriter, r *http.Request, target any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 32768)
	var raw json.RawMessage
	if httpapi.Decode(w, r, &raw) != nil || contract.JSONFields(string(raw), []string{"id", "expected_revision", "name", "description", "active", "definition", "schema_version", "kind", "match_type", "values", "sensors", "sensor_id", "registration_id", "valid_from", "valid_until", "targets", "type", "value"}, 32768) != nil {
		return watchlist.ErrInput
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(target) != nil {
		return watchlist.ErrInput
	}
	return nil
}

func watchlistFailure(w http.ResponseWriter, r *http.Request, e error) {
	switch {
	case errors.Is(e, watchlist.ErrInput):
		httpapi.Fail(w, r, 400, "invalid_watchlist", "请核对名单、规范值、探针范围和有效期；过宽网段或到期名单不能启用")
	case errors.Is(e, watchlist.ErrPermission):
		httpapi.Fail(w, r, 403, "watchlist_forbidden", "当前账号的名单权限已变化，请重新核对权限")
	case errors.Is(e, model.ErrUnauthenticated):
		httpapi.Fail(w, r, 401, "session_expired", "会话或权限已变化")
	case errors.Is(e, watchlist.ErrQuota), errors.Is(e, watchlist.ErrLimit):
		httpapi.Fail(w, r, 429, "watchlist_quota", "名单、近期变更或预览数量已达上限")
	case errors.Is(e, store.ErrConflict):
		httpapi.Fail(w, r, 409, "watchlist_conflict", "名单修订、探针注册或原提交输入已变化，请刷新后核对")
	case errors.Is(e, pgx.ErrNoRows):
		httpapi.Fail(w, r, 404, "not_found", "名单修订不存在、已到期或不可访问")
	default:
		httpapi.Fail(w, r, 503, "watchlist_unavailable", "名单服务暂不可用或修订不完整，未提交部分结果")
	}
}
func (a *API) watchlistReady(w http.ResponseWriter, r *http.Request) bool {
	if a.DB != nil {
		return true
	}
	watchlistFailure(w, r, errors.New("名单存储不可用"))
	return false
}
func (a *API) watchlists(w http.ResponseWriter, r *http.Request) {
	q := watchlist.Query{Limit: 20}
	values, parseErr := url.ParseQuery(r.URL.RawQuery)
	if parseErr != nil {
		watchlistFailure(w, r, watchlist.ErrInput)
		return
	}
	for k, v := range values {
		if len(v) != 1 {
			watchlistFailure(w, r, watchlist.ErrInput)
			return
		}
		switch k {
		case "cursor":
			q.Cursor = v[0]
		case "keyword":
			q.Keyword = v[0]
		case "active":
			q.Active = v[0]
		case "kind":
			q.Kind = v[0]
		case "limit":
			n, e := strconv.Atoi(v[0])
			if e != nil || strconv.Itoa(n) != v[0] {
				watchlistFailure(w, r, watchlist.ErrInput)
				return
			}
			q.Limit = n
		default:
			watchlistFailure(w, r, watchlist.ErrInput)
			return
		}
	}
	if _, e := q.Position(httpapi.Principal(r).TenantID); e != nil {
		watchlistFailure(w, r, e)
		return
	}
	if !a.watchlistReady(w, r) {
		return
	}
	out, e := a.DB.Watchlists(r.Context(), httpapi.Principal(r), q)
	if e != nil {
		watchlistFailure(w, r, e)
		return
	}
	httpapi.JSON(w, 200, out)
}
func (a *API) watchlistRevision(w http.ResponseWriter, r *http.Request) {
	rev, e := strconv.ParseInt(r.PathValue("revision"), 10, 64)
	if e != nil || strconv.FormatInt(rev, 10) != r.PathValue("revision") || rev < 1 || rev > watchlist.MaxRevision || !contract.ValidID(r.PathValue("id")) || r.URL.RawQuery != "" {
		watchlistFailure(w, r, watchlist.ErrInput)
		return
	}
	if !a.watchlistReady(w, r) {
		return
	}
	out, e := a.DB.Watchlist(r.Context(), httpapi.Principal(r), r.PathValue("id"), rev)
	if e != nil {
		watchlistFailure(w, r, e)
		return
	}
	httpapi.JSON(w, 200, out)
}
func (a *API) saveWatchlist(w http.ResponseWriter, r *http.Request) {
	var c watchlist.Change
	if r.URL.RawQuery != "" || !contract.ValidID(r.Header.Get("Idempotency-Key")) || decodeWatchlist(w, r, &c) != nil || c.Validate() != nil {
		watchlistFailure(w, r, watchlist.ErrInput)
		return
	}
	if !a.watchlistReady(w, r) {
		return
	}
	out, e := a.DB.SaveWatchlist(r.Context(), httpapi.Principal(r), r.Header.Get("Idempotency-Key"), c)
	if e != nil {
		watchlistFailure(w, r, e)
		return
	}
	httpapi.JSON(w, 200, out)
}
func (a *API) previewWatchlist(w http.ResponseWriter, r *http.Request) {
	var c watchlist.PreviewRequest
	if r.URL.RawQuery != "" || decodeWatchlist(w, r, &c) != nil || c.Validate() != nil {
		watchlistFailure(w, r, watchlist.ErrInput)
		return
	}
	if !a.watchlistReady(w, r) {
		return
	}
	out, e := a.DB.PreviewWatchlist(r.Context(), httpapi.Principal(r), c)
	if e != nil {
		watchlistFailure(w, r, e)
		return
	}
	httpapi.JSON(w, 200, out)
}
