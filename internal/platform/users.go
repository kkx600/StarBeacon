package platform

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/accounts"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/store"
)

func (a *API) registerUsers(m *http.ServeMux) {
	a.registerPasswords(m)
	m.HandleFunc("GET /api/v1/users", a.Auth.Require(true, a.users))
	m.HandleFunc("GET /api/v1/users/{id}", a.Auth.Require(true, a.user))
	m.HandleFunc("POST /api/v1/users", a.Auth.Require(true, a.createUser))
	m.HandleFunc("PATCH /api/v1/users/{id}", a.Auth.Require(true, a.changeUser))
}
func userFailure(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, accounts.ErrInput):
		httpapi.Fail(w, r, 400, "invalid_user", "用户参数无效或没有可提交的变更，请核对账号、角色、状态及修订")
	case errors.Is(err, accounts.ErrUnavailable):
		httpapi.Fail(w, r, 403, "user_management_forbidden", "当前账号已停用或不具备用户管理权限")
	case errors.Is(err, accounts.ErrProtected):
		httpapi.Fail(w, r, 409, "current_user_protected", "不能停用或降低当前登录账号的权限，请由其他管理员处理")
	case errors.Is(err, store.ErrConflict):
		httpapi.Fail(w, r, 409, "user_conflict", "账号名称、当前修订或原请求已变化，请刷新并核对原提交")
	case errors.Is(err, pgx.ErrNoRows):
		httpapi.Fail(w, r, 404, "not_found", "用户不存在或不可访问")
	case errors.Is(err, accounts.ErrExpired):
		httpapi.Fail(w, r, 410, "user_request_expired", "原提交已到保留期限，不能作为新的用户管理操作执行")
	case errors.Is(err, accounts.ErrQuota):
		w.Header().Set("Retry-After", "60")
		httpapi.Fail(w, r, 429, "user_quota_exceeded", "用户数量或今日变更额度已用尽，请稍后重试")
	default:
		httpapi.Fail(w, r, 503, "user_management_unavailable", "用户管理服务暂不可用；提交结果需使用原请求核对")
	}
}
func (a *API) users(w http.ResponseWriter, r *http.Request) {
	q := accounts.Query{Role: r.URL.Query().Get("role"), Active: r.URL.Query().Get("active"), Before: r.URL.Query().Get("before")}
	if !incidentQuery(r, "role", "active", "before") || q.Validate() != nil {
		userFailure(w, r, accounts.ErrInput)
		return
	}
	if a.DB == nil {
		userFailure(w, r, errors.New("用户存储未配置"))
		return
	}
	p, err := a.DB.Users(r.Context(), httpapi.Principal(r), q)
	if err != nil {
		userFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, p)
}
func (a *API) user(w http.ResponseWriter, r *http.Request) {
	if !incidentQuery(r) || !contract.ValidID(r.PathValue("id")) {
		userFailure(w, r, accounts.ErrInput)
		return
	}
	if a.DB == nil {
		userFailure(w, r, errors.New("用户存储未配置"))
		return
	}
	p, err := a.DB.User(r.Context(), httpapi.Principal(r), r.PathValue("id"))
	if err != nil {
		userFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, p)
}
func decodeUser(w http.ResponseWriter, r *http.Request, target any) bool {
	var raw json.RawMessage
	if !incidentQuery(r) || httpapi.Decode(w, r, &raw) != nil || contract.JSONFields(string(raw), []string{"username", "password", "role", "active", "expected_revision"}, 16384) != nil {
		userFailure(w, r, accounts.ErrInput)
		return false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(target) != nil {
		userFailure(w, r, accounts.ErrInput)
		return false
	}
	return true
}
func (a *API) createUser(w http.ResponseWriter, r *http.Request) {
	var input accounts.Create
	if !decodeUser(w, r, &input) {
		return
	}
	if input.Validate() != nil || !contract.ValidID(r.Header.Get("Idempotency-Key")) {
		userFailure(w, r, accounts.ErrInput)
		return
	}
	if a.DB == nil {
		userFailure(w, r, errors.New("用户存储未配置"))
		return
	}
	p, err := a.DB.CreateUser(r.Context(), httpapi.Principal(r), r.Header.Get("Idempotency-Key"), input)
	if err != nil {
		userFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, p)
}
func (a *API) changeUser(w http.ResponseWriter, r *http.Request) {
	var input accounts.Change
	if !decodeUser(w, r, &input) {
		return
	}
	if input.Validate() != nil || !contract.ValidID(r.PathValue("id")) || !contract.ValidID(r.Header.Get("Idempotency-Key")) {
		userFailure(w, r, accounts.ErrInput)
		return
	}
	if a.DB == nil {
		userFailure(w, r, errors.New("用户存储未配置"))
		return
	}
	p, err := a.DB.ChangeUser(r.Context(), httpapi.Principal(r), r.PathValue("id"), r.Header.Get("Idempotency-Key"), input)
	if err != nil {
		userFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, p)
}
