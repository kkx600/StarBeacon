package platform

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/kkx600/StarBeacon/internal/accounts"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/httpapi"
)

func (a *API) registerPasswords(m *http.ServeMux) {
	m.HandleFunc("GET /api/v1/auth/account", a.Auth.Require(false, a.passwordAccount))
	m.HandleFunc("POST /api/v1/auth/password", a.Auth.Require(false, a.changeOwnPassword))
	m.HandleFunc("POST /api/v1/users/{id}/password", a.Auth.Require(true, a.resetUserPassword))
}

func passwordFailure(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, accounts.ErrPassword):
		httpapi.Fail(w, r, 403, "current_password_invalid", "当前登录账号的密码验证失败，请重新输入")
	case errors.Is(err, accounts.ErrPasswordRate):
		w.Header().Set("Retry-After", "60")
		httpapi.Fail(w, r, 429, "password_attempts_exceeded", "密码操作过于频繁，请一分钟后重试")
	case errors.Is(err, accounts.ErrInput):
		httpapi.Fail(w, r, 400, "invalid_password_change", "密码参数无效或与原密码相同；新密码须为 12～72 个 UTF-8 字节，不含控制字符")
	default:
		userFailure(w, r, err)
	}
}

func (a *API) passwordAccount(w http.ResponseWriter, r *http.Request) {
	if !incidentQuery(r) {
		passwordFailure(w, r, accounts.ErrInput)
		return
	}
	if a.DB == nil {
		passwordFailure(w, r, errors.New("账号存储未配置"))
		return
	}
	result, err := a.DB.PasswordAccount(r.Context(), httpapi.Principal(r))
	if err != nil {
		passwordFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, result)
}

func (a *API) changeOwnPassword(w http.ResponseWriter, r *http.Request) {
	a.changePassword(w, r, httpapi.Principal(r).ID, true)
}

func (a *API) resetUserPassword(w http.ResponseWriter, r *http.Request) {
	// 当前账号通过独立入口修改，管理员重置只面向其他租户成员。
	if r.PathValue("id") == httpapi.Principal(r).ID {
		passwordFailure(w, r, accounts.ErrInput)
		return
	}
	a.changePassword(w, r, r.PathValue("id"), false)
}

func (a *API) changePassword(w http.ResponseWriter, r *http.Request, id string, own bool) {
	var raw json.RawMessage
	var input accounts.PasswordChange
	if !contract.ValidID(id) || !contract.ValidID(r.Header.Get("Idempotency-Key")) || !incidentQuery(r) || httpapi.Decode(w, r, &raw) != nil || contract.JSONFields(string(raw), []string{"current_password", "new_password", "expected_revision"}, 16384) != nil {
		passwordFailure(w, r, accounts.ErrInput)
		return
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&input) != nil || input.Validate() != nil {
		passwordFailure(w, r, accounts.ErrInput)
		return
	}
	if a.DB == nil {
		passwordFailure(w, r, errors.New("账号存储未配置"))
		return
	}
	result, err := a.DB.ChangePassword(r.Context(), httpapi.Principal(r), id, r.Header.Get("Idempotency-Key"), input)
	if err != nil {
		passwordFailure(w, r, err)
		return
	}
	if own {
		http.SetCookie(w, &http.Cookie{Name: a.Auth.CookieName, Path: "/", HttpOnly: true, Secure: a.Auth.Secure, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	}
	httpapi.JSON(w, 200, result)
}
