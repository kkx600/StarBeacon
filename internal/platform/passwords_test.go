package platform

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kkx600/StarBeacon/internal/accounts"
)

func TestPasswordHTTPRejectsAmbiguousOrUnavailableRequests(t *testing.T) {
	a := &API{}
	for _, body := range []string{`null`, `[]`, `{}`, `{"expected_revision":1,"current_password":"old","new_password":"password-new-1234","NewPassword":"extra"}`, `{"expected_revision":1,"expected_revision":2}`, `{"expected_revision":"1","current_password":"old","new_password":"password-new-1234"}`} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/api/v1/auth/password", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Idempotency-Key", "password_owned")
		a.changePassword(w, r, "user_owned", false)
		if w.Code != 400 {
			t.Fatal("歧义密码参数进入存储")
		}
	}
	for _, target := range []string{"/api/v1/auth/password", "/api/v1/auth/password?extra=true"} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", target, strings.NewReader(`{"expected_revision":1,"current_password":"old","new_password":"password-new-1234"}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Idempotency-Key", "password_owned")
		a.changePassword(w, r, "user_owned", false)
		if target == "/api/v1/auth/password" && w.Code != 503 || strings.Contains(target, "?") && w.Code != 400 {
			t.Fatal("密码依赖或参数含义不正确", w.Code)
		}
	}
	for _, target := range []string{"/api/v1/auth/account", "/api/v1/auth/account?extra=true"} {
		w := httptest.NewRecorder()
		a.passwordAccount(w, httptest.NewRequest("GET", target, nil))
		if target == "/api/v1/auth/account" && w.Code != 503 || strings.Contains(target, "?") && w.Code != 400 {
			t.Fatal("账号依赖或参数含义不正确")
		}
	}
	for _, item := range []struct {
		err    error
		status int
	}{{accounts.ErrPassword, 403}, {accounts.ErrPasswordRate, 429}, {accounts.ErrInput, 400}, {accounts.ErrUnavailable, 403}} {
		w := httptest.NewRecorder()
		passwordFailure(w, httptest.NewRequest("POST", "/api/v1/auth/password", nil), item.err)
		if w.Code != item.status || item.status == http.StatusTooManyRequests && w.Header().Get("Retry-After") != "60" {
			t.Fatal("密码操作错误含义不正确")
		}
	}
}
