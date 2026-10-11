package platform

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/accounts"
	"github.com/kkx600/StarBeacon/internal/store"
)

func TestUserHTTPStrictInputsAndDependencies(t *testing.T) {
	a := &API{}
	for _, handler := range []http.HandlerFunc{a.createUser, a.changeUser} {
		for _, body := range []string{`null`, `[]`, `{"role":"admin","role":"viewer"}`, `{"Role":"admin"}`, `{"extra":true}`, `{} {}`, `{"expected_revision":"1"}`} {
			r := httptest.NewRequest("POST", "/api/v1/users", strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			handler(w, r)
			if w.Code != 400 {
				t.Fatalf("歧义用户请求进入存储：%d", w.Code)
			}
		}
	}
	for _, target := range []string{"/api/v1/users?active=yes", "/api/v1/users?role=owner", "/api/v1/users?role=admin&role=viewer", "/api/v1/users?before=bad/id", "/api/v1/users?extra=true"} {
		w := httptest.NewRecorder()
		a.users(w, httptest.NewRequest("GET", target, nil))
		if w.Code != 400 {
			t.Fatal("非法筛选进入存储")
		}
	}
	for i, handler := range []http.HandlerFunc{a.users, a.user, a.createUser, a.changeUser} {
		body := `{"username":"owned","password":"owned-pass-12345","role":"viewer","active":true}`
		if i == 3 {
			body = `{"expected_revision":1,"role":"viewer","active":true}`
		}
		r := httptest.NewRequest("POST", "/api/v1/users", strings.NewReader(body))
		r.SetPathValue("id", "user_owned")
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Idempotency-Key", "owned_key")
		w := httptest.NewRecorder()
		handler(w, r)
		if w.Code != 503 {
			t.Fatal("未配置存储返回正常数据", w.Code)
		}
	}
	w := httptest.NewRecorder()
	a.user(w, httptest.NewRequest("GET", "/api/v1/users/id?extra=true", nil))
	if w.Code != 400 {
		t.Fatal("详情额外筛选被忽略")
	}
}

func TestUserHTTPFailureMeaning(t *testing.T) {
	for _, item := range []struct {
		err    error
		status int
		code   string
	}{{accounts.ErrInput, 400, "invalid_user"}, {accounts.ErrUnavailable, 403, "user_management_forbidden"}, {accounts.ErrProtected, 409, "current_user_protected"}, {store.ErrConflict, 409, "user_conflict"}, {pgx.ErrNoRows, 404, "not_found"}, {accounts.ErrExpired, 410, "user_request_expired"}, {accounts.ErrQuota, 429, "user_quota_exceeded"}, {errors.New("private storage failure"), 503, "user_management_unavailable"}} {
		w := httptest.NewRecorder()
		userFailure(w, httptest.NewRequest("GET", "/api/v1/users", nil), item.err)
		var result struct {
			Code string `json:"code"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &result)
		if w.Code != item.status || result.Code != item.code || strings.Contains(w.Body.String(), "private storage failure") {
			t.Fatal("用户管理错误含义或内部错误泄漏", w.Code, result.Code)
		}
		if item.status == 429 && w.Header().Get("Retry-After") == "" {
			t.Fatal("缺少重试提示")
		}
	}
}
