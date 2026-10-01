package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kkx600/StarBeacon/internal/model"
)

type sessionStub struct {
	u   model.Principal
	err error
}

func (s sessionStub) Password(context.Context, string) (model.Principal, string, error) {
	return s.u, "", s.err
}
func (s sessionStub) CreateSession(context.Context, model.Principal) (string, string, error) {
	return "", "", nil
}
func (s sessionStub) Session(context.Context, string) (model.Principal, error) { return s.u, s.err }
func (s sessionStub) DeleteSession(context.Context, string) error              { return nil }
func (s sessionStub) LoginAudit(context.Context, model.Principal, bool) error  { return nil }

func TestSessionAuthorizationAndCSRF(t *testing.T) {
	for _, tc := range []struct {
		name, role, csrf, origin, fetch string
		err                             error
		want                            int
	}{
		{name: "合法管理员", role: "admin", csrf: "test-csrf", origin: "https://console.example", want: 204},
		{name: "未授权角色", role: "viewer", csrf: "test-csrf", want: 403},
		{name: "缺少CSRF", role: "admin", want: 403},
		{name: "跨站请求", role: "admin", csrf: "test-csrf", origin: "https://other.example", want: 403},
		{name: "跨站浏览器标记", role: "admin", csrf: "test-csrf", fetch: "cross-site", want: 403},
		{name: "真实过期", err: model.ErrUnauthenticated, want: 401},
		{name: "数据库故障保留会话", err: errors.New("数据库不可用"), want: 503},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := &Auth{Store: sessionStub{u: model.Principal{Role: tc.role, CSRF: "test-csrf"}, err: tc.err}, CookieName: "session", Origin: "https://console.example"}
			r := httptest.NewRequest("PATCH", "/api/v1/sensors/one", strings.NewReader(`{"active":false}`))
			r.AddCookie(&http.Cookie{Name: "session", Value: strings.Repeat("a", 64)})
			r.Header.Set("X-CSRF-Token", tc.csrf)
			r.Header.Set("Origin", tc.origin)
			r.Header.Set("Sec-Fetch-Site", tc.fetch)
			w := httptest.NewRecorder()
			a.Require(true, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })(w, r)
			if w.Code != tc.want {
				t.Fatalf("状态=%d，期望=%d", w.Code, tc.want)
			}
		})
	}
}
func TestDecodeRejectsTenantOverrideAndAdditionalDocument(t *testing.T) {
	for _, body := range []string{`{"active":true,"tenant_id":"other"}`, `{"active":true} {"active":false}`} {
		r := httptest.NewRequest("PATCH", "/", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		var v struct {
			Active bool `json:"active"`
		}
		if Decode(httptest.NewRecorder(), r, &v) == nil {
			t.Fatal("接受了未知租户字段或额外文档")
		}
	}
}
func TestLoginDoesNotTreatStorageFailureAsWrongPassword(t *testing.T) {
	a := NewAuth(sessionStub{err: errors.New("存储故障")}, nil, "https://console.example", "session", true)
	r := httptest.NewRequest("POST", "/auth/login", strings.NewReader(`{"username":"admin","password":"long-password"}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	a.Login(w, r)
	if w.Code != 503 || !strings.Contains(w.Body.String(), "auth_unavailable") {
		t.Fatal("依赖故障被解释为错误密码")
	}
}
