package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/kkx600/StarBeacon/internal/model"
	"golang.org/x/crypto/bcrypt"
)

type failingSessions struct {
	hash                     string
	createError, deleteError error
}

func (s failingSessions) Password(context.Context, string) (model.Principal, string, error) {
	return model.Principal{ID: "user_owned", TenantID: "tenant_owned", Username: "admin", Role: "admin"}, s.hash, nil
}
func (s failingSessions) CreateSession(context.Context, model.Principal) (string, string, error) {
	return "", "", s.createError
}
func (s failingSessions) Session(context.Context, string) (model.Principal, error) {
	return model.Principal{}, nil
}
func (s failingSessions) DeleteSession(context.Context, string) error           { return s.deleteError }
func (failingSessions) LoginAudit(context.Context, model.Principal, bool) error { return nil }

func TestLoginRateCapacityInvalidInputAndSessionFailure(t *testing.T) {
	for _, input := range []struct {
		body, content, origin string
		want                  int
	}{
		{`{"username":"admin","password":"owned-password"}`, "application/json", "https://other.example", 403},
		{`{"unknown":true}`, "application/json", "https://console.example", 400},
		{`{"username":"` + strings.Repeat("a", 65) + `","password":"owned-password"}`, "application/json", "https://console.example", 400},
		{`{"username":"admin","password":"` + strings.Repeat("a", 73) + `"}`, "application/json", "https://console.example", 400},
		{`{}`, "text/plain", "https://console.example", 400},
	} {
		a := NewAuth(sessionStub{}, nil, "https://console.example", "session", true)
		r := httptest.NewRequest("POST", "/auth/login", strings.NewReader(input.body))
		r.Header.Set("Content-Type", input.content)
		r.Header.Set("Origin", input.origin)
		w := httptest.NewRecorder()
		a.Login(w, r)
		if w.Code != input.want || len(w.Result().Cookies()) != 0 {
			t.Fatal("非法登录设置了会话或返回错误状态", w.Code)
		}
	}
	a := NewAuth(sessionStub{}, nil, "https://console.example", "session", true)
	r := httptest.NewRequest("POST", "/auth/login", strings.NewReader(`{}`))
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = "owned-peer"
	for range 10 {
		ok, err := a.allowLogin(r)
		if !ok || err != nil {
			t.Fatal("登录限流过早拒绝", err)
		}
	}
	w := httptest.NewRecorder()
	a.Login(w, r)
	if w.Code != 429 || w.Header().Get("Retry-After") != "60" {
		t.Fatal("登录窗口没有正确限流", w.Code)
	}
	for key, item := range a.attempts {
		item.Start = time.Now().Add(-2 * time.Minute)
		a.attempts[key] = item
	}
	if ok, err := a.allowLogin(r); !ok || err != nil || len(a.attempts) != 1 {
		t.Fatal("过期窗口未清理", err)
	}
	for i := range 1025 {
		a.attempts[fmt.Sprint(i)] = attempt{Start: time.Now(), Count: 1}
	}
	if ok, err := a.allowLogin(r); ok || err != nil {
		t.Fatal("本地限流容量没有受限", err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("owned-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	a = NewAuth(failingSessions{hash: string(hash), createError: errors.New("storage unavailable")}, nil, "https://console.example", "session", true)
	r = httptest.NewRequest("POST", "/auth/login", strings.NewReader(`{"username":"admin","password":"owned-password"}`))
	r.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	a.Login(w, r)
	if w.Code != 503 || len(w.Result().Cookies()) != 0 {
		t.Fatal("会话保存失败仍颁发了 cookie")
	}
	a.Store = failingSessions{hash: string(hash), createError: model.ErrUnauthenticated}
	r = httptest.NewRequest("POST", "/auth/login", strings.NewReader(`{"username":"admin","password":"owned-password"}`))
	r.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	a.Login(w, r)
	if w.Code != 401 || !strings.Contains(w.Body.String(), "credentials_changed") || len(w.Result().Cookies()) != 0 {
		t.Fatal("过期身份验证未要求重新登录")
	}
	a.Store = failingSessions{deleteError: errors.New("storage unavailable")}
	for _, cookie := range []bool{false, true} {
		r = httptest.NewRequest("POST", "/auth/logout", nil)
		if cookie {
			r.AddCookie(&http.Cookie{Name: "session", Value: strings.Repeat("a", 64)})
		}
		w = httptest.NewRecorder()
		a.Logout(w, r)
		if w.Code != 503 || len(w.Result().Cookies()) != 0 {
			t.Fatal("退出失败清除了可重试的 cookie")
		}
	}
}

func TestMiddlewareBoundsUTF8MetadataAndContainsPanic(t *testing.T) {
	r := httptest.NewRequest("GET", "/owned", nil)
	r.RemoteAddr = "invalid-peer:1234"
	r.Header.Set("User-Agent", strings.Repeat("名", 171))
	w := httptest.NewRecorder()
	Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		meta := model.RequestMetadataFrom(r.Context())
		if meta.SourceIP != "" || len(meta.UserAgent) > 512 || !utf8.ValidString(meta.UserAgent) {
			t.Fatal("请求元数据未受约束", meta)
		}
		w.WriteHeader(204)
	})).ServeHTTP(w, r)
	if w.Code != 204 || w.Header().Get("X-Request-ID") == "" {
		t.Fatal("请求关联标识缺失")
	}
	w = httptest.NewRecorder()
	Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("private internal error") })).ServeHTTP(w, r)
	if w.Code != 500 || strings.Contains(w.Body.String(), "private internal") || !strings.Contains(w.Body.String(), "internal_error") {
		t.Fatal("异常泄露内部信息", w.Body.String())
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if Serve(ctx, listener.Addr().String(), http.NotFoundHandler(), "", "") == nil {
		t.Fatal("HTTP 监听冲突未返回错误")
	}
	if Serve(ctx, "127.0.0.1:0", http.NotFoundHandler(), "missing.crt", "missing.key") == nil {
		t.Fatal("TLS 证书缺失未返回错误")
	}
}
