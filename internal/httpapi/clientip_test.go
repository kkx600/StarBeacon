package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kkx600/StarBeacon/internal/clientip"
	"github.com/kkx600/StarBeacon/internal/model"
)

func TestProxyClientAddressSharedByAuditAndLoginLimit(t *testing.T) {
	policy, err := clientip.Parse("127.0.0.1/32")
	if err != nil {
		t.Fatal(err)
	}
	auth := NewAuth(sessionStub{}, nil, "https://console.example", "session", true)
	handler := MiddlewareWithClientIP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if model.RequestMetadataFrom(r.Context()).SourceIP != r.Header.Get("X-Real-IP") {
			t.Fatal("审计与可信客户端不一致")
		}
		auth.Login(w, r)
	}), policy)
	request := func(ip string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/auth/login", strings.NewReader(`{"unknown":true}`))
		r.RemoteAddr = "127.0.0.1:1234"
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Real-IP", ip)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	for range 10 {
		if w := request("198.51.100.20"); w.Code != 400 {
			t.Fatal("可信客户端提前用尽预算", w.Code)
		}
	}
	if w := request("198.51.100.20"); w.Code != 429 || w.Header().Get("Retry-After") != "60" {
		t.Fatal("同一客户端未限流")
	}
	if w := request("198.51.100.21"); w.Code != 400 {
		t.Fatal("不同客户端被共享代理预算阻断")
	}
	if len(auth.attempts) != 2 {
		t.Fatal("客户端预算范围错误")
	}
	// 未授权对端不能通过轮换头绕开同一来源限制。
	for i := range 12 {
		r := httptest.NewRequest("POST", "/auth/login", strings.NewReader(`{"unknown":true}`))
		r.RemoteAddr = "203.0.113.20:1234"
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Real-IP", "198.51.100.22")
		r.Header.Set("X-Forwarded-For", "198.51.100.23")
		w := httptest.NewRecorder()
		MiddlewareWithClientIP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if model.RequestMetadataFrom(r.Context()).SourceIP != "203.0.113.20" {
				t.Fatal("伪造头写入审计来源")
			}
			auth.Login(w, r)
		}), policy).ServeHTTP(w, r)
		if want := 400; i >= 10 && w.Code != 429 || i < 10 && w.Code != want {
			t.Fatal("未授权对端的限流不正确", i, w.Code)
		}
	}
}
