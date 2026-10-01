// Package httpapi 统一请求身份、错误语义、会话和浏览器写操作保护。
package httpapi

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/telemetry"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"
)

type ctxKey int

const principalKey ctxKey = 0
const requestKey ctxKey = 1

type SessionStore interface {
	Password(context.Context, string) (model.Principal, string, error)
	CreateSession(context.Context, model.Principal) (string, string, error)
	Session(context.Context, string) (model.Principal, error)
	DeleteSession(context.Context, string) error
	LoginAudit(context.Context, model.Principal, bool) error
}
type Auth struct {
	Store              SessionStore
	Redis              *redis.Client
	Origin, CookieName string
	Secure             bool
	dummy              []byte
	mu                 sync.Mutex
	attempts           map[string]attempt
}
type attempt struct {
	Start time.Time
	Count int
}

func NewAuth(s SessionStore, r *redis.Client, origin, cookie string, secure bool) *Auth {
	dummy, _ := bcrypt.GenerateFromPassword([]byte(store.Token()), bcrypt.DefaultCost)
	return &Auth{Store: s, Redis: r, Origin: origin, CookieName: cookie, Secure: secure, dummy: dummy, attempts: map[string]attempt{}}
}
func Principal(r *http.Request) model.Principal {
	u, _ := r.Context().Value(principalKey).(model.Principal)
	return u
}
func RequestID(r *http.Request) string { id, _ := r.Context().Value(requestKey).(string); return id }
func JSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func Fail(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	JSON(w, status, map[string]any{"code": code, "message": message, "request_id": RequestID(r)})
}
func Decode(w http.ResponseWriter, r *http.Request, target any) error {
	media, _, e := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if e != nil || media != "application/json" {
		return fmt.Errorf("请求必须使用 application/json")
	}
	r.Body = http.MaxBytesReader(w, r.Body, 2*1024*1024)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if e = d.Decode(target); e != nil {
		return fmt.Errorf("请求内容无效")
	}
	if e = d.Decode(new(any)); e != io.EOF {
		return fmt.Errorf("请求包含额外内容")
	}
	return nil
}
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := store.RandomID("req_")
		w.Header().Set("X-Request-ID", id)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "same-origin")
		peer, _, _ := net.SplitHostPort(r.RemoteAddr)
		if net.ParseIP(peer) == nil {
			peer = ""
		}
		ua := strings.ToValidUTF8(r.UserAgent(), "�")
		if len(ua) > 512 {
			ua = ua[:512]
			for !utf8.ValidString(ua) {
				ua = ua[:len(ua)-1]
			}
		}
		meta := model.RequestMetadata{SourceIP: peer, UserAgent: ua, RequestID: id}
		r = r.WithContext(model.WithRequestMetadata(context.WithValue(r.Context(), requestKey, id), meta))
		defer func() {
			if v := recover(); v != nil {
				slog.Error("HTTP 请求异常", "request_id", id)
				Fail(w, r, 500, "internal_error", "服务暂时不可用")
			}
		}()
		next.ServeHTTP(w, r)
	})
}
func (a *Auth) origin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	return (origin == "" || origin == a.Origin) && r.Header.Get("Sec-Fetch-Site") != "cross-site"
}
func (a *Auth) Require(admin bool, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, e := r.Cookie(a.CookieName)
		if e != nil || len(c.Value) != 64 {
			Fail(w, r, 401, "unauthenticated", "请先登录")
			return
		}
		u, e := a.Store.Session(r.Context(), c.Value)
		if e != nil {
			if !errors.Is(e, model.ErrUnauthenticated) {
				Fail(w, r, 503, "auth_unavailable", "认证服务暂时不可用")
				return
			}
			Fail(w, r, 401, "session_expired", "会话已失效，请重新登录")
			return
		}
		if admin && u.Role != "admin" {
			Fail(w, r, 403, "forbidden", "当前账号无此操作权限")
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" {
			if u.CSRF == "" || !a.origin(r) || subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(u.CSRF)) != 1 {
				Fail(w, r, 403, "csrf_failed", "请求验证失败，请刷新页面后重试")
				return
			}
		}
		next(w, r.WithContext(context.WithValue(r.Context(), principalKey, u)))
	}
}

const rateScript = `local n=redis.call('INCR',KEYS[1]);if n==1 then redis.call('EXPIRE',KEYS[1],60) end;return n`

func (a *Auth) allowLogin(r *http.Request) (bool, error) {
	ip, _, e := net.SplitHostPort(r.RemoteAddr)
	if e != nil {
		ip = r.RemoteAddr
	}
	key := store.Hash(ip)
	if a.Redis != nil {
		n, e := a.Redis.Eval(r.Context(), rateScript, []string{"sb:login:" + key}).Int()
		return n <= 10, e
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	for k, v := range a.attempts {
		if now.Sub(v.Start) > time.Minute {
			delete(a.attempts, k)
		}
	}
	if len(a.attempts) > 1024 {
		return false, nil
	}
	v := a.attempts[key]
	if now.Sub(v.Start) > time.Minute {
		v = attempt{Start: now}
	}
	v.Count++
	a.attempts[key] = v
	return v.Count <= 10, nil
}
func (a *Auth) Login(w http.ResponseWriter, r *http.Request) {
	if !a.origin(r) {
		Fail(w, r, 403, "origin_rejected", "请求来源不被允许")
		return
	}
	ok, e := a.allowLogin(r)
	if e != nil {
		Fail(w, r, 503, "auth_unavailable", "认证服务暂时不可用")
		return
	}
	if !ok {
		w.Header().Set("Retry-After", "60")
		Fail(w, r, 429, "too_many_attempts", "登录尝试过多，请稍后重试")
		return
	}
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if e = Decode(w, r, &input); e != nil || len(input.Username) > 64 || len(input.Password) > 72 {
		Fail(w, r, 400, "invalid_request", "登录信息格式无效")
		return
	}
	u, hash, lookup := a.Store.Password(r.Context(), input.Username)
	compare := []byte(hash)
	if lookup != nil {
		compare = a.dummy
		u = model.Principal{Username: strings.TrimSpace(input.Username)}
	}
	e = bcrypt.CompareHashAndPassword(compare, []byte(input.Password))
	if lookup != nil && !errors.Is(lookup, model.ErrUnauthenticated) {
		Fail(w, r, 503, "auth_unavailable", "认证服务暂时不可用")
		return
	}
	success := lookup == nil && e == nil
	if e = a.Store.LoginAudit(r.Context(), u, success); e != nil {
		Fail(w, r, 503, "audit_unavailable", "暂时无法记录登录，请稍后重试")
		return
	}
	if !success {
		Fail(w, r, 401, "invalid_credentials", "登录信息无效")
		return
	}
	token, csrf, e := a.Store.CreateSession(r.Context(), u)
	if e != nil {
		Fail(w, r, 503, "auth_unavailable", "认证服务暂时不可用")
		return
	}
	u.CSRF = csrf
	http.SetCookie(w, &http.Cookie{Name: a.CookieName, Value: token, Path: "/", HttpOnly: true, Secure: a.Secure, SameSite: http.SameSiteStrictMode, MaxAge: 8 * 3600})
	JSON(w, 200, u)
}
func (a *Auth) Logout(w http.ResponseWriter, r *http.Request) {
	c, _ := r.Cookie(a.CookieName)
	if c == nil || a.Store.DeleteSession(r.Context(), c.Value) != nil {
		Fail(w, r, 503, "auth_unavailable", "无法结束会话，请重试")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: a.CookieName, Path: "/", HttpOnly: true, Secure: a.Secure, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	JSON(w, 200, map[string]bool{"ok": true})
}
func (a *Auth) Register(mux *http.ServeMux, prefix string) {
	mux.HandleFunc("POST "+prefix+"/auth/login", a.Login)
	mux.HandleFunc("GET "+prefix+"/auth/me", a.Require(false, func(w http.ResponseWriter, r *http.Request) { JSON(w, 200, Principal(r)) }))
	mux.HandleFunc("POST "+prefix+"/auth/logout", a.Require(false, a.Logout))
}
func Health(mux *http.ServeMux, ready func(context.Context) error) {
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { JSON(w, 200, map[string]string{"status": "alive"}) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		if ready(ctx) != nil {
			JSON(w, 503, map[string]string{"status": "unavailable"})
			return
		}
		JSON(w, 200, map[string]string{"status": "ready"})
	})
	mux.Handle("GET /metrics", promhttp.HandlerFor(telemetry.Registry, promhttp.HandlerOpts{}))
}
func Serve(ctx context.Context, addr string, handler http.Handler, tlsCert, tlsKey string) error {
	s := &http.Server{Addr: addr, Handler: Middleware(handler), TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13}, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 * 1024}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = s.Shutdown(shutdown)
		case <-done:
		}
	}()
	var e error
	if tlsCert != "" {
		e = s.ListenAndServeTLS(tlsCert, tlsKey)
	} else {
		e = s.ListenAndServe()
	}
	close(done)
	if errors.Is(e, http.ErrServerClosed) {
		return nil
	}
	return e
}
