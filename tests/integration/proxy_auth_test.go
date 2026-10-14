//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/clientip"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/redis/go-redis/v9"
)

func TestTrustedProxyAuthenticationRedisBudgetAndAuditSource(t *testing.T) {
	if os.Getenv("SB_REDIS_URL") == "" {
		t.Skip("需要独立 Redis 依赖")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f, u, _, password := accountFixture(t, ctx)
	options, err := redis.ParseURL(os.Getenv("SB_REDIS_URL"))
	require(t, err)
	cache := redis.NewClient(options)
	defer cache.Close()
	policy, err := clientip.Parse("127.0.0.1/32,::1/128")
	require(t, err)
	// 强制覆盖含前导零的有效地址；限流键和审计使用规范地址，不沿用头部原文。
	nonce := "0" + store.Token()[:3]
	firstInput, secondInput := "2001:db8:"+nonce+"::1", "2001:db8:"+nonce+"::2"
	first, second := netip.MustParseAddr(firstInput).String(), netip.MustParseAddr(secondInput).String()
	keys := []string{"sb:login:" + store.Hash(first), "sb:login:" + store.Hash(second)}
	defer func() {
		clean, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		require(t, cache.Del(clean, keys...).Err())
	}()
	auth := httpapi.NewAuth(f.Runtime, cache, "", "proxy_owned_session", false)
	server := httptest.NewServer(httpapi.MiddlewareWithClientIP(http.HandlerFunc(auth.Login), policy))
	defer server.Close()
	login, err := json.Marshal(map[string]string{"username": u.Username, "password": password})
	require(t, err)
	post := func(ip string, body []byte, want int) {
		t.Helper()
		r, err := http.NewRequestWithContext(ctx, "POST", server.URL, strings.NewReader(string(body)))
		require(t, err)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Real-IP", ip)
		r.Header.Set("X-Forwarded-For", "203.0.113.90")
		r.Header.Set("Forwarded", "for=203.0.113.91")
		response, err := server.Client().Do(r)
		require(t, err)
		defer response.Body.Close()
		if response.StatusCode != want || want == 429 && response.Header.Get("Retry-After") != "60" {
			t.Fatal("可信代理的登录预算不正确", response.StatusCode, want)
		}
		if want == 200 && len(response.Cookies()) != 1 || want != 200 && len(response.Cookies()) != 0 {
			t.Fatal("失败或限流请求创建了会话")
		}
	}
	post(firstInput, login, 200)
	for range 9 {
		post(firstInput, []byte(`{"unknown":true}`), 400)
	}
	post(firstInput, login, 429)
	post(secondInput, login, 200)
	for i, want := range []int64{11, 1} {
		count, err := cache.Get(ctx, keys[i]).Int64()
		require(t, err)
		if count != want {
			t.Fatal("Redis 预算没有按客户端隔离")
		}
		ttl, err := cache.TTL(ctx, keys[i]).Result()
		require(t, err)
		if ttl <= 0 || ttl > time.Minute {
			t.Fatal("登录预算缺少期限")
		}
	}
	var ips []string
	require(t, f.Owner.Pool.QueryRow(ctx, `SELECT array_agg(source_ip ORDER BY id) FROM login_audits WHERE tenant_id=$1`, u.TenantID).Scan(&ips))
	if len(ips) != 2 || ips[0] != first || ips[1] != second {
		t.Fatal("登录审计误记代理或调用方转发链", ips)
	}
}
