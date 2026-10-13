//go:build integration

package integration

import (
	"context"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/admin"
	"github.com/kkx600/StarBeacon/internal/app"
	"github.com/kkx600/StarBeacon/internal/config"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/store"
)

// 平台在同一 race 进程中启动真实队列和轮询，核对可用状态及取消后资源释放。
func TestPlatformRunAnalysisReadinessAndCancellation(t *testing.T) {
	ctx, stop := context.WithTimeout(context.Background(), 45*time.Second)
	defer stop()
	f := newIsolatedDatabase(t, ctx)
	tenant, password := store.RandomID("it_startup_"), store.Token()
	require(t, admin.Bootstrap(ctx, f.Owner, tenant, "平台生命周期验收", tenant, password, "admin"))
	dir := t.TempDir()
	ca := filepath.Join(dir, "pki")
	require(t, admin.DevPKI(ca))
	privatePath, publicPath := filepath.Join(dir, "command.key"), filepath.Join(dir, "command.pub")
	require(t, control.GenerateKeys(privatePath, publicPath))
	addresses := availableAddresses(t, 2)
	c := config.Config{Mode: "development", DatabaseURL: f.RuntimeDSN, ESURL: os.Getenv("SB_ES_URL"), RedisURL: os.Getenv("SB_REDIS_URL"),
		HTTPAddr: addresses[0], GRPCAddr: addresses[1], AllowedOrigin: "http://" + addresses[0], CookieName: "startup_owned_session",
		TLSCA: filepath.Join(ca, "ca.crt"), TLSCert: filepath.Join(ca, "server.crt"), TLSKey: filepath.Join(ca, "server.key"), CommandSigningKey: privatePath,
		CredentialKey: store.Token()}
	run, cancelRun := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- app.Run(run, "platform", c) }()
	finished := false
	defer func() {
		cancelRun()
		if !finished {
			select {
			case err := <-done:
				if err != nil && !errors.Is(err, context.Canceled) {
					t.Error("平台取消后未正常退出", err)
				}
			case <-time.After(12 * time.Second):
				t.Error("平台取消后仍有生命周期任务")
			}
		}
	}()
	client := &http.Client{Timeout: 5 * time.Second}
	eventually(t, ctx, "实际平台 HTTP 已就绪", func() bool {
		select {
		case err := <-done:
			finished = true
			t.Fatal("平台启动提前退出", err)
		default:
		}
		request, err := http.NewRequestWithContext(ctx, "GET", c.AllowedOrigin+"/readyz", nil)
		require(t, err)
		response, err := client.Do(request)
		if err != nil {
			return false
		}
		response.Body.Close()
		return response.StatusCode == 200
	})
	jar, err := cookiejar.New(nil)
	require(t, err)
	client.Jar = jar
	live := &liveHTTP{t: t, ctx: ctx, client: client, origin: c.AllowedOrigin, prefix: "/api/v1"}
	live.login(tenant, password)
	var page struct {
		Items     []any `json:"items"`
		Available bool  `json:"model_execution_available"`
	}
	eventually(t, ctx, "真实分析队列可用", func() bool { live.request("GET", "/analysis/jobs", "", nil, &page, 200); return page.Available })
	if len(page.Items) != 0 {
		t.Fatal("平台读取其他验收数据库的分析记录")
	}
	// 覆盖多个持续轮询周期；不发出模型请求或设备任务。
	timer := time.NewTimer(2100 * time.Millisecond)
	defer timer.Stop()
	select {
	case err := <-done:
		finished = true
		t.Fatal("就绪平台在轮询期间退出", err)
	case <-ctx.Done():
		t.Fatal("生命周期验收超期")
	case <-timer.C:
	}
	live.request("GET", "/analysis/jobs", "", nil, &page, 200)
	if !page.Available {
		t.Fatal("轮询期间分析队列丢失可用状态")
	}
	live.request("POST", "/auth/logout", "", struct{}{}, nil, 200)
	cancelRun()
	select {
	case err := <-done:
		finished = true
		require(t, err)
	case <-time.After(12 * time.Second):
		t.Fatal("平台取消没有关闭 HTTP、控制面与分析队列")
	}
	t.Log("真实数据库、Redis、ES、分析队列、持续轮询与正常关停通过同进程 race 核对")
}
