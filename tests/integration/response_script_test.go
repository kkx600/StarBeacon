//go:build integration

package integration

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/responsescript"
)

func TestResponseScriptIsolation(t *testing.T) {
	binary := filepath.Join(filepath.Dir(os.Getenv("SB_TEST_MANAGEMENT_BINARY")), "starbeacon-agent")
	if !filepath.IsAbs(binary) {
		t.Fatal("隔离验收缺少本轮构建的采集器程序")
	}
	direct := exec.Command(binary, responsescript.WorkerCommand)
	if err := direct.Run(); err == nil {
		t.Fatal("宿主命令直接接受了解释器入口")
	}
	const password = "fixture-private-password"
	const token = "fixture-private-token"
	var logins, reads atomic.Int32
	waiting := make(chan struct{}, 1)
	device := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.Method + " " + req.URL.Path {
		case "POST /login":
			logins.Add(1)
			var form map[string]string
			if json.NewDecoder(req.Body).Decode(&form) != nil || form["pass"] != password {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			fmt.Fprintf(w, `{"token":%q,"ignored":%q}`, token, password)
		case "GET /health":
			reads.Add(1)
			if req.Header.Get("X-Auth-Token") != token {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			fmt.Fprintf(w, `{"healthy":true,"ignored":%q}`, token)
		case "GET /large":
			fmt.Fprint(w, strings.Repeat("a", 32*1024))
		case "GET /echo":
			fmt.Fprintf(w, `{"message":%q}`, password)
		case "GET /delayed":
			waiting <- struct{}{}
			<-req.Context().Done()
		default:
			t.Error("设备收到了未登记的请求")
			http.NotFound(w, req)
		}
	}))
	defer device.Close()
	roots := x509.NewCertPool()
	roots.AddCert(device.Certificate())
	secret := filepath.Join(t.TempDir(), "password")
	if err := os.WriteFile(secret, []byte(password), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := responsescript.Config{
		Source: `
def health(ctx, check):
    if check == "steps":
        total = 0
        for i in range(300000):
            total += i
        return total
    if check == "scope":
        return http.get(ctx.base_url + "/outside").status
    if check == "secret":
        return "%s" % secret.get("password")
    if check == "failed_state":
        state.set("cursor", "unsaved")
        fail("本次检查中止")
    if check == "read_state":
        return state.get("cursor") == None
    if check == "large" or check == "echo" or check == "delayed":
        return http.get(ctx.base_url + "/" + check).status
    token = state.get("device_token")
    if token == None:
        login = http.post(ctx.base_url + "/login", json = {"pass": secret.get("password")})
        token = login.json()["token"]
        state.set("device_token", token, ttl = 60)
    result = http.get(ctx.base_url + "/health", headers = {"X-Auth-Token": token})
    log.info("设备健康检查")
    return result.json()["healthy"]
`,
		Origin: device.URL, Roots: roots, Secrets: map[string]responsescript.Secret{"password": {File: secret}},
		Login: &responsescript.Login{Path: "/login", Secrets: map[string]string{"pass": "password"}, TokenField: "token"},
		Routes: []responsescript.Route{
			{Entry: "health", Method: "GET", Path: "/health", Headers: map[string]string{"X-Auth-Token": "token"}, Fields: []string{"healthy"}},
			{Entry: "health", Method: "GET", Path: "/large"},
			{Entry: "health", Method: "GET", Path: "/echo", Fields: []string{"message"}},
			{Entry: "health", Method: "GET", Path: "/delayed"},
		},
	}
	runtime, err := responsescript.New(cfg, binary)
	if err != nil {
		t.Fatal(err)
	}
	run := func(check string) responsescript.Result {
		raw, _ := json.Marshal(check)
		return runtime.Run(t.Context(), responsescript.Invocation{Entry: "health", Args: []json.RawMessage{raw}})
	}
	for _, tc := range []struct {
		mode string
		code responsescript.Code
	}{{"ok", responsescript.OK}, {"ok", responsescript.OK}, {"scope", responsescript.Scope}, {"steps", responsescript.Steps}, {"large", responsescript.Size}, {"secret", responsescript.Credential}, {"echo", responsescript.Credential}, {"failed_state", responsescript.ScriptError}} {
		result := run(tc.mode)
		if result.Code != tc.code || len(result.Events) == 0 || tc.code == responsescript.OK && string(result.Value) != "true" {
			t.Fatalf("%s 的结果为 %s，预期 %s", tc.mode, result.Code, tc.code)
		}
		raw, err := json.Marshal(result)
		if err != nil || strings.Contains(string(raw), password) || strings.Contains(string(raw), token) {
			t.Fatal("执行记录泄漏了设备凭据")
		}
	}
	if result := run("read_state"); result.Code != responsescript.OK || string(result.Value) != "true" {
		t.Fatal("失败调用提交了游标变更")
	}
	if logins.Load() != 1 || reads.Load() != 2 {
		t.Fatal("登录令牌缓存或设备请求计数不符")
	}
	finished := make(chan responsescript.Result, 1)
	go func() { finished <- run("delayed") }()
	select {
	case <-waiting:
	case <-time.After(6 * time.Second):
		t.Fatal("真实设备超时夹具未收到请求")
	}
	if result := run("ok"); result.Code != responsescript.Concurrency {
		t.Fatal("同一插件允许并发执行")
	}
	if result := <-finished; result.Code != responsescript.Timeout || len(result.Events) == 0 {
		t.Fatalf("超时结果为 %s", result.Code)
	}
	if result := run("ok"); result.Code != responsescript.OK {
		t.Fatalf("超时后未回收工作进程名额：%s", result.Code)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if result := runtime.Run(ctx, responsescript.Invocation{Entry: "health"}); result.Code != responsescript.Timeout {
		t.Fatalf("取消结果为 %s", result.Code)
	}
}
