package responsescript

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/outbound"
)

const samplePassword = "fixture-password-944"
const sampleAPIKey = "fixture-api-key-127"
const sampleToken = "fixture-session-827"

func privateSecret(t *testing.T, value string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(p, []byte(value), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func fixture(t *testing.T, handler http.HandlerFunc) Config {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	return Config{
		Source: "def health(ctx): return True", Origin: server.URL, Roots: roots,
		Secrets: map[string]Secret{
			"password": {File: privateSecret(t, samplePassword)},
			"api":      {File: privateSecret(t, sampleAPIKey)},
			"signing":  {File: privateSecret(t, strings.Repeat("\xff", 32)), HMAC: true},
		},
		Login: &Login{Path: "/login", Secrets: map[string]string{"password": "password"}, TokenField: "access"},
	}
}

func newRuntime(t *testing.T, cfg Config) *Runtime {
	t.Helper()
	r, err := New(cfg, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.client.CloseIdleConnections)
	return r
}

func evaluate(t *testing.T, r *Runtime, entry, source string, in Invocation) (Code, json.RawMessage, []Event) {
	t.Helper()
	in.Entry = entry
	b := &broker{r: r, in: in, state: r.state}
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	if err := left.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if err := right.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		defer right.Close()
		_ = serve(channel{right, right})
	}()
	code, value := b.exchange(ctx, channel{left, left}, program{source, entry, in.Args, r.cfg.Origin, in.TaskID, "2026-11-25T04:00:00Z"})
	_ = left.Close()
	<-joined
	return code, value, b.events
}

func TestResponseScriptConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Config)
		want   Code
	}{
		{"empty_source", func(c *Config) { c.Source = "" }, Input},
		{"too_many_routes", func(c *Config) { c.Routes = make([]Route, 33) }, Input},
		{"insecure_origin", func(c *Config) { c.Origin = "http://127.0.0.1" }, Scope},
		{"url_credentials", func(c *Config) { c.Origin = "https://user@127.0.0.1" }, Scope},
		{"url_path", func(c *Config) { c.Origin += "/health" }, Scope},
		{"url_query", func(c *Config) { c.Origin += "?" }, Scope},
		{"missing_pin", func(c *Config) { c.Origin = "https://device.example" }, Scope},
		{"different_pin", func(c *Config) { c.DeviceIP = netip.MustParseAddr("127.0.0.2") }, Scope},
		{"missing_ca", func(c *Config) { c.Roots = nil }, Scope},
		{"metadata_ip", func(c *Config) { c.Origin = "https://169.254.169.254" }, Scope},
		{"alias_ip", func(c *Config) { c.Origin = "https://[::ffff:127.0.0.1]" }, Scope},
		{"reserved_ref", func(c *Config) { c.Secrets["token"] = c.Secrets["api"] }, Credential},
		{"public_path", func(c *Config) { c.Secrets["password"] = Secret{File: "relative"} }, Credential},
		{"hmac_length", func(c *Config) { c.Secrets["api"] = Secret{File: c.Secrets["api"].File, HMAC: true} }, Credential},
		{"login_path", func(c *Config) { c.Login.Path = "/a/../other" }, Scope},
		{"login_secret", func(c *Config) { c.Login.Secrets["password"] = "signing" }, Credential},
		{"invalid_entry", func(c *Config) { c.Routes[0].Entry = "anything" }, Scope},
		{"invalid_method", func(c *Config) { c.Routes[0].Method = "TRACE" }, Scope},
		{"read_only", func(c *Config) { c.Routes[0].Method = "POST" }, Scope},
		{"unstable_path", func(c *Config) { c.Routes[0].Path = "/api/route%2Ftest" }, Scope},
		{"path_segments", func(c *Config) { c.Routes[0].Path = "/api/route@name" }, Scope},
		{"invalid_query", func(c *Config) { c.Routes[0].Query = []string{" "} }, Scope},
		{"duplicate", func(c *Config) { c.Routes = append(c.Routes, c.Routes[0]) }, Scope},
		{"host_header", func(c *Config) { c.Routes[0].Headers = map[string]string{"Host": ""} }, Scope},
		{"proxy_header", func(c *Config) { c.Routes[0].Headers = map[string]string{"Proxy-Authorization": "api"} }, Scope},
		{"header_case", func(c *Config) { c.Routes[0].Headers = map[string]string{"x-abc": "api"} }, Scope},
		{"auth_plaintext", func(c *Config) { c.Routes[0].Headers = map[string]string{"Authorization": ""} }, Scope},
		{"missing_header_ref", func(c *Config) { c.Routes[0].Headers = map[string]string{"Authorization": "missing"} }, Credential},
		{"missing_login_ref", func(c *Config) { c.Routes[0].Headers = map[string]string{"Authorization": "token"}; c.Login = nil }, Credential},
		{"unsafe_write_query", func(c *Config) {
			c.Routes[0].Entry = "block"
			c.Routes[0].Method = "PUT"
			c.Routes[0].Query = []string{"q"}
		}, Scope},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := fixture(t, http.NotFound)
			c.Routes = []Route{{Entry: "health", Method: "GET", Path: "/api/health"}}
			tc.change(&c)
			if _, err := New(c, ""); !errors.Is(err, tc.want) {
				t.Fatalf("期望 %s，实际 %v", tc.want, err)
			}
		})
	}
	cfg := fixture(t, http.NotFound)
	if _, err := New(cfg, "relative"); err != Isolation {
		t.Fatal("允许了相对路径工作进程")
	}
	cfg.Login = nil
	cfg.Origin, cfg.DeviceIP = "https://device.example", netip.MustParseAddr("127.0.0.1")
	if r := newRuntime(t, cfg); r.cfg.DeviceIP != cfg.DeviceIP {
		t.Fatal("域名没有绑定精确解析地址")
	}
}

func TestResponseScriptFunctions(t *testing.T) {
	r := newRuntime(t, fixture(t, http.NotFound))
	script := `
def health(ctx, sample):
    state.set("identifier", sample, ttl = 1)
    state.set("credential", secret.get("api"))
    log.info("开始检查")
    log.warn("设备返回空列表")
    signed = hash.hmac_sha256(secret.get("signing"), base64.decode("/w=="))
    return {
      "state": state.get("identifier"), "empty": state.get("missing"),
      "json": json.decode(json.encode({"value": True})),
      "base64": base64.encode(base64.decode("/w==")),
      "hash": hash.sha256("abc"), "signed": signed,
      "now": time.now(), "task": ctx.task_id,
    }
`
	in := Invocation{TaskID: "task-a", Args: []json.RawMessage{json.RawMessage("123")}}
	code, data, events := evaluate(t, r, "health", script, in)
	if code != OK || len(events) != 2 || events[1].Level != "warn" {
		t.Fatalf("执行平台函数失败 %s", code)
	}
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil || len(got) != 8 || got["state"] != float64(123) || got["empty"] != nil || got["base64"] != "/w==" ||
		got["hash"] != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" ||
		got["signed"] != "c64e95590356aa985ba29b462f7f2e8783426198cdbcf1fe2be57b25244db50a" ||
		got["now"] != "2026-11-25T04:00:00Z" || got["task"] != "task-a" {
		t.Fatalf("平台函数结果不符 %s", data)
	}
	r.now = func() time.Time { return time.Now().Add(3 * time.Second) }
	code, data, _ = evaluate(t, r, "health", `
def health(ctx):
    return state.get("identifier") == None and type(state.get("credential")) == "credential"
`, Invocation{})
	if code != OK || string(data) != "true" {
		t.Fatal("TTL 或凭据引用状态错误")
	}
}

func TestResponseScriptRejections(t *testing.T) {
	r := newRuntime(t, fixture(t, http.NotFound))
	for _, tc := range []struct {
		name, body string
		want       Code
	}{
		{"missing_entry", "def other(ctx): return True", ScriptError},
		{"invalid_source", "def health(ctx) return True", ScriptError},
		{"load", "load(\"local.star\", \"name\")\ndef health(ctx): return name", Scope},
		{"startup_http", "data = http.get(\"/health\")\ndef health(ctx): return data", Scope},
		{"result_ref", "def health(ctx): return secret.get(\"api\")", Credential},
		{"string_ref", "def health(ctx): return str(secret.get(\"api\"))", Credential},
		{"print_ref", "def health(ctx): print(secret.get(\"api\"))", Credential},
		{"dict_ref", "def health(ctx): return {secret.get(\"api\"): 1}", Credential},
		{"json_ref", "def health(ctx): return json.encode([secret.get(\"api\")])", Credential},
		{"lookup_missing", "def health(ctx): return secret.get(\"missing\")", Credential},
		{"log_ref", "def health(ctx): log.info(secret.get(\"api\"))", Credential},
		{"direct_log", "def health(ctx): log.info(\"" + sampleAPIKey + "\")", Credential},
		{"direct_result", "def health(ctx): return {\"message\": \"" + sampleAPIKey + "\"}", Credential},
		{"log_format", "def health(ctx): log.info(1)", Input},
		{"log_line", "def health(ctx): log.warn(\"a\\nb\")", Input},
		{"fail", "def health(ctx): fail(\"检查失败\")", ScriptError},
		{"log_fail", "def health(ctx): log.fail(\"检查失败\")", ScriptError},
		{"print", "def health(ctx): print(\"未登记日志\")", ScriptError},
		{"base64", "def health(ctx): return base64.decode(\"###\")", Input},
		{"hash_ref", "def health(ctx): return hash.sha256(secret.get(\"api\"))", Credential},
		{"hash_data", "def health(ctx): return hash.sha256(123)", Input},
		{"hash_size", "def health(ctx): return hash.sha256(\"a\"*17000)", Size},
		{"hmac_literal", "def health(ctx): return hash.hmac_sha256(\"key\", \"data\")", Credential},
		{"hmac_password", "def health(ctx): return hash.hmac_sha256(secret.get(\"api\"), \"data\")", Credential},
		{"state_key", "def health(ctx): return state.get(\".../key\")", Input},
		{"state_ttl", "def health(ctx): return state.set(\"item\", True, ttl = 0)", Input},
		{"state_full", "def health(ctx):\n    for i in range(33): state.set(str(i), 1)", Size},
		{"output_size", "def health(ctx): return \"x\" * 17000", Size},
		{"round_trips", "def health(ctx):\n    for i in range(97): state.get(\"empty\")", Rate},
		{"steps", "def health(ctx):\n    for i in range(1000000): i + 1", Steps},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clear(r.state)
			code, _, _ := evaluate(t, r, "health", tc.body, Invocation{})
			if code != tc.want {
				t.Fatalf("期望 %s，实际 %s", tc.want, code)
			}
		})
	}
}

func TestResponseScriptDeviceBroker(t *testing.T) {
	var writes, logins atomic.Int32
	cfg := fixture(t, func(w http.ResponseWriter, req *http.Request) {
		switch req.Method + " " + req.URL.Path {
		case "POST /login":
			logins.Add(1)
			var body map[string]string
			if err := json.NewDecoder(req.Body).Decode(&body); err != nil || body["password"] != samplePassword {
				t.Error("登录请求没有使用本地秘密")
			}
			fmt.Fprintf(w, `{"access":%q,"ignored":%q}`, sampleToken, samplePassword)
		case "GET /alerts":
			if req.Header.Get("Authorization") != "Bearer "+sampleToken || req.Header.Get("X-Key") != sampleAPIKey || req.Header.Get("X-Trace") != "test" || req.URL.Query().Get("from") != "2" {
				t.Error("代理请求的固定参数或认证错误")
			}
			fmt.Fprintf(w, `{"items":[1,2],"debug":%q}`, samplePassword)
		case "GET /redirect":
			http.Redirect(w, req, "/unknown", http.StatusFound)
		case "GET /invalid":
			fmt.Fprint(w, "not JSON")
		case "GET /empty":
			w.WriteHeader(http.StatusNoContent)
		case "GET /list":
			fmt.Fprint(w, `{"rows":[{"number":1}]}`)
		case "GET /echo":
			fmt.Fprintf(w, `{"field":{"nested":%q}}`, sampleAPIKey)
		case "PUT /rules":
			writes.Add(1)
			var body map[string]string
			if err := json.NewDecoder(req.Body).Decode(&body); err != nil || body["target"] != "192.0.2.21" {
				t.Error("变更请求不匹配授权正文")
			}
			fmt.Fprint(w, `{"id":"rule-1"}`)
		case "DELETE /rules/rule-1":
			writes.Add(1)
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("未登记的设备请求 %s", req.URL.Path)
			http.NotFound(w, req)
		}
	})
	cfg.Routes = []Route{
		{Entry: "pull_alerts", Method: "GET", Path: "/alerts", Query: []string{"from"}, Fields: []string{"items", "absent"}, Headers: map[string]string{"Authorization": "token", "X-Key": "api", "X-Trace": ""}},
		{Entry: "block", Method: "PUT", Path: "/rules", Fields: []string{"id"}},
		{Entry: "unblock", Method: "DELETE", Path: "/rules/{rule_id}"},
		{Entry: "health", Method: "GET", Path: "/"},
	}
	for _, path := range []string{"redirect", "invalid", "empty", "list", "echo"} {
		cfg.Routes = append(cfg.Routes, Route{Entry: "health", Method: "GET", Path: "/" + path, Fields: []string{"field", "rows"}})
	}
	r := newRuntime(t, cfg)
	cfg.Routes[0].Headers["X-Key"] = ""
	cfg.Routes[0].Query[0] = "wrong"
	cfg.Routes[0].Fields[0] = "debug"
	cfg.Login.Secrets["password"] = "api"
	login := `    login = http.post("/login", json = {"password": secret.get("password")})
    token = login.json()["access"]
`
	code, data, events := evaluate(t, r, "pull_alerts", "def pull_alerts(ctx):\n"+login+
		`    return http.get(ctx.base_url + "/alerts", params={"from": 2}, headers={"Authorization":token, "X-Key":secret.get("api"), "X-Trace":"test"}).json()
`, Invocation{})
	if code != OK || string(data) != `{"items":[1,2]}` || len(events) != 2 || logins.Load() != 1 {
		t.Fatalf("设备读取结果错误 %s %s", code, data)
	}
	write := `return http.put("/rules", json={"target":"192.0.2.21"}).json()["id"]`
	grant := &ApprovedWrite{Method: "PUT", Path: "/rules", Body: json.RawMessage(`{"target":"192.0.2.21"}`)}
	for _, tc := range []struct {
		name, entry, line string
		in                Invocation
		want              Code
	}{
		{"same_origin", "health", `return http.get("https://127.0.0.2/invalid").status`, Invocation{}, Scope},
		{"noncanonical_path", "health", `return http.get("/a/../invalid").status`, Invocation{}, Scope},
		{"cross_entry", "health", `return http.get("/alerts").status`, Invocation{}, Scope},
		{"wrong_query", "pull_alerts", `return http.get("/alerts", params={"to":1}).status`, Invocation{}, Scope},
		{"wrong_query_value", "pull_alerts", `return http.get("/alerts", params={"from":[]}).status`, Invocation{}, Input},
		{"secret_query", "pull_alerts", `return http.get("/alerts", params={"from":secret.get("api")}).status`, Invocation{}, Credential},
		{"plain_secret_query", "pull_alerts", `return http.get("/alerts", params={"from":"` + sampleAPIKey + `"}).status`, Invocation{}, Credential},
		{"unregistered_header", "pull_alerts", `return http.get("/alerts", headers={"X-Other":"a"}).status`, Invocation{}, Scope},
		{"wrong_header_ref", "pull_alerts", `return http.get("/alerts", headers={"X-Key":secret.get("password")}).status`, Invocation{}, Credential},
		{"ordinary_header", "pull_alerts", `return http.get("/alerts", headers={"X-Trace":7}).status`, Invocation{}, Credential},
		{"ordinary_header_control", "pull_alerts", `return http.get("/alerts", headers={"X-Trace":"a\nb"}).status`, Invocation{}, Input},
		{"missing_credential", "pull_alerts", `return http.get("/alerts").status`, Invocation{}, Credential},
		{"read_body", "health", `return http.get("/",json={"text":"value"}).status`, Invocation{}, Scope},
		{"wrong_login", "health", `return http.post("/login", json={"password":secret.get("api")}).status`, Invocation{}, Credential},
		{"login_plaintext", "health", `return http.post("/login", json={"password":"literal"}).status`, Invocation{}, Scope},
		{"redirect", "health", `return http.get("/redirect").status`, Invocation{}, Scope},
		{"invalid_json", "health", `return http.get("/invalid").json()`, Invocation{}, DeviceError},
		{"empty", "health", `return http.get("/empty").json()`, Invocation{}, OK},
		{"list", "health", `return http.get("/list").json()`, Invocation{}, OK},
		{"echo", "health", `return http.get("/echo").json()`, Invocation{}, Credential},
		{"write_without_grant", "block", write, Invocation{}, Scope},
		{"write_body_frozen", "block", `return http.put("/rules", json={"target":"192.0.2.22"}).status`, Invocation{Write: grant}, Scope},
		{"write_secret_body", "block", `return http.put("/rules", json={"target":secret.get("api")}).status`, Invocation{Write: grant}, Credential},
		{"write_once", "block", `http.put("/rules", json={"target":"192.0.2.21"})` + "\n    " + write, Invocation{Write: grant}, Scope},
		{"write_match", "block", write, Invocation{Write: grant}, OK},
		{"delete_protect_rule", "unblock", `return http.delete("/rules/other").status`, Invocation{RuleID: "rule-1"}, Scope},
		{"delete_match", "unblock", `return http.delete("/rules/rule-1").status`, Invocation{RuleID: "rule-1", Write: &ApprovedWrite{Method: "DELETE", Path: "/rules/rule-1"}}, OK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clear(r.state)
			r.requests = nil
			code, _, _ := evaluate(t, r, tc.entry, "def "+tc.entry+"(ctx):\n    "+tc.line, tc.in)
			if code != tc.want {
				t.Fatalf("预期 %s，实际 %s", tc.want, code)
			}
		})
	}
	if writes.Load() != 3 {
		t.Fatalf("设备实际收到 %d 次变更", writes.Load())
	}
}

func TestResponseScriptRunGuards(t *testing.T) {
	r := newRuntime(t, fixture(t, http.NotFound))
	tests := []struct {
		in   Invocation
		want Code
	}{
		{Invocation{Entry: "other"}, Input},
		{Invocation{Entry: "health", TaskID: "a/b"}, Input},
		{Invocation{Entry: "health", RuleID: "a/b"}, Input},
		{Invocation{Entry: "health", Args: make([]json.RawMessage, 5)}, Input},
		{Invocation{Entry: "health", Args: []json.RawMessage{json.RawMessage("invalid")}}, Input},
		{Invocation{Entry: "health", Args: []json.RawMessage{json.RawMessage(strings.Repeat("0", maxData+1))}}, Size},
		{Invocation{Entry: "health", Write: &ApprovedWrite{Method: "PUT", Path: "/rules"}}, Scope},
		{Invocation{Entry: "block", Write: &ApprovedWrite{Method: "GET", Path: "/rules"}}, Scope},
		{Invocation{Entry: "block", Write: &ApprovedWrite{Method: "PUT", Path: "/rules", Body: json.RawMessage(`"` + sampleAPIKey + `"`)}}, Credential},
		{Invocation{Entry: "health", Args: []json.RawMessage{json.RawMessage(strings.Repeat("[", 40) + "0" + strings.Repeat("]", 40))}}, Size},
	}
	for _, tc := range tests {
		if got := r.Run(t.Context(), tc.in); got.Code != tc.want || len(got.Events) != 1 || got.Events[0].Code != tc.want {
			t.Fatalf("预检期望 %s，实际 %s", tc.want, got.Code)
		}
	}
	for range cap(workerSlots) {
		workerSlots <- struct{}{}
		defer func() { <-workerSlots }()
	}
	if got := r.Run(t.Context(), Invocation{Entry: "health"}); got.Code != Concurrency {
		t.Fatal("超过采集器工作进程上限后仍可执行")
	}
}

func TestResponseScriptRequestBudgets(t *testing.T) {
	var seen atomic.Int32
	cfg := fixture(t, func(w http.ResponseWriter, req *http.Request) {
		seen.Add(1)
		w.WriteHeader(http.StatusNoContent)
	})
	cfg.Routes = []Route{{Entry: "health", Method: "GET", Path: "/state"}}
	r := newRuntime(t, cfg)
	now := time.Now()
	r.now = func() time.Time { return now }
	script := `
def health(ctx):
    for i in range(9):
        http.get(ctx.base_url + "/state")
    return True
`
	for _, expected := range []int32{8, 16, 24, 30, 30} {
		code, _, events := evaluate(t, r, "health", script, Invocation{})
		if code != Rate || seen.Load() != expected || len(events) == 0 || events[len(events)-1].Code != Rate {
			t.Fatalf("设备限流期望累计 %d 次，实际 %d 次，结果 %s", expected, seen.Load(), code)
		}
	}
	now = now.Add(time.Minute)
	one := "def health(ctx): return http.get(\"/state\").status"
	if code, result, _ := evaluate(t, r, "health", one, Invocation{}); code != OK || string(result) != "204" || seen.Load() != 31 {
		t.Fatal("满一分钟后没有恢复设备请求额度")
	}
}

func TestResponseScriptExpiredToken(t *testing.T) {
	cfg := fixture(t, func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/login":
			fmt.Fprintf(w, `{"access":%q}`, sampleToken)
		case "/echo":
			fmt.Fprintf(w, `{"echo":%q}`, sampleToken)
		case "/bad-login":
			w.WriteHeader(http.StatusUnauthorized)
		default:
			http.NotFound(w, req)
		}
	})
	cfg.Routes = []Route{{Entry: "health", Method: "GET", Path: "/echo", Fields: []string{"echo"}}}
	r := newRuntime(t, cfg)
	now := time.Now()
	r.now = func() time.Time { return now }
	script := `
def health(ctx):
    response = http.post("/login", json={"password":secret.get("password")})
    token = response.json()["access"]
    if token:
        state.set("session", token, ttl=3600)
    return response.status
`
	if code, result, _ := evaluate(t, r, "health", script, Invocation{}); code != OK || string(result) != "200" {
		t.Fatal("令牌不能存入受保护的键值状态")
	}
	if code, _, _ := evaluate(t, r, "health", "def health(ctx): return http.get(\"/echo\").json()", Invocation{}); code != Credential {
		t.Fatal("设备回显令牌可返回到脚本")
	}
	now = now.Add(tokenTTL)
	if code, result, _ := evaluate(t, r, "health", "def health(ctx): return state.get(\"session\")", Invocation{}); code != OK || string(result) != "null" {
		t.Fatal("失效的设备令牌仍能从状态读取")
	}
	r.cfg.Login.Path = "/bad-login"
	if code, result, _ := evaluate(t, r, "health", strings.ReplaceAll(script, "/login", "/bad-login"), Invocation{}); code != ScriptError || len(result) != 0 {
		t.Fatal("失败的登录响应提供了凭据字段")
	}
}

func TestResponseScriptUntrustedIPC(t *testing.T) {
	r := newRuntime(t, fixture(t, http.NotFound))
	b := &broker{r: r}
	for _, tc := range []struct {
		name string
		code Code
		then frame
	}{
		{"unsupported_rpc", Isolation, frame{Kind: "unknown"}},
		{"forged_reference", Credential, frame{Kind: "result", Code: OK, Value: wireValue{Ref: "api"}}},
		{"missing_result", Input, frame{Kind: "result", Code: OK}},
		{"invalid_code", Isolation, frame{Kind: "result", Code: "arbitrary"}},
		{"oversize_hmac", Size, frame{Kind: "hmac", Value: wireValue{Ref: "signing"}, Bytes: make([]byte, maxData+1)}},
		{"invalid_state", Credential, frame{Kind: "set", Name: "key", TTL: 30, Value: wireValue{Ref: "undefined"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var script bytes.Buffer
			worker := channel{write: &script}
			for _, v := range []frame{{Kind: "ready"}, tc.then} {
				if err := worker.send(v); err != nil {
					t.Fatal(err)
				}
			}
			if code, _ := b.exchange(t.Context(), channel{&script, io.Discard}, program{}); code != tc.code {
				t.Fatalf("IPC 期望 %s，实际 %s", tc.code, code)
			}
		})
	}
	for _, message := range [][]byte{{0}, {0, 0, 0, 0}, {0, 4, 0, 1}, {0, 0, 0, 3, 1}, {0, 0, 0, 1, 1}} {
		if _, err := (channel{read: bytes.NewReader(message)}).receive(); err == nil {
			t.Fatal("IPC 接受了无效帧")
		}
	}
	if err := (channel{write: io.Discard}).send(frame{Text: strings.Repeat("a", maxFrame+1)}); err != Size {
		t.Fatal("IPC 接受了超限帧")
	}
	if err := (channel{write: io.Discard}).send(frame{Value: wireValue{JSON: json.RawMessage("bad")}}); err != Isolation {
		t.Fatal("IPC 发送了无效结果")
	}
	if err := serve(channel{read: bytes.NewReader(nil), write: io.Discard}); err != Isolation {
		t.Fatal("工作进程接受了缺失的启动指令")
	}
	if got := WorkerMain(); got != 1 {
		t.Fatal("工作进程接受了未隔离的命令入口")
	}
}

func TestResponseScriptDeviceFailureCodes(t *testing.T) {
	r := newRuntime(t, fixture(t, http.NotFound))
	r.client.Transport = failingTransport{outbound.ErrTarget}
	b := &broker{r: r, in: Invocation{Entry: "health"}}
	r.cfg.Routes = []Route{{Entry: "health", Method: "GET", Path: "/health"}}
	request := frame{Kind: "http", Method: "GET", URL: "/health"}
	if code := b.device(t.Context(), request).Code; code != Scope {
		t.Fatalf("解析越界被分类为 %s", code)
	}
	r.client.Transport = failingTransport{io.ErrUnexpectedEOF}
	if code := b.device(t.Context(), request).Code; code != DeviceError {
		t.Fatalf("设备失败被分类为 %s", code)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if code := b.device(ctx, request).Code; code != Timeout {
		t.Fatalf("设备超时被分类为 %s", code)
	}
}

type failingTransport struct{ err error }

func (f failingTransport) RoundTrip(*http.Request) (*http.Response, error) { return nil, f.err }
