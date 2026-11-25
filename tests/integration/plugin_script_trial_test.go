//go:build integration

package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/agent"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/response"
	"github.com/kkx600/StarBeacon/internal/responsescript"
)

const pluginFixtureSource = `
def health(ctx):
    return http.get(ctx.base_url + "/health").json()["healthy"]

def pull_alerts(ctx, cursor):
    return http.get("/alerts", params={"after":cursor}).json()

def block(ctx, target, duration):
    return http.put("/block", json={"lease_id":ctx.task_id, "owner_sha256":ctx.owner_sha256, "expires_at":ctx.expires_at, "target_ip":target["ip"]}).status == 201

def unblock(ctx, target, lease):
    return http.delete("/remove/" + lease["rule_id"]).status == 204

def isolate(ctx, host, duration):
    return http.post("/isolate", json={"lease_id":ctx.task_id, "owner_sha256":ctx.owner_sha256, "expires_at":ctx.expires_at, "host_id":host}).status == 201

def release(ctx, host, lease):
    return http.delete("/remove/" + lease["rule_id"]).status == 204

def verify(ctx, target, lease):
    path = "/terminal/" if target["host_id"] else "/lease/"
    r = http.get(path + lease["lease_id"])
    return r.status == 200 and r.json()["state"] == "active"
`

type pluginFixtureLease struct {
	DeviceID string    `json:"device_id"`
	LeaseID  string    `json:"lease_id"`
	Owner    string    `json:"owner_sha256"`
	Expires  time.Time `json:"expires_at"`
	Observed time.Time `json:"observed_at"`
	IP       string    `json:"target_ip,omitempty"`
	Host     string    `json:"host_id,omitempty"`
	State    string    `json:"state"`
	Rule     string    `json:"rule_id"`
}

func TestPluginStarlarkReservedCapabilityTrials(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	binary := filepath.Join(filepath.Dir(os.Getenv("SB_TEST_MANAGEMENT_BINARY")), "starbeacon-agent")
	if !filepath.IsAbs(binary) {
		t.Fatal("缺少本轮构建的采集器")
	}
	const testIP, testHost = "192.0.2.41", "fixture-terminal"
	deviceInfo := func(observed string) map[string]any {
		return map[string]any{"device_id": "device_script", "version": "script/1", "native_ttl": true, "separate_leases": true,
			"conditional_revoke": true, "max_ttl_seconds": 60, "observed_at": observed, "healthy": true}
	}
	var mu sync.Mutex
	writes, removes, requests := 0, 0, 0
	var loseWriteResponse bool
	state := map[string]pluginFixtureLease{}
	device := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		requests++
		p := req.URL.Path
		w.Header().Set("Content-Type", "application/json")
		switch {
		case req.Method == "GET" && p == "/health":
			_ = json.NewEncoder(w).Encode(deviceInfo(time.Now().UTC().Format(time.RFC3339Nano)))
		case req.Method == "GET" && p == "/alerts" && req.URL.Query().Get("after") == "":
			fmt.Fprint(w, `{"cursor":"first","items":[]}`)
		case req.Method == "GET" && (strings.HasPrefix(p, "/lease/") || strings.HasPrefix(p, "/terminal/")):
			v, ok := state[p]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				fmt.Fprint(w, `{"code":"missing"}`)
				return
			}
			v.Observed = time.Now().UTC()
			_ = json.NewEncoder(w).Encode(v)
		case req.Method == "PUT" && p == "/block" || req.Method == "POST" && p == "/isolate":
			var v pluginFixtureLease
			if json.NewDecoder(req.Body).Decode(&v) != nil || v.LeaseID == "" || len(v.Owner) != 64 ||
				time.Until(v.Expires) > time.Minute || time.Until(v.Expires) < 5*time.Second ||
				p == "/block" && (v.IP != testIP || v.Host != "") || p == "/isolate" && (v.Host != testHost || v.IP != "") {
				t.Error("写入没有限制在本地保留目标、身份和时限")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			prefix := "/lease/"
			if p == "/isolate" {
				prefix = "/terminal/"
			}
			v.DeviceID, v.Rule, v.State = "device_script", fmt.Sprintf("rule_%d", writes), "active"
			state[prefix+v.LeaseID] = v
			writes++
			if loseWriteResponse {
				w.WriteHeader(http.StatusServiceUnavailable)
				fmt.Fprint(w, `{}`)
				return
			}
			w.WriteHeader(http.StatusCreated)
			fmt.Fprint(w, `{}`)
		case req.Method == "DELETE" && strings.HasPrefix(p, "/remove/"):
			for k, v := range state {
				if "/remove/"+v.Rule == p && req.Header.Get("If-Match") == `"`+v.Owner+`"` && v.State == "active" {
					v.State = "revoked"
					state[k] = v
					removes++
					w.WriteHeader(http.StatusNoContent)
					return
				}
			}
			t.Error("解除没有核对原所有者和设备规则")
			w.WriteHeader(http.StatusPreconditionFailed)
		default:
			t.Error("设备征用夹具收到了未登记请求")
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	defer device.Close()
	dir := t.TempDir()
	pub, signer, err := ed25519.GenerateKey(rand.Reader)
	require(t, err)
	wal, err := agent.OpenWAL(filepath.Join(dir, "agent.db"), "tenant_plugin", "sensor_owned", "reg_owned", 2*1024*1024)
	require(t, err)
	defer wal.Close()
	ca := filepath.Join(dir, "ca.pem")
	require(t, os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: device.Certificate().Raw}), 0600))
	deviceCfg := response.Configuration{ID: "connector_script", DeviceID: "device_script", DeviceVersion: "script/1",
		Origin: device.URL, CAFile: ca, AllowedTargets: []string{"192.0.2.0/24"}, MaxTTLSeconds: 60}
	names := []string{"device_id", "lease_id", "owner_sha256", "expires_at", "state", "rule_id", "observed_at"}
	healthFields := []string{"device_id", "version", "native_ttl", "separate_leases", "conditional_revoke", "max_ttl_seconds", "observed_at"}
	mapping := func(keys []string) []response.TemplateField {
		fields := make([]response.TemplateField, 0, len(keys))
		for _, key := range keys {
			fields = append(fields, response.TemplateField{Name: key, Value: key})
		}
		return fields
	}
	fieldsIP := append(append([]string(nil), names...), "target_ip")
	fieldsHost := append(append([]string(nil), names...), "host_id")
	add := func(method, path, target string) map[string]any {
		keys := []string{"lease_id", "owner_sha256", "expires_at", target}
		fields := make([]response.TemplateField, 0, len(keys))
		for _, key := range keys {
			fields = append(fields, response.TemplateField{Name: key, Value: "{{" + key + "}}"})
		}
		return map[string]any{"method": method, "path": path, "body": fields}
	}
	remove := map[string]string{"method": "DELETE", "path": "/remove/{rule_id}"}
	verify := func(path string, fields []string) map[string]any {
		return map[string]any{"path": path, "fields": mapping(fields), "missing_field": "code", "missing_value": "missing"}
	}
	profile := map[string]any{"plugin_id": "script_owned", "device": deviceCfg, "test_address": testIP, "test_host": testHost,
		"script": map[string]any{
			"routes": []responsescript.Route{
				{Entry: "health", Method: "GET", Path: "/health", Fields: append(healthFields, "healthy")},
				{Entry: "pull_alerts", Method: "GET", Path: "/alerts", Query: []string{"after"}, Fields: []string{"cursor", "items"}},
				{Entry: "block", Method: "PUT", Path: "/block"},
				{Entry: "unblock", Method: "DELETE", Path: "/remove/{rule_id}"},
				{Entry: "isolate", Method: "POST", Path: "/isolate"},
				{Entry: "release", Method: "DELETE", Path: "/remove/{rule_id}"},
				{Entry: "verify", Method: "GET", Path: "/lease/{rule_id}", Fields: append(fieldsIP, "code")},
				{Entry: "verify", Method: "GET", Path: "/terminal/{rule_id}", Fields: append(fieldsHost, "code")},
			},
			"actions": map[string]any{"block": add("PUT", "/block", "target_ip"), "unblock": remove,
				"isolate": add("POST", "/isolate", "host_id"), "release": remove},
			"verify":        map[string]any{"block": verify("/lease/{rule_id}", fieldsIP), "isolate": verify("/terminal/{rule_id}", fieldsHost)},
			"device_health": map[string]any{"path": "/health", "fields": mapping(healthFields)},
		}}
	raw, _ := json.Marshal(map[string]any{"schema_version": "response.plugin-bindings.v1", "profiles": []any{profile}})
	file := filepath.Join(dir, "plugins.json")
	require(t, os.WriteFile(file, raw, 0600))
	service, err := agent.NewPluginService(wal, file, binary, pub, "127.0.0.1:443")
	require(t, err)
	defer service.Close()
	engine := &agent.Engine{WAL: wal, Plugins: service}
	exampleHealth, _ := json.Marshal(deviceInfo("{{observed_at}}"))
	leaseBody := func(target, value, state, rule string) string {
		v, _ := json.Marshal(map[string]string{"device_id": "{{device_id}}", "lease_id": "{{lease_id}}", "owner_sha256": "{{owner_sha256}}",
			"expires_at": "{{expires_at}}", "observed_at": "{{observed_at}}", "state": state, "rule_id": rule, target: value})
		return string(v)
	}
	examples := []response.PluginExample{{Method: "GET", Path: "/health", Status: 200, Response: string(exampleHealth)},
		{Method: "GET", Path: "/alerts", Query: "after=", Status: 200, Response: `{"cursor":"first","items":[]}`}}
	for _, flow := range []struct{ read, write, method, field, marker, rule string }{
		{"/lease/fixture-lease", "/block", "PUT", "target_ip", "{{target_ip}}", "block_rule"},
		{"/terminal/fixture-lease", "/isolate", "POST", "host_id", "{{host_id}}", "isolate_rule"},
	} {
		examples = append(examples,
			response.PluginExample{Method: "GET", Path: flow.read, Status: 404, Response: `{"code":"missing"}`},
			response.PluginExample{Method: flow.method, Path: flow.write, Status: 201, Response: `{}`},
			response.PluginExample{Method: "GET", Path: flow.read, Status: 200, Response: leaseBody(flow.field, flow.marker, "active", flow.rule)},
			response.PluginExample{Method: "DELETE", Path: "/remove/" + flow.rule, Status: 204},
			response.PluginExample{Method: "GET", Path: flow.read, Status: 200, Response: leaseBody(flow.field, flow.marker, "revoked", flow.rule)})
	}
	source := &response.PluginScript{Source: pluginFixtureSource, Entries: []string{"health", "pull_alerts", "block", "unblock", "verify", "isolate", "release"}}
	version := response.PluginVersion{ID: "script_owned", Version: 1, Name: "防御联动夹具", Device: "客户自有 API",
		Kind: "script", State: "draft", CreatedBy: "owner", CreatedAt: time.Now().UTC(), Script: source, ScriptSHA256: source.SHA256(), Examples: examples}
	binding := service.Bindings()[0]
	var hashes [3]string
	for i, stage := range response.PluginStages {
		trial := response.PluginTrial{Binding: binding, Version: version, Stage: stage}
		payload, _ := json.Marshal(trial)
		c := control.Command{ID: fmt.Sprintf("task_stage_%d", i), TenantID: wal.TenantID, SensorID: wal.SensorID,
			RegistrationID: wal.RegistrationID, Kind: response.PluginTrialCommand, IssuedAt: time.Now().UTC(),
			ExpiresAt: time.Now().Add(time.Minute).UTC(), Payload: payload}
		result, code, err := engine.Execute(ctx, c)
		if err != nil {
			t.Fatalf("%s 试运行失败 %s, %v，回执 %s", stage, code, err, result)
		}
		r, err := response.ReadPluginTrialResult(result, trial)
		require(t, err)
		hashes[i] = r.SHA256()
		mu.Lock()
		nW, nR, nReq := writes, removes, requests
		mu.Unlock()
		if i == 0 && nReq != 0 || i == 1 && (nReq == 0 || nW != 0) || i == 2 && (nW != 2 || nR != 2) {
			t.Fatalf("%s 的真实写入、解除或访问数量异常 %d/%d/%d", stage, nW, nR, nReq)
		}
	}
	grant := response.PluginGrant{TenantID: wal.TenantID, SensorID: wal.SensorID, RegistrationID: wal.RegistrationID,
		Version: 1, Binding: binding, DefinitionSHA256: version.DefinitionSHA256(), TrialSHA256: hashes}
	signed, err := response.SignPlugin(grant, signer)
	require(t, err)
	artifact := &response.PluginArtifact{Version: version, Release: signed}
	payload, _ := json.Marshal(response.PluginActivation{PluginID: version.ID, Action: "publish", Artifact: artifact})
	c := control.Command{ID: "capable_publish", TenantID: wal.TenantID, SensorID: wal.SensorID, RegistrationID: wal.RegistrationID,
		Kind: response.PluginApplyCommand, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(time.Minute).UTC(), Payload: payload}
	activateFixturePlugin(t, ctx, service, engine, wal, signer, c)
	checkManagedPluginAction(t, ctx, service, wal, c, deviceCfg, testIP)
	artifact.Release.Signature[0] ^= 1
	c.Payload, _ = json.Marshal(response.PluginActivation{PluginID: version.ID, Action: "publish", Artifact: artifact})
	if _, code, err := engine.Execute(ctx, c); err == nil || code != "plugin_signature" {
		t.Fatal("采集器接受了被修改的版本签名", code)
	}
	// 插件声称已生效但没有实际 GET 的情况须被父进程拒绝。
	liar := *version.Script
	liar.Source = strings.Split(liar.Source, "def verify")[0] + "def verify(ctx, target, lease): return True\n"
	version.Script, version.ScriptSHA256 = &liar, liar.SHA256()
	c.Kind, c.ID = response.PluginTrialCommand, "verify_without_read"
	c.Payload, _ = json.Marshal(response.PluginTrial{Version: version, Binding: binding, Stage: response.PluginRead})
	if _, _, err := engine.Execute(ctx, c); err == nil {
		t.Fatal("只有脚本返回值无法冒充独立回读")
	}
	version.Script, version.ScriptSHA256 = source, source.SHA256()

	readOnly := *source
	readOnly.Entries = []string{"health", "pull_alerts", "verify"}
	version.Script, version.ScriptSHA256 = &readOnly, readOnly.SHA256()
	for _, stage := range []string{response.PluginRead, response.PluginCapability} {
		req := response.PluginTrial{Version: version, Binding: binding, Stage: stage}
		c.ID = "readonly_" + stage
		c.Payload, _ = json.Marshal(req)
		result, _, err := engine.Execute(ctx, c)
		require(t, err)
		_, err = response.ReadPluginTrialResult(result, req)
		require(t, err)
	}
	// 只读脚本不依赖设备处置能力映射，但仍须在父进程留下成功的真实读取。
	delete(profile["script"].(map[string]any), "device_health")
	plainProfile, _ := json.Marshal(map[string]any{"schema_version": "response.plugin-bindings.v1", "profiles": []any{profile}})
	require(t, os.WriteFile(file, plainProfile, 0600))
	readService, err := agent.NewPluginService(wal, file, binary, pub)
	require(t, err)
	defer readService.Close()
	readEngine := &agent.Engine{WAL: wal, Plugins: readService}
	c.ID = "health_from_actual_device"
	c.Payload, _ = json.Marshal(response.PluginTrial{Version: version, Binding: readService.Bindings()[0], Stage: response.PluginRead})
	_, _, err = readEngine.Execute(ctx, c)
	require(t, err)
	fakeHealth := readOnly
	fakeHealth.Source = strings.Replace(fakeHealth.Source, `return http.get(ctx.base_url + "/health").json()["healthy"]`, "return True", 1)
	version.Script, version.ScriptSHA256 = &fakeHealth, fakeHealth.SHA256()
	c.ID = "health_without_device"
	c.Payload, _ = json.Marshal(response.PluginTrial{Version: version, Binding: readService.Bindings()[0], Stage: response.PluginRead})
	if _, code, err := readEngine.Execute(ctx, c); err == nil || code != "plugin_unavailable" {
		t.Fatal("只读脚本可在未连接设备时宣称健康", code, err)
	}
	version.Script, version.ScriptSHA256 = source, source.SHA256()
	mu.Lock()
	loseWriteResponse = true
	mu.Unlock()
	c.ID = "unknown_write_result"
	c.Payload, _ = json.Marshal(response.PluginTrial{Version: version, Binding: binding, Stage: response.PluginCapability})
	if _, code, err := engine.Execute(ctx, c); err == nil || code != "result_unknown" {
		t.Fatal("设备接收请求后异常响应未标记为未知", code, err)
	}
	mu.Lock()
	rolledBack := state["/lease/"+c.ID]
	mu.Unlock()
	if rolledBack.State != "revoked" {
		t.Fatal("不明确的写入结果未通过实际回读确认并解除")
	}
	c.ID = "unknown_result_retry"
	if _, code, err := engine.Execute(ctx, c); err == nil || code != "plugin_test_reserved" {
		t.Fatal("未知结果期限内未保护专用试运行目标", code, err)
	}
}

func activateFixturePlugin(t *testing.T, ctx context.Context, service *agent.PluginService, engine *agent.Engine, wal *agent.WAL, signer ed25519.PrivateKey, c control.Command) {
	t.Helper()
	manager, err := agent.NewTaskManager(wal, signer.Public().(ed25519.PublicKey), engine)
	require(t, err)
	manager.Plugins = service
	raw, sig, err := control.Encode(c, signer)
	require(t, err)
	require(t, manager.Accept(raw, sig))
	running, stop := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- manager.Run(running) }()
	defer func() { stop(); require(t, <-done) }()
	if receipt := waitPluginReceipt(t, ctx, manager, c.ID); receipt.State != "succeeded" {
		t.Fatalf("采集器未落盘签名版本 %s/%s", receipt.State, receipt.Code)
	}
}

func checkManagedPluginAction(t *testing.T, ctx context.Context, service *agent.PluginService, wal *agent.WAL, identity control.Command, cfg response.Configuration, ip string) {
	t.Helper()
	live, err := agent.NewResponseService(wal, "")
	require(t, err)
	defer live.Close()
	live.Plugins = service
	running, stop := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- live.Run(running) }()
	defer func() { stop(); require(t, <-done) }()
	var advertised response.Health
	for started := time.Now(); time.Since(started) < 5*time.Second && ctx.Err() == nil; {
		items := live.Health()
		if len(items) == 1 && items[0].Status == "ready" {
			advertised = items[0]
			break
		}
		time.Sleep(15 * time.Millisecond)
	}
	if advertised.DeviceID != cfg.DeviceID || advertised.MaxTTLSeconds != 60 || advertised.ConfigSHA256 == cfg.SHA256() {
		t.Fatal("已签脚本未从真实设备健康响应发布连接器")
	}
	now := time.Now().UTC()
	a := response.Action{SchemaVersion: response.ActionSchema, ConnectorID: cfg.ID, ConfigSHA256: advertised.ConfigSHA256,
		DeviceID: cfg.DeviceID, LeaseID: "fixture_authorized", TargetIP: ip, Reason: "核对同一租约授权入口",
		RequestedAt: now, ExpiresAt: now.Add(time.Minute), OwnerSHA256: response.Owner(wal.TenantID, wal.SensorID, wal.RegistrationID, "fixture_authorized")}
	identity.Payload, _ = json.Marshal(a)
	for _, step := range []struct{ kind, id, state string }{
		{"response.block", a.LeaseID, "active"}, {"response.read", "fixture_read", "active"}, {"response.revoke", "fixture_revoke", "revoked"},
	} {
		identity.Kind, identity.ID = step.kind, step.id
		raw, _, err := live.Execute(ctx, identity)
		require(t, err)
		result, err := response.ReadResult(raw, a, step.kind, time.Now().UTC())
		require(t, err)
		if result.Observation.State != step.state {
			t.Fatal("启用的脚本未沿用原租约动作链", step.kind, result.Observation.State)
		}
	}
}
