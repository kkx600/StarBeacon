package response

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type endpointFixture struct {
	mu              sync.Mutex
	leases          map[string]Lease
	writes, deletes int
	intercept       func(http.ResponseWriter, *http.Request) bool
}

func clientFixture(t *testing.T) (*Client, *endpointFixture) {
	t.Helper()
	f := &endpointFixture{leases: map[string]Lease{}}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		if r.Header.Get("Authorization") != "Bearer controlled-protocol-test-token" {
			w.WriteHeader(401)
			_, _ = w.Write([]byte(`{}`))
			return
		}
		if f.intercept != nil && f.intercept(w, r) {
			return
		}
		if r.URL.Path == "/starbeacon/v1/device" {
			_ = json.NewEncoder(w).Encode(Device{SchemaVersion: DeviceSchema, DeviceID: "device_test", Version: "fixture/1", NativeTTL: true, SeparateLeases: true, ConditionalRevoke: true, MaxTTLSeconds: 3600, ObservedAt: time.Now().UTC()})
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/starbeacon/v1/leases/")
		value, exists := f.leases[id]
		if r.Method == http.MethodPut {
			var a Action
			if json.NewDecoder(r.Body).Decode(&a) != nil || a.LeaseID != id {
				w.WriteHeader(400)
				_, _ = w.Write([]byte(`{}`))
				return
			}
			f.writes++
			value = Lease{SchemaVersion: LeaseSchema, DeviceID: a.DeviceID, LeaseID: a.LeaseID, OwnerSHA256: a.OwnerSHA256, TargetIP: a.TargetIP, ExpiresAt: a.ExpiresAt, State: "active"}
			f.leases[id] = value
			w.WriteHeader(202)
			_, _ = w.Write([]byte(`{}`))
			return
		}
		if !exists {
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`{ "schema_version": "response.error.v1", "code": "lease_not_found" }`))
			return
		}
		if r.Method == http.MethodDelete {
			if r.Header.Get("If-Match") != `"`+value.OwnerSHA256+`"` {
				w.WriteHeader(412)
				_, _ = w.Write([]byte(`{}`))
				return
			}
			f.deletes++
			value.State = "revoked"
		}
		value.ObservedAt = time.Now().UTC()
		if value.State == "active" && !value.ExpiresAt.After(value.ObservedAt) {
			value.State = "expired"
		}
		f.leases[id] = value
		_ = json.NewEncoder(w).Encode(value)
	}))
	t.Cleanup(server.Close)
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	token := filepath.Join(dir, "token")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(token, []byte("controlled-protocol-test-token\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c := Configuration{ID: "connector_test", DeviceID: "device_test", DeviceVersion: "fixture/1", Origin: server.URL, CAFile: ca, TokenFile: token, AllowedTargets: []string{"198.51.100.0/24"}, ProtectedTargets: []string{"198.51.100.1/32"}, MaxTTLSeconds: 3600}
	client, err := NewClient(c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return client, f
}
func actionFixture(c Configuration) Action {
	now := time.Now().UTC()
	return Action{SchemaVersion: ActionSchema, ConnectorID: c.ID, ConfigSHA256: c.SHA256(), DeviceID: c.DeviceID, LeaseID: "task_owned", OwnerSHA256: Owner("tenant_test", "sensor_test", "registration_test", "task_owned"), TargetIP: "198.51.100.10", RequestedAt: now, ExpiresAt: now.Add(time.Minute), Reason: "受控协议验证"}
}

func TestResponseHealthReadinessStrictResultsAndLeaseOverlap(t *testing.T) {
	c, _ := clientFixture(t)
	a := actionFixture(c.Config)
	h := Health{ConnectorID: c.Config.ID, DeviceID: c.Config.DeviceID, Version: c.Config.DeviceVersion, ConfigSHA256: c.Config.SHA256(), Status: "ready", ObservedAt: time.Now().UTC(), MaxTTLSeconds: 3600}
	if !h.Ready(time.Now().UTC()) {
		t.Fatal("有效设备不可用")
	}
	for _, change := range []func(*Health){func(v *Health) { v.Status = "unverified" }, func(v *Health) { v.ConnectorID = "/" }, func(v *Health) { v.DeviceID = "/" }, func(v *Health) { v.ConfigSHA256 = "" }, func(v *Health) { v.Version = "" }, func(v *Health) { v.Version = "version\n" }, func(v *Health) { v.MaxTTLSeconds = 29 }, func(v *Health) { v.MaxTTLSeconds = 3601 }, func(v *Health) { v.ObservedAt = time.Time{} }, func(v *Health) { v.ObservedAt = time.Now().UTC().Add(-time.Minute) }, func(v *Health) { v.ObservedAt = time.Now().UTC().Add(time.Minute) }} {
		value := h
		change(&value)
		if value.Ready(time.Now().UTC()) {
			t.Fatal("无效设备状态")
		}
	}
	result, err := c.Execute(context.Background(), "response.block", a)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(result)
	if _, err = ReadResult(raw, a, "response.block", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{`null`, `{"verified":true,"verified":true}`, `{"Verified":true}`, string(raw[:len(raw)-1]) + `,"extra":true}`, strings.Repeat(" ", 16385)} {
		if _, err = ReadResult([]byte(invalid), a, "response.block", time.Now().UTC()); err == nil {
			t.Fatal("不规范回执被接受")
		}
	}
	b := a
	b.LeaseID = "task_overlap"
	b.OwnerSHA256 = Owner("tenant_other", "sensor_other", "registration_other", b.LeaseID)
	if _, err = c.Execute(context.Background(), "response.block", b); err != nil {
		t.Fatal(err)
	}
	if _, err = c.Execute(context.Background(), "response.revoke", a); err != nil {
		t.Fatal(err)
	}
	result, err = c.Execute(context.Background(), "response.read", b)
	if err != nil || result.Observation.State != "active" {
		t.Fatal("同 IP 独立租约被解除", err)
	}
	foreign := b
	foreign.OwnerSHA256 = Owner("tenant_other", "sensor_other", "registration_other", "task_other")
	if _, err = c.Execute(context.Background(), "response.revoke", foreign); err == nil {
		t.Fatal("跨租约所有者解除")
	}
}
func TestResponseNativeTTLReadRevokeAndIdempotency(t *testing.T) {
	c, f := clientFixture(t)
	a := actionFixture(c.Config)
	for _, kind := range []string{"response.block", "response.block", "response.read", "response.revoke", "response.revoke", "response.read"} {
		result, err := c.Execute(context.Background(), kind, a)
		if err != nil {
			t.Fatal(kind, err)
		}
		if err = result.Validate(a, kind, time.Now().UTC()); err != nil || !result.Verified || result.Effect != "not_observed" {
			t.Fatal("无来源的回读", err)
		}
	}
	f.mu.Lock()
	if f.writes != 1 || f.deletes != 1 {
		t.Fatal("幂等失败", f.writes, f.deletes)
	}
	f.mu.Unlock()
	if _, err := c.Execute(context.Background(), "response.block", a); !errors.Is(err, ErrUnknown) {
		t.Fatal("历史已解除动作被重建", err)
	}
	a.LeaseID = "task_expired"
	a.RequestedAt = time.Now().UTC().Add(-time.Minute)
	a.ExpiresAt = a.RequestedAt.Add(30 * time.Second)
	f.mu.Lock()
	f.leases[a.LeaseID] = Lease{SchemaVersion: LeaseSchema, DeviceID: a.DeviceID, LeaseID: a.LeaseID, OwnerSHA256: a.OwnerSHA256, TargetIP: a.TargetIP, ExpiresAt: a.ExpiresAt, State: "active"}
	f.mu.Unlock()
	result, err := c.Execute(context.Background(), "response.read", a)
	if err != nil || result.Observation.State != "expired" {
		t.Fatal("到期未独立回读", err)
	}
	if _, err = c.Execute(context.Background(), "response.block", a); !errors.Is(err, ErrInput) {
		t.Fatal("过期授权重建", err)
	}
	if _, err = c.Execute(context.Background(), "response.revoke", a); err != nil {
		t.Fatal(err)
	}
}
func TestResponseContractInputsAndObservationBinding(t *testing.T) {
	c, _ := clientFixture(t)
	a := actionFixture(c.Config)
	for _, change := range []func(*Action){func(v *Action) { v.SchemaVersion = "other" }, func(v *Action) { v.ConnectorID = "/" }, func(v *Action) { v.DeviceID = "/" }, func(v *Action) { v.LeaseID = "/" }, func(v *Action) { v.ConfigSHA256 = "AA" }, func(v *Action) { v.OwnerSHA256 = "" }, func(v *Action) { v.TargetIP = "127.0.0.1" }, func(v *Action) { v.Reason = " " }, func(v *Action) { v.Reason = "x\n" }, func(v *Action) { v.RequestedAt = time.Time{} }, func(v *Action) { v.ExpiresAt = v.RequestedAt }, func(v *Action) { v.ExpiresAt = v.RequestedAt.Add(2 * time.Hour) }} {
		v := a
		change(&v)
		if v.Validate() == nil {
			t.Fatal("接受无效授权", v)
		}
	}
	for _, ip := range []string{"0.0.0.0", "01.1.1.1", "::ffff:198.51.100.10", "fe80::1", "224.0.0.1", "240.0.0.1", "198.51.100.10/32", "2001:db8::1%eth0"} {
		if ValidTarget(ip) {
			t.Fatal(ip)
		}
	}
	if !ValidTarget("2001:db8::1") {
		t.Fatal("规范 IPv6 被拒绝")
	}
	raw, _ := json.Marshal(a)
	if _, err := ReadAction(raw); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{`null`, `[]`, `{"schema_version":"x","schema_version":"y"}`, `{"SchemaVersion":"x"}`, `{"extra":1}`, strings.Repeat(" ", 8193)} {
		if _, err := ReadAction([]byte(raw)); err == nil {
			t.Fatal("严格载荷边界")
		}
	}
	i := Intent{ConnectorID: c.Config.ID, ConfigSHA256: c.Config.SHA256(), TargetIP: a.TargetIP, TTLSeconds: 30, Reason: "业务依据"}
	if i.Validate("response.block") != nil {
		t.Fatal("合法意图")
	}
	raw, _ = json.Marshal(i)
	if _, err := ReadIntent(raw, "response.block"); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"response.read", "response.revoke", "other"} {
		if i.Validate(kind) == nil {
			t.Fatal("混合参数")
		}
	}
	i.TargetIP = ""
	i.TTLSeconds = 0
	i.OriginalTaskID = a.LeaseID
	if i.Validate("response.read") != nil || i.Validate("response.revoke") != nil {
		t.Fatal("原任务引用")
	}
	i.Reason = ""
	if i.Validate("response.read") == nil {
		t.Fatal("无操作依据")
	}
	lease := Lease{SchemaVersion: LeaseSchema, DeviceID: a.DeviceID, LeaseID: a.LeaseID, OwnerSHA256: a.OwnerSHA256, TargetIP: a.TargetIP, ExpiresAt: a.ExpiresAt, State: "active", ObservedAt: time.Now().UTC()}
	for _, change := range []func(*Lease){func(v *Lease) { v.SchemaVersion = "x" }, func(v *Lease) { v.DeviceID = "other" }, func(v *Lease) { v.LeaseID = "other" }, func(v *Lease) { v.OwnerSHA256 = strings.Repeat("a", 64) }, func(v *Lease) { v.TargetIP = "198.51.100.11" }, func(v *Lease) { v.ExpiresAt = v.ExpiresAt.Add(time.Second) }, func(v *Lease) { v.ObservedAt = v.ObservedAt.Add(-time.Minute) }, func(v *Lease) { v.ObservedAt = v.ObservedAt.Add(time.Minute) }, func(v *Lease) { v.State = "expired" }, func(v *Lease) { v.State = "accepted" }} {
		v := lease
		change(&v)
		if v.Validate(a, time.Now().UTC()) == nil {
			t.Fatal("回读绑定缺失")
		}
	}
	r := Result{SchemaVersion: "response.result.v1", ConnectorID: a.ConnectorID, ConfigSHA256: a.ConfigSHA256, Verified: true, Observation: lease, Effect: "not_observed"}
	for _, change := range []func(*Result){func(v *Result) { v.SchemaVersion = "x" }, func(v *Result) { v.Verified = false }, func(v *Result) { v.ConnectorID = "other" }, func(v *Result) { v.ConfigSHA256 = "" }, func(v *Result) { v.Effect = "blocked" }} {
		v := r
		change(&v)
		if v.Validate(a, "response.read", time.Now().UTC()) == nil {
			t.Fatal("结果未绑定")
		}
	}
	if r.Validate(a, "response.revoke", time.Now().UTC()) == nil || r.Validate(a, "other", time.Now().UTC()) == nil {
		t.Fatal("未解除状态伪称解除")
	}
	if Code(ErrInput) != "response_scope_invalid" || Code(ErrUnavailable) != "response_device_unavailable" || Code(errors.New("secret")) != "result_unknown" {
		t.Fatal("错误分类")
	}
}
func TestResponseConfigurationFilesAndScope(t *testing.T) {
	c, _ := clientFixture(t)
	base := c.Config
	if base.Validate() != nil || base.Allows("198.51.100.1", 30) || base.Allows("198.51.100.2", 29) || base.Allows("203.0.113.1", 30) || base.Allows("bad", 30) || !base.Allows("198.51.100.2", 30) {
		t.Fatal("作用范围或保护范围")
	}
	for _, change := range []func(*Configuration){func(v *Configuration) { v.ID = "/" }, func(v *Configuration) { v.DeviceVersion = "" }, func(v *Configuration) { v.Origin = "http://127.0.0.1" }, func(v *Configuration) { v.Origin = "https://name.example" }, func(v *Configuration) { v.Origin += "/path" }, func(v *Configuration) { v.CAFile = "relative" }, func(v *Configuration) { v.TokenFile = "relative" }, func(v *Configuration) { v.MaxTTLSeconds = 0 }, func(v *Configuration) { v.AllowedTargets = nil }, func(v *Configuration) { v.AllowedTargets = []string{"198.51.100.1/24"} }, func(v *Configuration) { v.AllowedTargets = []string{"198.51.100.0/24", "198.51.100.0/24"} }, func(v *Configuration) { v.ProtectedTargets = []string{"::ffff:0.0.0.0/96"} }} {
		v := base
		change(&v)
		if v.Validate() == nil || v.Allows("198.51.100.2", 30) {
			t.Fatal("无效配置")
		}
		if _, err := NewClient(v); err == nil {
			t.Fatal("构建无效客户端")
		}
	}
	for _, bad := range []string{"missing", "empty", "invalid"} {
		v := base
		v.CAFile = filepath.Join(t.TempDir(), bad)
		if bad != "missing" {
			if err := os.WriteFile(v.CAFile, []byte(bad), 0600); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := NewClient(v); err == nil {
			t.Fatal("无效信任材料")
		}
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "connectors.json")
	file := File{SchemaVersion: "response.connectors.v1", Connectors: []Configuration{base}}
	raw, _ := json.Marshal(file)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadFile(path)
	if err != nil || loaded.RetentionDays != 180 {
		t.Fatal("默认留存", err)
	}
	file.RetentionDays = 7
	raw, _ = json.Marshal(file)
	_ = os.WriteFile(path, raw, 0600)
	if loaded, err = LoadFile(path); err != nil || loaded.RetentionDays != 7 {
		t.Fatal("可配置留存")
	}
	for _, change := range []func(*File){func(v *File) { v.SchemaVersion = "x" }, func(v *File) { v.RetentionDays = 3651 }, func(v *File) { v.Connectors = nil }, func(v *File) { v.Connectors = append(v.Connectors, base) }} {
		v := file
		v.Connectors = append([]Configuration(nil), file.Connectors...)
		change(&v)
		raw, _ = json.Marshal(v)
		_ = os.WriteFile(path, raw, 0600)
		if _, err := LoadFile(path); err == nil {
			t.Fatal("配置文件边界")
		}
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPrivateFile(path, 128*1024); err == nil {
		t.Fatal("公开权限秘密")
	}
	if _, err := ReadPrivateFile(dir, 128*1024); err == nil {
		t.Fatal("目录")
	}
	_ = os.Chmod(path, 0600)
	if _, err := ReadPrivateFile(path, 1); err == nil {
		t.Fatal("文件预算")
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPrivateFile(link, 128*1024); err == nil {
		t.Fatal("链接")
	}
	if _, err := LoadFile(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("缺失配置")
	}
	for _, raw := range []string{`{"schema_version":"response.connectors.v1","schema_version":"x"}`, `null`, `{ "extra": 1 }`} {
		_ = os.WriteFile(path, []byte(raw), 0600)
		if _, err := LoadFile(path); err == nil {
			t.Fatal("配置严格 JSON")
		}
	}
}
func TestResponseDeviceErrorsAndUnknownWrites(t *testing.T) {
	for _, code := range []int{400, 401, 403, 409, 412, 429, 500, 302} {
		t.Run(string(rune(code)), func(t *testing.T) {
			c, f := clientFixture(t)
			a := actionFixture(c.Config)
			f.intercept = func(w http.ResponseWriter, r *http.Request) bool {
				if r.Method == http.MethodPut {
					w.WriteHeader(code)
					_, _ = w.Write([]byte(`{}`))
					return true
				}
				return false
			}
			_, err := c.Execute(context.Background(), "response.block", a)
			if err == nil {
				t.Fatal("仅 HTTP 状态被当成生效")
			}
			if code < 500 && code != 302 && !errors.Is(err, ErrUnavailable) {
				t.Fatal("确定拒绝未分类", err)
			}
			f.mu.Lock()
			if f.writes != 0 {
				t.Fatal("错误重发")
			}
			f.mu.Unlock()
		})
	}
	c, f := clientFixture(t)
	a := actionFixture(c.Config)
	f.intercept = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method != http.MethodPut {
			return false
		}
		f.writes++
		f.leases[a.LeaseID] = Lease{SchemaVersion: LeaseSchema, DeviceID: a.DeviceID, LeaseID: a.LeaseID, OwnerSHA256: a.OwnerSHA256, TargetIP: a.TargetIP, ExpiresAt: a.ExpiresAt, State: "active"}
		connection, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Fatal(err)
		}
		_ = connection.Close()
		return true
	}
	result, err := c.Execute(context.Background(), "response.block", a)
	if err != nil || result.Observation.State != "active" {
		t.Fatal("丢失受理响应未回读", err)
	}
	f.mu.Lock()
	if f.writes != 1 {
		t.Fatal("丢失响应导致重复写")
	}
	f.intercept = nil
	f.mu.Unlock()
	f.intercept = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodDelete {
			w.WriteHeader(503)
			_, _ = w.Write([]byte(`{}`))
			return true
		}
		return false
	}
	if _, err = c.Execute(context.Background(), "response.revoke", a); !errors.Is(err, ErrUnknown) {
		t.Fatal("解除未知被确认", err)
	}
	f.mu.Lock()
	f.intercept = nil
	f.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = c.Execute(ctx, "response.block", a); err == nil {
		t.Fatal("取消")
	}
}
func TestResponseProtocolPayloadAndCredentialBoundaries(t *testing.T) {
	for _, body := range []string{`{}`, `{"schema_version":"response.device.v1","device_id":"wrong"}`, `{"native_ttl":true,"native_ttl":false}`, strings.Repeat("x", 16385), `[]`} {
		c, f := clientFixture(t)
		f.intercept = func(w http.ResponseWriter, r *http.Request) bool { _, _ = w.Write([]byte(body)); return true }
		if _, err := c.Describe(context.Background()); err == nil {
			t.Fatal("无效身份或预算")
		}
	}
	c, f := clientFixture(t)
	a := actionFixture(c.Config)
	for _, mutate := range []func(*Action){func(v *Action) { v.ConfigSHA256 = "" }, func(v *Action) { v.ConnectorID = "other" }, func(v *Action) { v.DeviceID = "other" }, func(v *Action) { v.TargetIP = "198.51.100.1" }, func(v *Action) {
		v.RequestedAt = time.Now().UTC().Add(time.Minute)
		v.ExpiresAt = v.RequestedAt.Add(time.Minute)
	}} {
		v := a
		mutate(&v)
		if _, err := c.Execute(context.Background(), "response.block", v); err == nil {
			t.Fatal("客户端作用范围")
		}
	}
	if _, err := c.Execute(context.Background(), "response.read", a); !errors.Is(err, ErrUnknown) {
		t.Fatal("不存在不等于已解除")
	}
	if _, err := c.Execute(context.Background(), "response.revoke", a); !errors.Is(err, ErrUnknown) {
		t.Fatal("不存在不等于已解除")
	}
	if _, err := c.Execute(context.Background(), "other", a); err == nil {
		t.Fatal("任意动作")
	}
	f.intercept = func(w http.ResponseWriter, r *http.Request) bool {
		if strings.Contains(r.URL.Path, "/leases/") {
			_, _ = w.Write([]byte(`{"state":"active","state":"revoked"}`))
			return true
		}
		return false
	}
	if _, err := c.Execute(context.Background(), "response.read", a); err == nil {
		t.Fatal("回读重复字段")
	}
	f.mu.Lock()
	f.intercept = func(w http.ResponseWriter, r *http.Request) bool {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("login"))
		return true
	}
	f.mu.Unlock()
	if _, err := c.Describe(context.Background()); err == nil {
		t.Fatal("登录页面")
	}
	for _, token := range []string{"", "short", "controlled-secret\r\nHeader: x", strings.Repeat("x", 4097)} {
		_ = os.WriteFile(c.Config.TokenFile, []byte(token), 0600)
		if _, err := c.Describe(context.Background()); err == nil {
			t.Fatal("凭据边界")
		}
	}
	_ = os.Remove(c.Config.TokenFile)
	if _, err := c.Describe(context.Background()); err == nil {
		t.Fatal("撤销凭据")
	}
	h := sha256.Sum256([]byte("x"))
	if !validHash(hex.EncodeToString(h[:])) || validHash(strings.ToUpper(hex.EncodeToString(h[:]))) {
		t.Fatal("规范摘要")
	}
}
