package agent

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/response"
	bolt "go.etcd.io/bbolt"
)

func responseServiceFixture(t *testing.T) (*ResponseService, string, *int, *sync.Mutex) {
	t.Helper()
	m, _ := taskFixture(t, terminalRunner{})
	dir := t.TempDir()
	var mu sync.Mutex
	writes := 0
	leases := map[string]response.Lease{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") != "Bearer controlled-response-fixture" {
			w.WriteHeader(401)
			_, _ = w.Write([]byte(`{}`))
			return
		}
		if r.URL.Path == "/starbeacon/v1/device" {
			_ = json.NewEncoder(w).Encode(response.Device{SchemaVersion: response.DeviceSchema, DeviceID: "device_fixture", Version: "fixture/1", NativeTTL: true, SeparateLeases: true, ConditionalRevoke: true, MaxTTLSeconds: 3600, ObservedAt: time.Now().UTC()})
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/starbeacon/v1/leases/")
		v, ok := leases[id]
		if r.Method == "PUT" {
			var a response.Action
			if json.NewDecoder(r.Body).Decode(&a) != nil {
				w.WriteHeader(400)
				_, _ = w.Write([]byte(`{}`))
				return
			}
			writes++
			v = response.Lease{SchemaVersion: response.LeaseSchema, DeviceID: a.DeviceID, LeaseID: a.LeaseID, OwnerSHA256: a.OwnerSHA256, TargetIP: a.TargetIP, ExpiresAt: a.ExpiresAt, State: "active"}
			leases[id] = v
			w.WriteHeader(202)
			_, _ = w.Write([]byte(`{}`))
			return
		}
		if !ok {
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`{"schema_version":"response.error.v1","code":"lease_not_found"}`))
			return
		}
		if r.Method == "DELETE" {
			if r.Header.Get("If-Match") != `"`+v.OwnerSHA256+`"` {
				w.WriteHeader(412)
				_, _ = w.Write([]byte(`{}`))
				return
			}
			v.State = "revoked"
		}
		v.ObservedAt = time.Now().UTC()
		if v.State == "active" && !v.ExpiresAt.After(v.ObservedAt) {
			v.State = "expired"
		}
		leases[id] = v
		_ = json.NewEncoder(w).Encode(v)
	}))
	t.Cleanup(server.Close)
	ca := filepath.Join(dir, "ca")
	token := filepath.Join(dir, "token")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(token, []byte("controlled-response-fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	c := response.Configuration{ID: "connector_fixture", DeviceID: "device_fixture", DeviceVersion: "fixture/1", Origin: server.URL, CAFile: ca, TokenFile: token, AllowedTargets: []string{"198.51.100.0/24"}, ProtectedTargets: []string{"198.51.100.1/32"}, MaxTTLSeconds: 3600}
	path := filepath.Join(dir, "connectors.json")
	raw, _ := json.Marshal(response.File{SchemaVersion: "response.connectors.v1", RetentionDays: 7, Connectors: []response.Configuration{c}})
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	s, err := NewResponseService(m.WAL, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s, path, &writes, &mu
}
func responseCommand(s *ResponseService, id string) control.Command {
	var config response.Configuration
	for _, c := range s.clients {
		config = c.Config
	}
	now := time.Now().UTC()
	a := response.Action{SchemaVersion: response.ActionSchema, ConnectorID: config.ID, DeviceID: config.DeviceID, ConfigSHA256: config.SHA256(), LeaseID: id, OwnerSHA256: response.Owner(s.WAL.TenantID, s.WAL.SensorID, s.WAL.RegistrationID, id), TargetIP: "198.51.100.10", RequestedAt: now, ExpiresAt: now.Add(time.Minute), Reason: "受控联动"}
	raw, _ := json.Marshal(a)
	return control.Command{ID: id, TenantID: s.WAL.TenantID, SensorID: s.WAL.SensorID, RegistrationID: s.WAL.RegistrationID, Kind: "response.block", IssuedAt: now, ExpiresAt: now.Add(30 * time.Second), Payload: raw}
}
func TestResponseServiceDurableRestartReconciliationAndCredentials(t *testing.T) {
	s, path, writes, mu := responseServiceFixture(t)
	ctx := context.Background()
	s.check(ctx, "connector_fixture")
	if h := s.Health(); len(h) != 1 || h[0].Status != "ready" {
		t.Fatal("身份未核验")
	}
	c := responseCommand(s, "task_owned")
	raw, code, err := s.Execute(ctx, c)
	if err != nil || code != "" || !json.Valid(raw) {
		t.Fatal(code, err)
	}
	var r responseRecord
	if err = s.WAL.DB.View(func(tx *bolt.Tx) error {
		return json.Unmarshal(tx.Bucket([]byte("response_leases")).Get([]byte(c.ID)), &r)
	}); err != nil {
		t.Fatal(err)
	}
	if r.Status != "active" || r.Result == nil || r.RetainUntil.Sub(r.Action.RequestedAt) != 7*24*time.Hour {
		t.Fatal("授权或可配置留存未落盘")
	}
	if _, _, err = s.Execute(ctx, c); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if *writes != 1 {
		t.Fatal("重复设备写入")
	}
	mu.Unlock()
	s.Close()
	restored, err := NewResponseService(s.WAL, path)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	r.CheckedAt = time.Now().UTC().Add(-time.Minute)
	r.Status = "unknown"
	r.Result = nil
	if err = s.WAL.DB.Update(func(tx *bolt.Tx) error {
		raw, _ := json.Marshal(r)
		return tx.Bucket([]byte("response_leases")).Put([]byte(c.ID), raw)
	}); err != nil {
		t.Fatal(err)
	}
	if err = restored.maintain(ctx); err != nil {
		t.Fatal(err)
	}
	if err = s.WAL.DB.View(func(tx *bolt.Tx) error {
		return json.Unmarshal(tx.Bucket([]byte("response_leases")).Get([]byte(c.ID)), &r)
	}); err != nil || r.Status != "active" {
		t.Fatal("重启未只读核对", err)
	}
	mu.Lock()
	if *writes != 1 {
		t.Fatal("重启补发副作用")
	}
	mu.Unlock()
	for _, kind := range []string{"response.read", "response.revoke"} {
		v := c
		v.ID = "task_reconcile"
		v.Kind = kind
		if _, _, err = restored.Execute(ctx, v); err != nil {
			t.Fatal(err)
		}
	}
	var token string
	for _, client := range restored.clients {
		token = client.Config.TokenFile
	}
	if err = os.WriteFile(token, []byte("revoked-credential-token"), 0600); err != nil {
		t.Fatal(err)
	}
	restored.check(ctx, "connector_fixture")
	if restored.Health()[0].Status != "unavailable" {
		t.Fatal("认证撤回仍显示就绪")
	}
	short, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	if err = restored.Run(short); err != nil {
		t.Fatal("维护退出", err)
	}
	engine := &Engine{Response: restored}
	if !strings.Contains(strings.Join(engine.Capabilities(), ","), "response.block") {
		t.Fatal("未声明能力")
	}
	if _, _, err = engine.Execute(ctx, c); err == nil {
		t.Fatal("失效凭据仍写入")
	}
	if _, code, err = (&Engine{}).Execute(ctx, c); err == nil || code != "response_device_unavailable" {
		t.Fatal("未配置执行器")
	}
}
func TestResponseServiceScopeHistoryBudgetAndStorageFailures(t *testing.T) {
	s, _, writes, mu := responseServiceFixture(t)
	ctx := context.Background()
	c := responseCommand(s, "task_budget")
	for _, change := range []func(*control.Command){func(v *control.Command) { v.TenantID = "other" }, func(v *control.Command) { v.SensorID = "other" }, func(v *control.Command) { v.RegistrationID = "other" }, func(v *control.Command) { v.ID = "other" }, func(v *control.Command) { v.Payload = json.RawMessage(`{}`) }} {
		v := c
		change(&v)
		if _, _, err := s.Execute(ctx, v); err == nil {
			t.Fatal("跨执行范围")
		}
	}
	a, _ := response.ReadAction(c.Payload)
	for _, change := range []func(*response.Action){func(v *response.Action) { v.ConnectorID = "unknown" }, func(v *response.Action) { v.ConfigSHA256 = control.Digest([]byte("other")) }, func(v *response.Action) { v.TargetIP = "198.51.100.1" }} {
		v := a
		change(&v)
		invalid := c
		invalid.Payload, _ = json.Marshal(v)
		if _, _, err := s.Execute(ctx, invalid); err == nil {
			t.Fatal("保护范围")
		}
	}
	read := c
	read.ID = "task_observe"
	read.Kind = "response.read"
	if _, _, err := s.Execute(ctx, read); err == nil {
		t.Fatal("未登记原租约")
	}
	if err := s.WAL.DB.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("response_leases"))
		for i := range 1024 {
			v := a
			v.LeaseID = fmt.Sprintf("lease_%04d", i)
			v.OwnerSHA256 = response.Owner(s.WAL.TenantID, s.WAL.SensorID, s.WAL.RegistrationID, v.LeaseID)
			r := responseRecord{Action: v, Status: "active", RetainUntil: time.Now().UTC().Add(time.Hour)}
			raw, _ := json.Marshal(r)
			if err := b.Put([]byte(fmt.Sprintf("lease_%04d", i)), raw); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, code, err := s.Execute(ctx, c); err == nil || code != "local_storage_unavailable" {
		t.Fatal("目录容量保护", code, err)
	}
	mu.Lock()
	if *writes != 0 {
		t.Fatal("存储失败仍创建副作用")
	}
	mu.Unlock()
	if err := s.WAL.DB.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("response_leases")).Put([]byte("bad"), []byte("corrupt"))
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.maintain(ctx); err == nil {
		t.Fatal("损坏租约被忽略")
	}
	if _, err := NewResponseService(s.WAL, filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("不可读取配置")
	}
	if err := s.WAL.DB.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Execute(ctx, c); err == nil {
		t.Fatal("关闭存储")
	}
}
func TestResponseServiceBoundedRetentionAndUnknownRead(t *testing.T) {
	s, _, _, _ := responseServiceFixture(t)
	c := responseCommand(s, "task_missing_device_resource")
	a, _ := response.ReadAction(c.Payload)
	if err := s.WAL.DB.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("response_leases"))
		for i := range 32 {
			v := a
			v.LeaseID = fmt.Sprintf("lease_history_%02d", i)
			v.OwnerSHA256 = response.Owner(s.WAL.TenantID, s.WAL.SensorID, s.WAL.RegistrationID, v.LeaseID)
			v.RequestedAt = time.Now().UTC().Add(-8 * 24 * time.Hour)
			v.ExpiresAt = v.RequestedAt.Add(time.Minute)
			r := responseRecord{Action: v, Status: "expired", RetainUntil: time.Now().UTC().Add(-time.Hour)}
			raw, _ := json.Marshal(r)
			if err := b.Put([]byte(v.LeaseID), raw); err != nil {
				return err
			}
		}
		r := responseRecord{Action: a, Status: "unknown", RetainUntil: time.Now().UTC().Add(time.Hour)}
		raw, _ := json.Marshal(r)
		return b.Put([]byte(a.LeaseID), raw)
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.maintain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := s.WAL.DB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("response_leases"))
		if b.Stats().KeyN != 17 {
			t.Fatal("清理无界或提前清理有效历史")
		}
		var r responseRecord
		if err := json.Unmarshal(b.Get([]byte(a.LeaseID)), &r); err != nil {
			return err
		}
		if r.Status != "unknown" || r.CheckedAt.IsZero() {
			t.Fatal("不存在被当作已解除")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestResponseManagementProtectionAndCorruptDirectory(t *testing.T) {
	s, _, _, _ := responseServiceFixture(t)
	_, local, _ := net.ParseCIDR("198.51.100.10/24")
	local.IP = net.ParseIP("198.51.100.10")
	s.addresses = func() ([]net.Addr, error) { return []net.Addr{local}, nil }
	if !errors.Is(s.protectManagement(context.Background(), "198.51.100.10"), response.ErrInput) {
		t.Fatal("本机管理地址参与封禁")
	}
	s.addresses = func() ([]net.Addr, error) { return nil, errors.New("unavailable") }
	if !errors.Is(s.protectManagement(context.Background(), "198.51.100.11"), response.ErrUnavailable) {
		t.Fatal("无法核对本机地址仍允许写入")
	}
	s.addresses = func() ([]net.Addr, error) { return []net.Addr{&net.TCPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 80}}, nil }
	if s.protectManagement(context.Background(), "198.51.100.11") == nil {
		t.Fatal("不完整地址目录")
	}
	s.addresses = func() ([]net.Addr, error) { return nil, nil }
	for _, endpoint := range []string{"198.51.100.10:443", "[2001:db8::10]:443", "bad-address"} {
		s.management = []string{endpoint}
		target := "198.51.100.10"
		if strings.HasPrefix(endpoint, "[") {
			target = "2001:db8::10"
		}
		if s.protectManagement(context.Background(), target) == nil {
			t.Fatal("管理端点未保护", endpoint)
		}
	}
	s.management = []string{"platform.example:443", "platform.example:444"}
	calls := 0
	s.resolve = func(context.Context, string, string) ([]netip.Addr, error) {
		calls++
		return []netip.Addr{netip.MustParseAddr("198.51.100.10")}, nil
	}
	if s.protectManagement(context.Background(), "198.51.100.11") != nil || calls != 1 {
		t.Fatal("重复解析或错误拒绝")
	}
	if !errors.Is(s.protectManagement(context.Background(), "198.51.100.10"), response.ErrInput) {
		t.Fatal("管理域名解析目标未保护")
	}
	s.resolve = func(context.Context, string, string) ([]netip.Addr, error) { return nil, nil }
	if s.protectManagement(context.Background(), "198.51.100.11") == nil {
		t.Fatal("管理目标解析空值")
	}
	s.management = nil
	c := responseCommand(s, "task_corrupt_directory")
	a, _ := response.ReadAction(c.Payload)
	if err := s.WAL.DB.Update(func(tx *bolt.Tx) error {
		raw, _ := json.Marshal(responseRecord{Action: a, Status: "unknown", RetainUntil: time.Now().UTC().Add(time.Hour)})
		return tx.Bucket([]byte("response_leases")).Put([]byte("different_key"), raw)
	}); err != nil {
		t.Fatal(err)
	}
	if s.maintain(context.Background()) == nil {
		t.Fatal("租约键镜像不符被接受")
	}
	if err := s.WAL.DB.Update(func(tx *bolt.Tx) error { return tx.DeleteBucket([]byte("response_leases")) }); err != nil {
		t.Fatal(err)
	}
	if s.maintain(context.Background()) == nil {
		t.Fatal("不存在的目录被忽略")
	}
	if _, _, err := s.Execute(context.Background(), c); err == nil {
		t.Fatal("不存在的目录仍创建副作用")
	}
}
