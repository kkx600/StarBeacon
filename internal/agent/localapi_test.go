package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/clientip"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/store"
	bolt "go.etcd.io/bbolt"
)

func TestLocalManagementAuthenticationNetworkConfigurationAndStorageFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "local.db")
	wal, err := OpenWAL(path, "tenant_local", "sensor_local", "registration_local", 4*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	defer wal.Close()
	identity, err := NewLocalIdentity(wal, "local-test-password")
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	policy, err := clientip.Parse("127.0.0.1/32,::1/128")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(httpapi.MiddlewareWithClientIP(mux, policy))
	defer server.Close()
	auth := httpapi.NewAuth(identity, nil, server.URL, "local_test_session", false)
	mux.Handle("/", LocalHandler(wal, auth, path))
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar, Timeout: 5 * time.Second}
	csrf := ""
	request := func(method, path, body string, status int) []byte {
		t.Helper()
		r, err := http.NewRequest(method, server.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Origin", server.URL)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", csrf)
		r.Header.Set("X-Real-IP", "192.0.2.11")
		r.Header.Set("User-Agent", "StarBeacon采集器验收")
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		data, err := io.ReadAll(io.LimitReader(response.Body, 65537))
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != status {
			t.Fatalf("%s %s：%d，期望 %d；%s", method, path, response.StatusCode, status, data)
		}
		if response.Header.Get("X-Content-Type-Options") != "nosniff" {
			t.Fatal("本地接口缺少内容类型保护")
		}
		return data
	}
	for _, path := range []string{"/api/local/v1/network/interfaces", "/api/local/v1/capture-config", "/api/local/v1/health", "/api/local/v1/identity"} {
		request("GET", path, "", 401)
	}
	request("POST", "/api/local/v1/auth/login", `{"username":"unknown","password":"local-test-password"}`, 401)
	request("POST", "/api/local/v1/auth/login", `{"username":"admin","password":"wrong"}`, 401)
	login := func() {
		raw := request("POST", "/api/local/v1/auth/login", `{"username":"admin","password":"local-test-password"}`, 200)
		var principal model.Principal
		if err := json.Unmarshal(raw, &principal); err != nil {
			t.Fatal(err)
		}
		if principal.TenantID != "tenant_local" || principal.Role != "admin" || principal.CSRF == "" {
			t.Fatal("本地身份或防伪令牌错误")
		}
		csrf = principal.CSRF
	}
	login()
	request("GET", "/api/local/v1/auth/me", "", 200)
	var interfaces struct {
		Items []NetworkInterface `json:"items"`
	}
	if err := json.Unmarshal(request("GET", "/api/local/v1/network/interfaces", "", 200), &interfaces); err != nil {
		t.Fatal(err)
	}
	if len(interfaces.Items) == 0 {
		t.Fatal("本机网卡列表为空")
	}
	for _, item := range interfaces.Items {
		if item.Index <= 0 || item.Name == "" || item.MTU <= 0 || item.Addresses == nil {
			t.Fatal("实际网卡信息不完整", item)
		}
	}
	request("GET", "/api/local/v1/health", "", 200)
	request("GET", "/api/local/v1/identity?extra=1", "", 400)
	var identityStatus struct {
		Mode   string `json:"mode"`
		Sensor string `json:"sensor_id"`
	}
	if err := json.Unmarshal(request("GET", "/api/local/v1/identity", "", 200), &identityStatus); err != nil || identityStatus.Mode != "static" || identityStatus.Sensor != "sensor_local" {
		t.Fatal("本机静态身份回执不符", err)
	}
	initial := request("GET", "/api/local/v1/capture-config", "", 200)
	if !strings.Contains(string(initial), `"interfaces":[]`) || !strings.Contains(string(initial), `"not_applied"`) {
		t.Fatal("初始目标不应宣称捕获已生效", string(initial))
	}
	validCSRF := csrf
	csrf = "wrong"
	request("PUT", "/api/local/v1/capture-config", `{"interfaces":[]}`, 403)
	csrf = validCSRF
	for _, bad := range []string{`{}`, `{"interfaces":null}`, `{"interfaces":"eth0"}`, `{"interfaces":[],"command":"danger"}`, `{"interfaces":["missing-interface"]}`} {
		request("PUT", "/api/local/v1/capture-config", bad, 400)
	}
	tooMany, _ := json.Marshal(map[string]any{"interfaces": make([]string, 17)})
	request("PUT", "/api/local/v1/capture-config", string(tooMany), 400)
	for _, item := range interfaces.Items {
		if item.Loopback {
			raw, _ := json.Marshal(map[string]any{"interfaces": []string{item.Name}})
			request("PUT", "/api/local/v1/capture-config", string(raw), 400)
		}
		if item.Up && !item.Loopback {
			duplicate, _ := json.Marshal(map[string]any{"interfaces": []string{item.Name, item.Name}})
			request("PUT", "/api/local/v1/capture-config", string(duplicate), 400)
			valid, _ := json.Marshal(map[string]any{"interfaces": []string{item.Name}})
			request("PUT", "/api/local/v1/capture-config", string(valid), 200)
			break
		}
	}
	request("PUT", "/api/local/v1/capture-config", `{"interfaces":[]}`, 200)
	saved := request("GET", "/api/local/v1/capture-config", "", 200)
	if !strings.Contains(string(saved), `"not_applied"`) || !strings.Contains(string(saved), `"updated_at"`) {
		t.Fatal("配置没有持久化或错误宣称生效")
	}
	copy, err := wal.LocalConfig()
	if err != nil {
		t.Fatal(err)
	}
	copy[0] = '!'
	unchanged, err := wal.LocalConfig()
	if err != nil || unchanged[0] != '{' {
		t.Fatal("响应字节引用污染了持久化配置", err)
	}
	var loginAudits, configureAudits int
	if err := wal.DB.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("local_audits")).ForEach(func(_, value []byte) error {
			var entry LocalAudit
			if err := json.Unmarshal(value, &entry); err != nil {
				return err
			}
			if entry.ExpiresAt.IsZero() || entry.ExpiresAt.Before(entry.CreatedAt.AddDate(0, 0, 179)) {
				t.Error("审计缺少默认留存期限")
			}
			if entry.SourceIP != "192.0.2.11" || entry.UserAgent != "StarBeacon采集器验收" || entry.RequestID == "" {
				t.Error("本机审计未保存可信客户端与请求来源")
			}
			if entry.Action == "login" {
				loginAudits++
				if entry.Success == nil {
					t.Error("登录审计没有验证结果")
				}
			}
			if entry.Action == "capture.configure" {
				configureAudits++
				if entry.RequestID == "" || entry.Username != "admin" {
					t.Error("配置审计没有调用身份与请求标识")
				}
			}
			return nil
		})
	}); err != nil {
		t.Fatal(err)
	}
	if loginAudits != 3 || configureAudits < 1 {
		t.Fatal("配置或失败登录没有审计", loginAudits, configureAudits)
	}
	request("POST", "/api/local/v1/auth/logout", `{}`, 200)
	request("GET", "/api/local/v1/auth/me", "", 401)
	request("GET", "/api/local/v1/capture-config", "", 401)
	login()
	if err := wal.Close(); err != nil {
		t.Fatal(err)
	}
	request("GET", "/readyz", "", 503)
	request("GET", "/healthz", "", 200)
	request("GET", "/api/local/v1/capture-config", "", 503)
	request("PUT", "/api/local/v1/capture-config", `{"interfaces":[]}`, 503)
	request("POST", "/api/local/v1/auth/login", `{"username":"admin","password":"local-test-password"}`, 503)
}

func TestLocalSessionQuotaExpiryRevocationAndAuditTransaction(t *testing.T) {
	wal, err := OpenWAL(filepath.Join(t.TempDir(), "sessions.db"), "tenant_test", "sensor_test", "reg_test", 4*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	defer wal.Close()
	if _, err = NewLocalIdentity(wal, strings.Repeat("x", 73)); err == nil {
		t.Fatal("接受了超过密码库上限的密码")
	}
	identity, err := NewLocalIdentity(wal, "test-password")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	u, _, err := identity.Password(ctx, "admin")
	if err != nil {
		t.Fatal(err)
	}
	tokens := []string{}
	for range 32 {
		token, csrf, err := identity.CreateSession(ctx, u)
		if err != nil || csrf == "" {
			t.Fatal("正常会话创建失败", err)
		}
		tokens = append(tokens, token)
	}
	if _, _, err = identity.CreateSession(ctx, u); err == nil {
		t.Fatal("超出本机会话上限仍然创建会话")
	}
	identity.mu.Lock()
	expired := identity.sessions[store.Hash(tokens[0])]
	expired.Expiry = time.Now().Add(-time.Second)
	identity.sessions[store.Hash(tokens[0])] = expired
	identity.mu.Unlock()
	if _, err = identity.Session(ctx, tokens[0]); !errors.Is(err, model.ErrUnauthenticated) {
		t.Fatal("过期会话仍可读取", err)
	}
	if _, _, err = identity.CreateSession(ctx, u); err != nil {
		t.Fatal("过期会话未释放额度", err)
	}
	if err = identity.DeleteSession(ctx, tokens[1]); err != nil {
		t.Fatal(err)
	}
	if _, err = identity.Session(ctx, tokens[1]); !errors.Is(err, model.ErrUnauthenticated) {
		t.Fatal("退出后会话仍然有效", err)
	}
	previous := []byte(`{"interfaces":[],"status":"not_applied"}`)
	if err = wal.SaveLocalConfig(previous, "admin", "request_previous"); err != nil {
		t.Fatal(err)
	}
	if err = wal.DB.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte("local_audits")).Put(key(0), []byte(`{"broken":`)) }); err != nil {
		t.Fatal(err)
	}
	if err = wal.SaveLocalConfig([]byte(`{"interfaces":["different"]}`), "admin", "request_blocked"); err == nil {
		t.Fatal("审计损坏时配置仍然提交")
	}
	saved, err := wal.LocalConfig()
	if err != nil || string(saved) != string(previous) {
		t.Fatal("审计失败没有回滚配置事务", err, string(saved))
	}
}
