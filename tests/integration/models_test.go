//go:build integration

package integration

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/admin"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/llm"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/outbound"
	"github.com/kkx600/StarBeacon/internal/platform"
	"github.com/kkx600/StarBeacon/internal/secrets"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/redis/go-redis/v9"
)

// 本测试验收真实 HTTP、SDK、PG、Redis 与 TLS 契约，不代表模型通过领域质量评测。
func TestModelConfigurationTLSVerificationIsolationAndBudgets(t *testing.T) {
	if os.Getenv("SB_MODE") != "development" || os.Getenv("SB_MIGRATION_DATABASE_URL") == "" {
		t.Skip("需要独立开发依赖")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	owner, err := store.Open(ctx, os.Getenv("SB_MIGRATION_DATABASE_URL"))
	require(t, err)
	defer owner.Close()
	db, err := store.Open(ctx, os.Getenv("SB_DATABASE_URL"))
	require(t, err)
	defer db.Close()
	require(t, db.VerifyRuntimeRole(ctx))
	options, err := redis.ParseURL(os.Getenv("SB_REDIS_URL"))
	require(t, err)
	options.DB = 15
	cache := redis.NewClient(options)
	defer cache.Close()
	tenants := []string{store.RandomID("it_models_a_"), store.RandomID("it_models_b_")}
	password := store.Token()
	for _, tenant := range tenants {
		require(t, admin.Bootstrap(ctx, owner, tenant, "模型接入验收", tenant, password, "admin"))
		defer func() {
			clean, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			require(t, owner.TenantTx(clean, tenant, func(tx pgx.Tx) error {
				for _, table := range []string{"model_capability_checks", "model_provider_versions", "model_providers", "operation_audits", "login_audits", "retention_policies"} {
					if _, err := tx.Exec(clean, "DELETE FROM "+table+" WHERE tenant_id=$1", tenant); err != nil {
						return err
					}
				}
				for _, query := range []string{"DELETE FROM sessions WHERE user_id IN(SELECT id FROM users WHERE tenant_id=$1)", "DELETE FROM users WHERE tenant_id=$1", "DELETE FROM tenants WHERE id=$1"} {
					if _, err := tx.Exec(clean, query, tenant); err != nil {
						return err
					}
				}
				return nil
			}))
		}()
	}
	require(t, admin.Bootstrap(ctx, owner, tenants[0], "模型接入验收", tenants[0]+"_viewer", password, "viewer"))
	vault, err := secrets.New(store.Token())
	require(t, err)
	var calls atomic.Int32
	provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var payload map[string]any
		if r.URL.Path != "/v1/responses" || r.Method != "POST" || r.Header.Get("Authorization") != "Bearer owned-model-integration-key" || json.NewDecoder(io.LimitReader(r.Body, 32769)).Decode(&payload) != nil || payload["store"] != false || payload["model"] != "owned-model" || payload["max_output_tokens"] != float64(64) {
			w.WriteHeader(400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"response_owned","object":"response","status":"completed","model":"owned-model","output":[{"type":"message","role":"assistant","id":"message_owned","status":"completed","content":[{"type":"output_text","text":"连接成功。","annotations":[]}]}],"usage":{"input_tokens":3,"output_tokens":4,"total_tokens":7}}`)
	}))
	defer provider.Close()
	networks, err := outbound.ParseNetworks("127.0.0.0/8")
	require(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(provider.Certificate())
	policy := outbound.Policy{PrivateNetworks: networks, Roots: roots}
	auth := httpapi.NewAuth(db, cache, "", "it_model_session", false)
	api := &platform.API{DB: db, Redis: cache, Auth: auth, Vault: vault, Outbound: policy}
	server := httptest.NewServer(httpapi.Middleware(api.Handler()))
	defer server.Close()
	auth.Origin = server.URL
	login := func(username string) (*liveHTTP, model.Principal) {
		jar, err := cookiejar.New(nil)
		require(t, err)
		client := &liveHTTP{t: t, ctx: ctx, client: &http.Client{Jar: jar, Timeout: 5 * time.Second}, origin: server.URL, prefix: "/api/v1"}
		client.login(username, password)
		var user model.Principal
		client.request("GET", "/auth/me", "", nil, &user, 200)
		return client, user
	}
	a, user := login(tenants[0])
	b, other := login(tenants[1])
	viewer, _ := login(tenants[0] + "_viewer")
	change := store.ModelChange{ID: "provider_owned", ReplaceKey: true, Config: llm.Config{Name: "协议验收提供方", Kind: "openai_responses", BaseURL: provider.URL + "/v1", Model: "owned-model", APIKey: "owned-model-integration-key", Enabled: true, MaxOutputTokens: 256, TimeoutSeconds: 5, DailyRequests: 2}}
	var saved llm.Provider
	a.request("POST", "/models/providers", "", change, &saved, 200)
	if saved.Revision != 1 || !saved.HasKey || saved.AllowExternal {
		t.Fatal("模型公开配置不正确", saved)
	}
	public, err := json.Marshal(saved)
	require(t, err)
	if strings.Contains(string(public), change.Config.APIKey) || strings.Contains(string(public), "api_key") {
		t.Fatal("模型 API 回显凭据")
	}
	viewer.request("GET", "/models/providers", "", nil, nil, 403)
	viewer.request("POST", "/models/providers", "", change, nil, 403)
	csrf := a.csrf
	a.csrf = ""
	a.request("POST", "/models/providers", "", change, nil, 403)
	a.csrf = csrf
	a.request("POST", "/models/providers", "", map[string]any{"unknown": true}, nil, 400)
	b.request("POST", "/models/providers/provider_owned/test", "check_cross_tenant", map[string]any{"expected_revision": 1}, nil, 404)
	var list struct {
		Items     []llm.Provider `json:"items"`
		Available bool           `json:"available"`
	}
	b.request("GET", "/models/providers", "", nil, &list, 200)
	if len(list.Items) != 0 || !list.Available {
		t.Fatal("模型跨租户可见或可用状态不正确")
	}
	var ciphertext string
	require(t, owner.TenantTx(ctx, user.TenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT ciphertext FROM model_provider_versions WHERE provider_id=$1 AND revision=1`, change.ID).Scan(&ciphertext)
	}))
	if strings.Contains(ciphertext, change.Config.APIKey) {
		t.Fatal("模型凭据未加密")
	}
	if _, err := vault.Open(other.TenantID, "model", change.ID, 1, ciphertext); !errors.Is(err, secrets.ErrUnavailable) {
		t.Fatal("密文可跨租户解密")
	}
	if _, err := vault.Open(user.TenantID, "model", change.ID, 2, ciphertext); !errors.Is(err, secrets.ErrUnavailable) {
		t.Fatal("密文可跨修订复用")
	}
	var check llm.Check
	for range 2 {
		a.request("POST", "/models/providers/provider_owned/test", "model_check_one", map[string]any{"expected_revision": 1}, &check, 200)
	}
	if calls.Load() != 1 || check.State != "succeeded" || check.Result.Text != "" || check.Result.Usage == nil || check.Result.Usage.TotalTokens != 7 {
		t.Fatal("幂等验证、正文留存或用量错误", check, calls.Load())
	}
	var retention float64
	var audits int
	require(t, owner.TenantTx(ctx, user.TenantID, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT extract(epoch FROM(expires_at-created_at))/86400 FROM model_capability_checks WHERE id=$1`, check.ID).Scan(&retention); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT count(*) FROM operation_audits WHERE action='models.provider.test'`).Scan(&audits)
	}))
	if retention < 179.999 || retention > 180.001 || audits != 1 {
		t.Fatal("默认留存或幂等审计错误", retention, audits)
	}
	a.request("POST", "/models/providers", "", change, nil, 409)
	change.ExpectedRevision = 1
	change.ReplaceKey = false
	change.Config.APIKey = ""
	a.request("POST", "/models/providers", "", change, &saved, 200)
	if saved.Revision != 2 || !saved.HasKey {
		t.Fatal("保留凭据失败", saved)
	}
	a.request("POST", "/models/providers/provider_owned/test", "model_check_one", map[string]any{"expected_revision": 2}, nil, 409)
	a.request("POST", "/models/providers/provider_owned/test", "model_check_stale", map[string]any{"expected_revision": 1}, nil, 409)
	a.request("POST", "/models/providers/provider_owned/test", "model_check_two", map[string]any{"expected_revision": 2}, &check, 200)
	a.request("POST", "/models/providers/provider_owned/test", "model_check_over_quota", map[string]any{"expected_revision": 2}, nil, 429)
	if calls.Load() != 2 {
		t.Fatal("预算拒绝后仍调用提供方", calls.Load())
	}
	change.ExpectedRevision = 2
	change.Config.Enabled = false
	a.request("POST", "/models/providers", "", change, &saved, 200)
	a.request("POST", "/models/providers/provider_owned/test", "model_check_disabled", map[string]any{"expected_revision": 3}, nil, 409)
	change.ExpectedRevision = 3
	change.Config.Enabled = true
	change.Config.BaseURL = provider.URL + "/other"
	a.request("POST", "/models/providers", "", change, nil, 400)
	change.Config.BaseURL = provider.URL + "/v1"
	change.ReplaceKey = true
	change.Config.APIKey = ""
	a.request("POST", "/models/providers", "", change, &saved, 200)
	if saved.HasKey {
		t.Fatal("清除凭据未生效")
	}
	// 不访问提供方，验证持久租约失联、重复提交与旧回执的边界。
	change.ID = "provider_lease"
	change.ExpectedRevision = 0
	change.Config.APIKey = "owned-model-integration-key"
	change.Config.DailyRequests = 100
	a.request("POST", "/models/providers", "", change, &saved, 200)
	lease, err := db.StartModelCheck(ctx, user, change.ID, "lease_owned", 1, vault, "req_lease")
	require(t, err)
	if !lease.Execute {
		t.Fatal("首次验证没有取得执行资格")
	}
	if lease.Result.DurationMS != nil {
		t.Fatal("尚未返回的验证耗时不能补为零")
	}
	if _, err := db.StartModelCheck(ctx, user, change.ID, "lease_other", 1, vault, "req_lease"); !errors.Is(err, store.ErrModelQuota) {
		t.Fatal("同提供方并发验证越过预算", err)
	}
	require(t, owner.TenantTx(ctx, user.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE model_capability_checks SET deadline=now()-interval '1 second' WHERE id=$1`, lease.ID)
		return err
	}))
	duplicate, err := db.StartModelCheck(ctx, user, change.ID, "lease_owned", 1, vault, "req_lease")
	require(t, err)
	if duplicate.Execute || duplicate.State != "uncertain" {
		t.Fatal("失联验证被再次调用或错误标记", duplicate.Check)
	}
	if duplicate.Result.DurationMS != nil {
		t.Fatal("失联验证没有耗时证据，不能补为零")
	}
	if _, err := db.FinishModelCheck(ctx, user.TenantID, lease, llm.Result{State: "succeeded", Code: "completed"}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("旧回执覆盖失联状态", err)
	}
	if _, err := db.FinishModelCheck(ctx, other.TenantID, lease, llm.Result{State: "succeeded", Code: "completed"}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("跨租户回写验证状态", err)
	}
	a.request("GET", "/models/providers", "", nil, &list, 200)
	if len(list.Items) != 2 {
		t.Fatal("模型配置列表不完整")
	}
	t.Log("模型配置加密、真实 TLS/SDK 请求、修订、幂等、预算、失联状态、审计、默认 180 天及租户／角色隔离通过；未将协议夹具计为真实模型领域评测")
}
