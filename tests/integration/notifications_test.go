//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/admin"
	"github.com/kkx600/StarBeacon/internal/bus"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/notify"
	"github.com/kkx600/StarBeacon/internal/outbound"
	"github.com/kkx600/StarBeacon/internal/platform"
	"github.com/kkx600/StarBeacon/internal/secrets"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/worker"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/redis/go-redis/v9"
)

func TestNotificationHTTPDurableOutboxTLSReceiptAndIsolation(t *testing.T) {
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
	options.DB = 10
	cache := redis.NewClient(options)
	defer cache.Close()
	queue, err := bus.OpenNamespace(ctx, os.Getenv("SB_NATS_URL"), store.RandomID("it_notice_"))
	require(t, err)
	defer queue.Close()
	defer func() {
		clean, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		for _, stream := range []string{bus.Alerts, bus.Context, bus.Logs, bus.Quarantine, bus.Indexed} {
			if err := queue.JS.DeleteStream(clean, queue.StreamName(stream)); !errors.Is(err, jetstream.ErrStreamNotFound) {
				require(t, err)
			}
		}
	}()
	require(t, queue.Ensure(ctx, 1, 16*1024*1024))
	tenants := []string{store.RandomID("it_notice_a_"), store.RandomID("it_notice_b_")}
	password := store.Token()
	for _, tenant := range tenants {
		require(t, admin.Bootstrap(ctx, owner, tenant, "通知验收", tenant, password, "admin"))
		defer func() {
			clean, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			require(t, owner.TenantTx(clean, tenant, func(tx pgx.Tx) error {
				for _, table := range []string{"notification_deliveries", "notification_batches", "notification_channel_versions", "notification_channels", "operation_audits", "login_audits"} {
					if _, err := tx.Exec(clean, "DELETE FROM "+table+" WHERE tenant_id=$1", tenant); err != nil {
						return err
					}
				}
				for _, query := range []string{"DELETE FROM sessions WHERE user_id IN(SELECT id FROM users WHERE tenant_id=$1)", "DELETE FROM retention_policies WHERE tenant_id=$1", "DELETE FROM users WHERE tenant_id=$1", "DELETE FROM tenants WHERE id=$1"} {
					if _, err := tx.Exec(clean, query, tenant); err != nil {
						return err
					}
				}
				return nil
			}))
		}()
	}
	require(t, admin.Bootstrap(ctx, owner, tenants[0], "通知验收", tenants[0]+"_viewer", password, "viewer"))
	vault, err := secrets.New(store.Token())
	require(t, err)
	accepted := make(chan notify.Message, 8)
	sink := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var item notify.Message
		if json.NewDecoder(io.LimitReader(r.Body, 65537)).Decode(&item) != nil || item.ID == "" || r.Header.Get("Idempotency-Key") != item.ID || r.Header.Get("Authorization") != "Bearer owned-fixture-token" {
			w.WriteHeader(400)
			return
		}
		accepted <- item
		w.WriteHeader(204)
	}))
	defer sink.Close()
	networks, err := outbound.ParseNetworks("127.0.0.0/8")
	require(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(sink.Certificate())
	policy := outbound.Policy{PrivateNetworks: networks, Roots: roots}
	auth := httpapi.NewAuth(db, cache, "", "it_notifications", false)
	api := &platform.API{DB: db, Auth: auth, Redis: cache, Vault: vault, Outbound: policy}
	server := httptest.NewServer(httpapi.Middleware(api.Handler()))
	defer server.Close()
	auth.Origin = server.URL
	client := func() *http.Client {
		jar, err := cookiejar.New(nil)
		require(t, err)
		return &http.Client{Jar: jar, Timeout: 5 * time.Second}
	}
	request := func(c *http.Client, method, path, csrf, key string, body, target any, status int) {
		t.Helper()
		var input io.Reader
		if body != nil {
			data, err := json.Marshal(body)
			require(t, err)
			input = bytes.NewReader(data)
		}
		r, err := http.NewRequestWithContext(ctx, method, server.URL+path, input)
		require(t, err)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", server.URL)
		r.Header.Set("X-CSRF-Token", csrf)
		r.Header.Set("Idempotency-Key", key)
		response, err := c.Do(r)
		require(t, err)
		defer response.Body.Close()
		data, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		require(t, err)
		if response.StatusCode != status {
			t.Fatalf("%s %s：状态 %d，预期 %d，%s", method, path, response.StatusCode, status, data)
		}
		if strings.Contains(string(data), "owned-fixture-token") || strings.Contains(string(data), "owned-fixture-secret") {
			t.Fatal("API 泄漏了连接凭据")
		}
		if target != nil {
			require(t, json.Unmarshal(data, target))
		}
	}
	login := func(name string) (*http.Client, model.Principal) {
		c := client()
		request(c, "POST", "/api/v1/auth/login", "", "", map[string]string{"username": name, "password": password}, nil, 200)
		var user model.Principal
		request(c, "GET", "/api/v1/auth/me", "", "", nil, &user, 200)
		return c, user
	}
	a, user := login(tenants[0])
	b, other := login(tenants[1])
	viewer, readOnly := login(tenants[0] + "_viewer")
	enabled := true
	change := store.ChannelChange{ID: "channel_owned", Name: "告警通知", Kind: "webhook", Enabled: &enabled, Severities: []string{"high"}, Connection: &notify.Config{Endpoint: sink.URL + "/owned-fixture", Token: "owned-fixture-token", Secret: "owned-fixture-secret"}}
	var saved notify.Channel
	request(a, "POST", "/api/v1/notifications/channels", user.CSRF, "", change, &saved, 200)
	if saved.Revision != 1 || saved.Target != sink.URL {
		t.Fatal("渠道目标脱敏或修订无效")
	}
	request(a, "POST", "/api/v1/notifications/channels", "", "", change, nil, 403)
	request(viewer, "GET", "/api/v1/notifications/channels", "", "", nil, nil, 403)
	request(viewer, "POST", "/api/v1/notifications/channels", readOnly.CSRF, "", change, nil, 403)
	request(b, "POST", "/api/v1/notifications/channels/channel_owned/test", other.CSRF, "key_owned", nil, nil, 404)
	var list struct {
		Items     []notify.Channel `json:"items"`
		Available bool             `json:"available"`
	}
	request(b, "GET", "/api/v1/notifications/channels", "", "", nil, &list, 200)
	if len(list.Items) != 0 || !list.Available {
		t.Fatal("渠道跨租户可见或可用状态错误")
	}
	var ciphertext string
	require(t, owner.TenantTx(ctx, user.TenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT ciphertext FROM notification_channel_versions WHERE tenant_id=$1 AND channel_id='channel_owned' AND revision=1`, user.TenantID).Scan(&ciphertext)
	}))
	if strings.Contains(ciphertext, "owned-fixture") {
		t.Fatal("连接凭据没有加密")
	}
	if _, err := vault.Open(other.TenantID, "notification", change.ID, 1, ciphertext); !errors.Is(err, secrets.ErrUnavailable) {
		t.Fatal("密文跨租户可复用")
	}
	for range 2 {
		request(a, "POST", "/api/v1/notifications/channels/channel_owned/test", user.CSRF, "key_owned", nil, nil, 202)
	}
	var page struct {
		Items []store.Delivery `json:"items"`
		Next  string           `json:"next_cursor"`
	}
	request(a, "GET", "/api/v1/notifications/deliveries", "", "", nil, &page, 200)
	if len(page.Items) != 1 || page.Items[0].State != "queued" {
		t.Fatal("重复测试产生了重复投递")
	}
	lease, err := db.LeaseNotification(ctx, user.TenantID, vault)
	require(t, err)
	outcome := (notify.Sender{Policy: policy}).Send(ctx, lease.Config, lease.Message)
	if outcome.State != "accepted" {
		t.Fatal("真实 HTTPS 目标未确认受理", outcome)
	}
	select {
	case item := <-accepted:
		if !item.Test || item.ID != lease.ID || len(item.Alerts) != 0 {
			t.Fatal("测试通知混入业务告警")
		}
	case <-ctx.Done():
		t.Fatal("没有真实渠道消息")
	}
	wrong := lease
	wrong.Token = store.Token()
	if !errors.Is(db.FinishNotification(ctx, wrong, outcome), store.ErrConflict) {
		t.Fatal("错误租约能写回执")
	}
	require(t, db.FinishNotification(ctx, lease, outcome))
	if !errors.Is(db.FinishNotification(ctx, lease, outcome), store.ErrConflict) {
		t.Fatal("旧回执覆盖当前状态")
	}
	request(a, "GET", "/api/v1/notifications/deliveries?state=accepted", "", "", nil, &page, 200)
	if len(page.Items) != 1 || page.Items[0].Attempts != 1 {
		t.Fatal("投递回执未持久化")
	}
	for _, query := range []string{"state=invalid", "cursor=invalid%2B", "cursor=" + strings.Repeat("a", 257)} {
		request(a, "GET", "/api/v1/notifications/deliveries?"+query, "", "", nil, nil, 400)
	}
	change.ExpectedRevision = 1
	change.Name = "受控通知"
	change.Connection = nil
	request(a, "POST", "/api/v1/notifications/channels", user.CSRF, "", change, &saved, 200)
	request(a, "POST", "/api/v1/notifications/channels", user.CSRF, "", change, nil, 409)
	change.ExpectedRevision = 2
	change.Kind = "feishu"
	request(a, "POST", "/api/v1/notifications/channels", user.CSRF, "", change, nil, 409)
	change.Kind = "webhook"
	alerts := []notify.Summary{{ID: "event_owned", SensorID: "sensor_owned", Severity: "high", Timestamp: time.Now(), RuleID: "100001", RuleName: "实际通知链路"}, {ID: "event_filtered", SensorID: "sensor_owned", Severity: "low", Timestamp: time.Now(), RuleID: "100002", RuleName: "级别过滤"}}
	require(t, queue.Publish(ctx, "sb.indexed", "batch_owned", map[string]any{"tenant_id": user.TenantID, "batch_id": "batch_owned", "alerts": alerts}))
	stream, err := queue.JS.Stream(ctx, queue.StreamName(bus.Indexed))
	require(t, err)
	message, err := stream.GetLastMsgForSubject(ctx, queue.Subject("sb.indexed"))
	require(t, err)
	notifier := &worker.Notifier{DB: db, Vault: vault}
	for range 2 {
		require(t, notifier.Enqueue(ctx, message.Data))
	}
	request(a, "GET", "/api/v1/notifications/deliveries", "", "", nil, &page, 200)
	if len(page.Items) != 2 || page.Items[0].AlertCount != 1 {
		t.Fatal("持久批次没有过滤或去重")
	}
	// 三秒内同渠道不能重复获得执行权限；其他租户始终不可租赁当前任务。
	if _, err := db.LeaseNotification(ctx, other.TenantID, vault); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("跨租户获得投递租约")
	}
	if _, err := db.LeaseNotification(ctx, user.TenantID, vault); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("渠道速率限制被绕过")
	}
	resetRate := func() {
		require(t, owner.TenantTx(ctx, user.TenantID, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE notification_channels SET next_delivery_at=now()-interval '1 second' WHERE tenant_id=$1 AND id='channel_owned'`, user.TenantID)
			return err
		}))
	}
	resetRate()
	lease, err = db.LeaseNotification(ctx, user.TenantID, vault)
	require(t, err)
	if lease.Config.Token != "owned-fixture-token" || len(lease.Message.Alerts) != 1 {
		t.Fatal("保留凭据或级别过滤无效")
	}
	require(t, owner.TenantTx(ctx, user.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE notification_deliveries SET lease_until=now()-interval '1 second' WHERE tenant_id=$1 AND id=$2`, user.TenantID, lease.ID)
		return err
	}))
	if _, err := db.LeaseNotification(ctx, user.TenantID, vault); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("过期执行被再次发送")
	}
	request(a, "GET", "/api/v1/notifications/deliveries?state=uncertain", "", "", nil, &page, 200)
	if len(page.Items) != 1 || page.Items[0].ID != lease.ID {
		t.Fatal("空队列回滚了过期租约的处理")
	}
	current := page.Items[0]
	request(a, "POST", "/api/v1/notifications/deliveries/"+current.ID+"/retry", user.CSRF, "", map[string]any{"expected_version": current.Version}, nil, 400)
	request(a, "POST", "/api/v1/notifications/deliveries/"+current.ID+"/retry", user.CSRF, "", map[string]any{"expected_version": current.Version - 1, "acknowledge_duplicates": true}, nil, 409)
	request(a, "POST", "/api/v1/notifications/deliveries/"+current.ID+"/retry", user.CSRF, "", map[string]any{"expected_version": current.Version, "acknowledge_duplicates": true}, nil, 202)
	resetRate()
	lease, err = db.LeaseNotification(ctx, user.TenantID, vault)
	require(t, err)
	require(t, db.FinishNotification(ctx, lease, notify.Outcome{State: "uncertain", Code: "acknowledgment_lost"}))
	// 配置变更撤销尚未执行的旧修订，不向已改变的接收目标发送旧任务。
	require(t, db.EnqueueNotifications(ctx, user.TenantID, "batch_cancelled", alerts, vault, ""))
	change.Name = "渠道静默"
	request(a, "POST", "/api/v1/notifications/channels", user.CSRF, "", change, &saved, 200)
	resetRate()
	if _, err := db.LeaseNotification(ctx, user.TenantID, vault); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("配置修订后旧批次仍被执行")
	}
	request(a, "GET", "/api/v1/notifications/deliveries?state=cancelled", "", "", nil, &page, 200)
	if len(page.Items) != 1 {
		t.Fatal("旧修订没有保留取消记录")
	}
	change.ExpectedRevision = 3
	enabled = false
	request(a, "POST", "/api/v1/notifications/channels", user.CSRF, "", change, &saved, 200)
	for index := range 23 {
		batch := store.RandomID("batch_page_")
		require(t, db.EnqueueNotifications(ctx, user.TenantID, batch, alerts, vault, ""))
		require(t, owner.TenantTx(ctx, user.TenantID, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE notification_deliveries d SET created_at=now()+make_interval(secs=>$2) FROM notification_batches b WHERE b.tenant_id=d.tenant_id AND b.id=d.batch_id AND b.upstream_batch_id=$1 AND d.tenant_id=$3`, batch, index, user.TenantID)
			return err
		}))
	}
	request(a, "GET", "/api/v1/notifications/deliveries?state=suppressed", "", "", nil, &page, 200)
	if len(page.Items) != 20 || page.Next == "" {
		t.Fatal("推送日志没有生成游标页")
	}
	seen := map[string]bool{}
	prior := page.Items[0].CreatedAt
	for _, item := range page.Items {
		if item.CreatedAt.After(prior) {
			t.Fatal("日志未按时间降序")
		}
		seen[item.ID] = true
		prior = item.CreatedAt
	}
	request(a, "GET", "/api/v1/notifications/deliveries?state=suppressed&cursor="+url.QueryEscape(page.Next), "", "", nil, &page, 200)
	if len(page.Items) != 3 || page.Next != "" {
		t.Fatal("日志翻页遗漏或重复")
	}
	for _, item := range page.Items {
		if seen[item.ID] || item.CreatedAt.After(prior) {
			t.Fatal("游标页重复或乱序")
		}
		prior = item.CreatedAt
	}
	var wrongRetention, audits int
	require(t, owner.TenantTx(ctx, user.TenantID, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM notification_batches WHERE tenant_id=$1 AND expires_at-created_at<>interval '180 days'`, user.TenantID).Scan(&wrongRetention); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT count(*) FROM operation_audits WHERE tenant_id=$1 AND action LIKE 'notifications.%'`, user.TenantID).Scan(&audits)
	}))
	if wrongRetention != 0 || audits != 7 {
		t.Fatal("默认留存或操作审计无效", wrongRetention, audits)
	}
	t.Log("真实 HTTP、PostgreSQL RLS、Redis 会话、NATS 持久批次、HTTPS 渠道、凭据加密、回执租约、幂等、抑制、人工重试、时间游标与 180 天留存通过")
}
