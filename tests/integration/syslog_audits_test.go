//go:build integration

package integration

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/bus"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/notify"
	"github.com/kkx600/StarBeacon/internal/outbound"
	"github.com/kkx600/StarBeacon/internal/platform"
	"github.com/kkx600/StarBeacon/internal/secrets"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/worker"
)

type auditSinkMessage struct {
	notify.Message
	Sequence int `json:"sequence"`
	Total    int `json:"total"`
}

// 接收器以真实 TLS、字节计数分帧和 fsync 保存受控日志；平台仍不假定远端落盘确认。
func syslogAuditSink(t *testing.T) (string, outbound.Policy, <-chan auditSinkMessage, string) {
	t.Helper()
	certificate := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(certificate.Close)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", certificate.TLS)
	require(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(certificate.Certificate())
	networks, err := outbound.ParseNetworks("127.0.0.0/8")
	require(t, err)
	messages := make(chan auditSinkMessage, 64)
	done := make(chan struct{})
	failures := make(chan error, 1)
	path := filepath.Join(t.TempDir(), "received.jsonl")
	go func() {
		defer close(done)
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			failures <- err
			return
		}
		defer file.Close()
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
			reader := bufio.NewReader(connection)
			prefix, err := reader.ReadString(' ')
			size, parseErr := strconv.Atoi(strings.TrimSpace(prefix))
			if err != nil || parseErr != nil || size < 1 || size > 8192 {
				connection.Close()
				failures <- errors.New("日志分帧大小无效")
				return
			}
			raw := make([]byte, size)
			_, err = io.ReadFull(reader, raw)
			connection.Close()
			parts := strings.SplitN(string(raw), " ", 8)
			var item auditSinkMessage
			if err != nil || len(parts) != 8 || !strings.HasPrefix(parts[7], "\xef\xbb\xbf") || json.Unmarshal([]byte(strings.TrimPrefix(parts[7], "\xef\xbb\xbf")), &item) != nil || len(item.Logs) != 1 || parts[5] != item.Logs[0].Stream {
				failures <- errors.New("审计帧内容无效")
				return
			}
			data, err := json.Marshal(item)
			if err == nil {
				_, err = file.Write(append(data, '\n'))
			}
			if err == nil {
				err = file.Sync()
			}
			if err != nil {
				failures <- err
				return
			}
			messages <- item
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		select {
		case <-done:
		case <-time.After(6 * time.Second):
			t.Error("受控日志接收器未结束")
		}
		select {
		case err := <-failures:
			t.Error(err)
		default:
		}
	})
	return listener.Addr().String(), outbound.Policy{PrivateNetworks: networks, Roots: roots}, messages, path
}

func TestSyslogAuditHTTPWorkerTLSDeliveryAndTenantIsolation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f, u, b, password := accountFixture(t, ctx)
	endpoint, policy, received, path := syslogAuditSink(t)
	vault, err := secrets.New(store.Token())
	require(t, err)
	a := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime, Vault: vault, Outbound: policy}, u.Username, password)
	enabled := true
	change := store.ChannelChange{ID: "syslog_owned", Name: "租户审计归档", Kind: "syslog_tls", Enabled: &enabled, Severities: []string{}, Streams: []string{"operations", "logins"}, Connection: &notify.Config{Endpoint: endpoint}}
	var saved notify.Channel
	a.request("POST", "/notifications/channels", "", change, &saved, 200)
	if len(saved.Streams) != 2 || saved.Streams[0] != "operations" {
		t.Fatal("公开日志范围不完整")
	}
	a.login(u.Username, password)
	metadata := model.WithRequestMetadata(ctx, model.RequestMetadata{RequestID: "audit_fixture_owned", SourceIP: "192.0.2.11", UserAgent: "审计验收"})
	require(t, f.Runtime.LoginAudit(metadata, u, false))
	require(t, f.Runtime.LoginAudit(metadata, b, true))
	require(t, f.Runtime.TenantTx(metadata, u.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(metadata, `INSERT INTO operation_audits(tenant_id,user_id,action,object_id,request_id,source_ip,user_agent,reason) VALUES($1,$2,'fixture.owned.action','owned_object','audit_fixture_owned','192.0.2.11','审计验收',$3)`, u.TenantID, u.ID, "private-operation-reason")
		return err
	}))
	queue, err := bus.OpenNamespace(ctx, os.Getenv("SB_NATS_URL"), store.RandomID("it_audit_notice_"))
	require(t, err)
	defer queue.Close()
	require(t, queue.Ensure(ctx, 1, 16*1024*1024))
	defer func() {
		clean, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		for _, stream := range []string{bus.Alerts, bus.Context, bus.Quarantine, bus.Indexed} {
			require(t, queue.JS.DeleteStream(clean, queue.StreamName(stream)))
		}
	}()
	notifier := &worker.Notifier{Bus: queue, DB: f.Runtime, Vault: vault, Sender: notify.Sender{Policy: policy}}
	run, stop := context.WithCancel(ctx)
	finished := make(chan error, 1)
	go func() { finished <- notifier.Run(run) }()
	defer func() {
		stop()
		select {
		case err := <-finished:
			require(t, err)
		case <-time.After(8 * time.Second):
			t.Error("审计投递进程未结束")
		}
	}()
	seen := map[string]bool{}
	operation, logins := 0, 0
	for len(seen) < 4 {
		select {
		case item := <-received:
			log := item.Logs[0]
			if item.TenantID != u.TenantID || item.ID == "" || len(item.Alerts) != 0 || item.Sequence != 1 || item.Total != 1 || log.ID == "" || seen[log.Stream+"/"+log.ID] {
				t.Fatal("重复投递、越权或不完整审计")
			}
			seen[log.Stream+"/"+log.ID] = true
			if log.Stream == "operations" {
				operation++
			} else if log.Stream == "logins" {
				logins++
				if log.Success == nil || log.Phase != "password_verification" {
					t.Fatal("凭据验证被误报为完成登录")
				}
			}
			if log.RequestID == "audit_fixture_owned" && (log.SourceIP != "192.0.2.11" || log.UserAgent != "审计验收") {
				t.Fatal("审计来源丢失")
			}
		case <-ctx.Done():
			t.Fatal("未收到真实审计投递")
		}
	}
	if operation != 2 || logins != 2 {
		t.Fatal("业务操作与验证结果没有独立投递")
	}
	eventually(t, ctx, "审计回执未持久化", func() bool {
		items, _, err := f.Runtime.NotificationDeliveries(ctx, u.TenantID, "", "")
		if err != nil || len(items) != 4 {
			return false
		}
		for _, d := range items {
			if d.State != "transport_written" || d.RecordCount != 1 || d.AlertCount != 0 || d.Stream == "alerts" {
				return false
			}
		}
		return true
	})
	var page struct {
		Items []store.Delivery `json:"items"`
	}
	a.request("GET", "/notifications/deliveries", "", nil, &page, 200)
	if len(page.Items) != 4 {
		t.Fatal("推送列表没有包含审计")
	}
	foreign, _, err := f.Runtime.NotificationDeliveries(ctx, b.TenantID, "", "")
	require(t, err)
	if len(foreign) != 0 {
		t.Fatal("跨租户看到审计投递")
	}
	data, err := os.ReadFile(path)
	require(t, err)
	if len(strings.Split(strings.TrimSpace(string(data)), "\n")) != 4 || strings.Contains(string(data), password) || strings.Contains(string(data), "private-operation-reason") || strings.Contains(string(data), b.TenantID) {
		t.Fatal("日志外发越权或包含非许可字段")
	}
	require(t, f.Runtime.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		var minimum, maximum float64
		err := tx.QueryRow(ctx, `SELECT min(extract(epoch FROM expires_at-created_at)),max(extract(epoch FROM expires_at-created_at)) FROM notification_batches WHERE tenant_id=$1`, u.TenantID).Scan(&minimum, &maximum)
		if err == nil && (minimum < 179*86400 || maximum > 180*86400+2) {
			return errors.New("审计外发默认保留期错误")
		}
		return err
	}))
	select {
	case <-received:
		t.Fatal("审计执行完成后重复发送")
	case <-time.After(350 * time.Millisecond):
	}
}

func TestSyslogAuditAtomicRollbackRoutingRevisionsAndBounds(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f, u, b, password := accountFixture(t, ctx)
	vault, err := secrets.New(store.Token())
	require(t, err)
	policy := outbound.Policy{}
	enabled := true
	change := store.ChannelChange{ID: "syslog_owned", Name: "操作日志", Kind: "syslog_tls", Enabled: &enabled, Streams: []string{"operations"}, Severities: []string{}, Connection: &notify.Config{Endpoint: "logs.example.invalid:6514"}}
	saved, err := f.Runtime.SaveNotificationChannel(ctx, u, change, vault, policy, "channel_owned_create")
	require(t, err)
	count := func(tenant string) int {
		t.Helper()
		var n int
		require(t, f.Runtime.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, "SELECT count(*) FROM notification_batches WHERE tenant_id=$1", tenant).Scan(&n)
		}))
		return n
	}
	if count(u.TenantID) != 1 {
		t.Fatal("配置保存没有与审计同事务提交")
	}
	sentinel := errors.New("owned_rollback")
	err = f.Runtime.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO operation_audits(tenant_id,user_id,action,object_id,request_id) VALUES($1,$2,'fixture.rollback','object_owned','rollback_owned')`, u.TenantID, u.ID); err != nil {
			return err
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) || count(u.TenantID) != 1 {
		t.Fatal("审计事务回滚后遗留投递")
	}
	require(t, f.Runtime.LoginAudit(ctx, u, true))
	require(t, f.Runtime.LoginAudit(ctx, b, true))
	require(t, f.Runtime.LoginAudit(ctx, model.Principal{Username: "unknown_owned"}, false))
	if count(u.TenantID) != 1 || count(b.TenantID) != 0 {
		t.Fatal("未订阅或归属未知的登录被外发")
	}
	for _, invalid := range [][]string{{}, {"operations", "operations"}, {"unknown"}} {
		bad := change
		bad.Streams = invalid
		bad.ExpectedRevision = saved.Revision
		if _, err = f.Runtime.SaveNotificationChannel(ctx, u, bad, vault, policy, "invalid_owned"); !errors.Is(err, notify.ErrConfig) {
			t.Fatal("无效日志类别被保存", err)
		}
	}
	ordinary := change
	ordinary.ID = "webhook_owned"
	ordinary.Kind = "webhook"
	ordinary.Connection = &notify.Config{Endpoint: "https://logs.example.invalid"}
	if _, err = f.Runtime.SaveNotificationChannel(ctx, u, ordinary, vault, policy, "ordinary_owned"); !errors.Is(err, notify.ErrConfig) {
		t.Fatal("普通办公渠道开启审计")
	}
	change.ExpectedRevision = saved.Revision
	change.Streams = nil
	change.Connection = nil
	saved, err = f.Runtime.SaveNotificationChannel(ctx, u, change, vault, policy, "preserve_owned")
	require(t, err)
	if len(saved.Streams) != 1 || saved.Streams[0] != "operations" {
		t.Fatal("旧调用者清空既有范围")
	}
	for range 1 {
		_, err = f.Runtime.LeaseNotification(ctx, u.TenantID, vault)
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatal("修订变化后原目的未取消", err)
		}
	}
	lease, err := f.Runtime.LeaseNotification(ctx, u.TenantID, vault)
	require(t, err)
	if lease.Message.Logs[0].RequestID != "preserve_owned" {
		t.Fatal("租约读取错误的冻结修订")
	}
	require(t, f.Runtime.FinishNotification(ctx, lease, notify.Outcome{State: "retry", Code: "connection_failed"}))
	noCSRF := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime, Vault: vault, Outbound: policy}, u.Username, password)
	noCSRF.csrf = ""
	noCSRF.request("POST", "/notifications/channels", "", change, nil, 403)
	require(t, f.Runtime.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE retention_policies SET days=7 WHERE tenant_id=$1 AND category='notifications'`, u.TenantID)
		return err
	}))
	require(t, f.Runtime.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO operation_audits(tenant_id,user_id,action,object_id,request_id,user_agent,reason) VALUES($1,$2,'fixture.clip',$3,'clip_owned',$4,'not-for-egress')`, u.TenantID, u.ID, strings.Repeat("中", 1025), "bad\nclient")
		return err
	}))
	require(t, f.Runtime.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		var raw []byte
		var days float64
		if err := tx.QueryRow(ctx, `SELECT message,extract(epoch FROM expires_at-created_at)/86400 FROM notification_batches WHERE tenant_id=$1 AND message->'logs'->0->>'request_id'='clip_owned'`, u.TenantID).Scan(&raw, &days); err != nil {
			return err
		}
		var message notify.Message
		if err := json.Unmarshal(raw, &message); err != nil {
			return err
		}
		if len(message.Logs) != 1 || !message.Logs[0].Truncated || len([]rune(message.Logs[0].ObjectID)) != 1024 || message.Logs[0].UserAgent != "bad client" || days < 6.9 || days > 7.1 || strings.Contains(string(raw), "not-for-egress") {
			return errors.New("有界脱敏与留存不一致")
		}
		return nil
	}))
	// 数据库也拒绝无效类别，不能依赖 HTTP 校验维持来源隔离。
	err = f.Runtime.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE notification_channels SET streams='["operations","operations"]' WHERE tenant_id=$1`, u.TenantID)
		return err
	})
	if err == nil {
		t.Fatal("数据库接受重复类别")
	}
	muted := time.Now().Add(time.Hour)
	change.ExpectedRevision = saved.Revision
	change.MutedUntil = &muted
	saved, err = f.Runtime.SaveNotificationChannel(ctx, u, change, vault, policy, "mute_owned")
	require(t, err)
	require(t, f.Runtime.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		var state string
		err := tx.QueryRow(ctx, `SELECT d.state FROM notification_deliveries d JOIN notification_batches b ON b.tenant_id=d.tenant_id AND b.id=d.batch_id WHERE d.tenant_id=$1 AND b.message->'logs'->0->>'request_id'='mute_owned'`, u.TenantID).Scan(&state)
		if err == nil && state != "suppressed" {
			return fmt.Errorf("静默渠道状态=%s", state)
		}
		return err
	}))
	enabled = false
	change.MutedUntil = nil
	change.ExpectedRevision = saved.Revision
	_, err = f.Runtime.SaveNotificationChannel(ctx, u, change, vault, policy, "disable_owned")
	require(t, err)
	require(t, f.Runtime.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		var state string
		err := tx.QueryRow(ctx, `SELECT d.state FROM notification_deliveries d JOIN notification_batches b ON b.tenant_id=d.tenant_id AND b.id=d.batch_id WHERE d.tenant_id=$1 AND b.message->'logs'->0->>'request_id'='disable_owned'`, u.TenantID).Scan(&state)
		if err == nil && state != "suppressed" {
			return errors.New("停用渠道继续投递")
		}
		return err
	}))
}
