//go:build integration

package integration

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/admin"
	"github.com/kkx600/StarBeacon/internal/bus"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/detectionquality"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/notify"
	"github.com/kkx600/StarBeacon/internal/outbound"
	"github.com/kkx600/StarBeacon/internal/platform"
	"github.com/kkx600/StarBeacon/internal/qualityevent"
	"github.com/kkx600/StarBeacon/internal/secrets"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/transport"
	"github.com/kkx600/StarBeacon/internal/worker"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/redis/go-redis/v9"
)

// 本用例的统计是协议夹具；实际 AF_PACKET 统计链路由独立原生捕获用例验证。
func qualityFixture(t *testing.T, run string, changes map[string]uint64) detectionquality.Report {
	t.Helper()
	now := time.Now().UTC().Add(-10 * time.Second)
	var tracker detectionquality.Tracker
	tracker.Start(run, strings.Repeat("a", 64), now)
	for i := range 2 {
		stats := map[string]any{}
		for _, counter := range tracker.Snapshot(now, true).Counters {
			parts := strings.Split(counter.Key, ".")
			nested := stats
			for _, part := range parts[:len(parts)-1] {
				if nested[part] == nil {
					nested[part] = map[string]any{}
				}
				nested = nested[part].(map[string]any)
			}
			value := uint64(0)
			if i == 1 {
				value = changes[counter.Key]
			}
			nested[parts[len(parts)-1]] = value
		}
		at := now.Add(time.Duration(i*5+1) * time.Second)
		raw, _ := json.Marshal(map[string]any{"event_type": "stats", "timestamp": at.Format(time.RFC3339Nano), "stats": stats})
		tracker.Observe(raw, at)
	}
	r := tracker.Snapshot(time.Now().UTC(), true)
	require(t, r.Validate())
	return r
}

// 通过真实镜像网卡、原生 noalert 规则和五秒总计数触发；禁止向 EVE 注入统计。
func verifyNativeQualityEvent(t *testing.T, ctx context.Context, api *liveHTTP, es *store.Elasticsearch, id transport.SensorIdentity, accepted <-chan notify.Message, endpoint string) {
	t.Helper()
	enabled := true
	api.request("POST", "/notifications/channels", "", store.ChannelChange{ID: "channel_live_quality", Name: "检测质量事件", Kind: "webhook", Enabled: &enabled, Streams: []string{"quality"}, Severities: []string{}, Connection: &notify.Config{Endpoint: endpoint}}, nil, 200)
	started := time.Now().UTC()
	traffic := &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, Timeout: 3 * time.Second}
	r, err := http.NewRequestWithContext(ctx, "GET", os.Getenv("SB_TEST_CAPTURE_ENDPOINT")+"/starbeacon/quality", nil)
	require(t, err)
	response, err := traffic.Do(r)
	require(t, err)
	require(t, response.Body.Close())
	if response.StatusCode != 200 {
		t.Fatal("质量观测流量未成功响应")
	}
	index, err := contract.IndexName(id.TenantID, "context", started.Format("2006-01-02"))
	require(t, err)
	params := url.Values{"start": {started.Add(-time.Minute).Format(time.RFC3339Nano)}, "end": {started.Add(time.Minute).Format(time.RFC3339Nano)}, "sensor_id": {id.SensorID}, "registration_id": {id.RegistrationID}}
	var found qualityevent.Event
	eventually(t, ctx, "真实 noalert 原生统计到持久质量历史", func() bool {
		response, err := es.API.Indices.Refresh(es.API.Indices.Refresh.WithContext(ctx), es.API.Indices.Refresh.WithIndex(index))
		if err != nil {
			return false
		}
		response.Body.Close()
		var page store.QualityPage
		api.request("GET", "/sensors/quality-events?"+params.Encode(), "", nil, &page, 200)
		for _, e := range page.Items {
			if slices.Contains(e.Signal.Reasons, "detect.alerts_suppressed") && e.Report.State == "observed" && e.Report.Policy.State == "policy_applied" {
				require(t, e.Validate())
				found = e
				return true
			}
		}
		return false
	})
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	for {
		select {
		case m := <-accepted:
			if len(m.Quality) == 1 && m.Quality[0].ID == found.ID {
				if len(m.Alerts) != 0 || m.TenantID != id.TenantID || m.Quality[0].SensorID != id.SensorID {
					t.Fatal("原生质量通知身份不一致")
				}
				t.Logf("真实网卡 noalert → 原生统计 → 心跳 → 持久待办 → ES → 渠道受理 %.3fs；采样区间事件 %s", time.Since(started).Seconds(), found.ID)
				return
			}
		case <-deadline.C:
			t.Fatal("原生质量事件未完成通知闭环")
		case <-ctx.Done():
			t.Fatal("原生质量验证达到用例期限")
		}
	}
}

func TestQualityEventsDurableHeartbeatIndexingNotificationsAndIsolation(t *testing.T) {
	if os.Getenv("SB_MODE") != "development" || os.Getenv("SB_MIGRATION_DATABASE_URL") == "" {
		t.Skip("需要专属 Docker 依赖")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	owner, err := store.Open(ctx, os.Getenv("SB_MIGRATION_DATABASE_URL"))
	require(t, err)
	defer owner.Close()
	db, err := store.Open(ctx, os.Getenv("SB_DATABASE_URL"))
	require(t, err)
	defer db.Close()
	require(t, db.VerifyRuntimeRole(ctx))
	es, err := store.OpenES(os.Getenv("SB_ES_URL"), os.Getenv("SB_ES_API_KEY"))
	require(t, err)
	queue, err := bus.OpenNamespace(ctx, os.Getenv("SB_NATS_URL"), store.RandomID("it_quality_"))
	require(t, err)
	defer queue.Close()
	require(t, queue.Ensure(ctx, 1, 16*1024*1024))
	defer func() {
		clean, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		for _, name := range []string{bus.Alerts, bus.Context, bus.Quarantine, bus.Indexed} {
			if err := queue.JS.DeleteStream(clean, queue.StreamName(name)); !errors.Is(err, jetstream.ErrStreamNotFound) {
				require(t, err)
			}
		}
	}()
	opts, err := redis.ParseURL(os.Getenv("SB_REDIS_URL"))
	require(t, err)
	opts.DB = 14
	cache := redis.NewClient(opts)
	defer cache.Close()
	tenants := []string{store.RandomID("it_quality_a_"), store.RandomID("it_quality_b_")}
	password := store.Token()
	for _, tenant := range tenants {
		require(t, admin.Bootstrap(ctx, owner, tenant, "质量事件验收", tenant, password, "admin"))
		defer func() {
			clean, stop := context.WithTimeout(context.Background(), 10*time.Second)
			defer stop()
			require(t, owner.TenantTx(clean, tenant, func(tx pgx.Tx) error {
				for _, table := range []string{"sensor_quality_outbox", "sensor_quality_cursors", "notification_deliveries", "notification_batches", "notification_channel_versions", "notification_channels", "operation_audits", "login_audits", "sensors", "retention_policies"} {
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
	tenant := tenants[0]
	require(t, admin.Bootstrap(ctx, owner, tenant, "质量事件验收", tenant+"_viewer", password, "viewer"))
	id := transport.SensorIdentity{TenantID: tenant, SensorID: "probe_owned", RegistrationID: "reg_owned"}
	require(t, owner.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO sensors(tenant_id,id,name,registration_id,active) VALUES($1,$2,'专属探针',$3,true)`, tenant, id.SensorID, id.RegistrationID)
		return err
	}))
	heartbeat := func(r detectionquality.Report) error {
		raw, _ := json.Marshal(map[string]any{"managed": true, "config_sha256": r.ConfigSHA256, "quality": r})
		return db.Heartbeat(ctx, id, model.HostHealth{ObservedAt: time.Now().UTC(), Capture: raw})
	}
	count := func(table string) int {
		t.Helper()
		var n int
		require(t, db.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, "SELECT count(*) FROM "+table+" WHERE tenant_id=$1", tenant).Scan(&n)
		}))
		return n
	}
	baseline := qualityFixture(t, "engine_owned", nil)
	for _, at := range []*time.Time{baseline.SampledAt, baseline.ReceivedAt, baseline.IntervalStartedAt} {
		*at = at.Add(-8 * time.Second)
	}
	require(t, heartbeat(baseline))
	if count("sensor_quality_outbox") != 0 {
		t.Fatal("无问题基线产生事件")
	}
	report := qualityFixture(t, "engine_owned", map[string]uint64{"capture.kernel_drops": 2})
	// 最新五秒已经没有增量，但相邻已接收快照间的累计损失不能遗漏。
	zero := "0"
	report.Counters[1].Delta = &zero
	report.Capture = detectionquality.Facet{State: "no_reported_change", Reasons: []string{}}
	require(t, heartbeat(report))
	if count("sensor_quality_outbox") != 1 {
		t.Fatal("心跳未原子建立持久待办")
	}
	var concurrent sync.WaitGroup
	errorsCh := make(chan error, 8)
	for range 8 {
		concurrent.Go(func() { errorsCh <- heartbeat(report) })
	}
	concurrent.Wait()
	close(errorsCh)
	for err := range errorsCh {
		require(t, err)
	}
	if count("sensor_quality_outbox") != 1 {
		t.Fatal("同一问题心跳重复记录")
	}
	invalid := report
	invalid.ConfigSHA256 = "bad"
	if heartbeat(invalid) == nil || count("sensor_quality_outbox") != 1 {
		t.Fatal("无效快照改变心跳或待办")
	}
	var stagedExpiry time.Time
	var retainedDays float64
	require(t, owner.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT expires_at,extract(epoch FROM(expires_at-created_at))/86400 FROM sensor_quality_outbox WHERE tenant_id=$1`, tenant).Scan(&stagedExpiry, &retainedDays)
	}))
	if retainedDays != 180 {
		t.Fatal("事件待办未沿用默认 180 天", retainedDays)
	}
	wrong, err := db.LeaseQuality(ctx, tenants[1])
	require(t, err)
	if wrong.ID != "" {
		t.Fatal("跨租户领取待办")
	}
	lease, err := db.LeaseQuality(ctx, tenant)
	require(t, err)
	event, err := qualityevent.Decode(lease.Document)
	require(t, err)
	if lease.ID == "" || event.Report.Counters[1].Delta == nil || *event.Report.Counters[1].Delta != "2" {
		t.Fatal("冻结区间丢失")
	}
	if !event.Report.IntervalStartedAt.Equal(*baseline.SampledAt) {
		t.Fatal("历史区间未覆盖跳过的原生采样")
	}
	empty, err := db.LeaseQuality(ctx, tenant)
	require(t, err)
	if empty.ID != "" {
		t.Fatal("并行重复领取租约")
	}
	forged := lease
	forged.Token = "wrong"
	if !errors.Is(db.FinishQuality(ctx, forged, true), store.ErrConflict) {
		t.Fatal("租约令牌未核对")
	}
	require(t, db.FinishQuality(ctx, lease, false))
	empty, err = db.LeaseQuality(ctx, tenant)
	require(t, err)
	if empty.ID != "" {
		t.Fatal("重试没有退避")
	}
	require(t, owner.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE sensor_quality_outbox SET next_at=now()-interval '1 second' WHERE tenant_id=$1`, tenant)
		return err
	}))
	lease, err = db.LeaseQuality(ctx, tenant)
	require(t, err)
	indexer := worker.Indexer{DB: db, ES: es, Bus: queue}
	wrongPartition := lease
	wrongPartition.Partition = "2026-01-01"
	if indexer.ProcessQuality(ctx, wrongPartition) == nil {
		t.Fatal("事件分区与记录时间不一致")
	}
	require(t, indexer.ProcessQuality(ctx, lease))
	require(t, indexer.ProcessQuality(ctx, lease))
	require(t, db.FinishQuality(ctx, lease, true))
	if !errors.Is(db.FinishQuality(ctx, lease, true), store.ErrConflict) {
		t.Fatal("重复完成已领取事件")
	}
	index, err := contract.IndexName(tenant, "context", event.CreatedAt.UTC().Format("2006-01-02"))
	require(t, err)
	defer func() {
		clean, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		response, err := es.API.Indices.Delete([]string{index}, es.API.Indices.Delete.WithContext(clean))
		require(t, err)
		response.Body.Close()
	}()
	response, err := es.API.Indices.Refresh(es.API.Indices.Refresh.WithContext(ctx), es.API.Indices.Refresh.WithIndex(index))
	require(t, err)
	response.Body.Close()
	stream, err := queue.JS.Stream(ctx, queue.StreamName(bus.Indexed))
	require(t, err)
	info, err := stream.Info(ctx)
	require(t, err)
	if info.State.Msgs != 1 {
		t.Fatal("重复写索引重复发布通知消息")
	}
	message, err := stream.GetLastMsgForSubject(ctx, queue.Subject("sb.indexed"))
	require(t, err)
	// 原始统计详情只保存在历史事件，不进入办公摘要。
	if strings.Contains(string(message.Data), "config_sha256") || strings.Contains(string(message.Data), "counters") {
		t.Fatal("通知流泄漏原生详情")
	}
	vault, err := secrets.New(store.Token())
	require(t, err)
	received := make(chan notify.Message, 2)
	sink := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m notify.Message
		if json.NewDecoder(r.Body).Decode(&m) != nil || r.Header.Get("Idempotency-Key") != m.ID {
			w.WriteHeader(400)
			return
		}
		received <- m
		w.WriteHeader(204)
	}))
	defer sink.Close()
	networks, _ := outbound.ParseNetworks("127.0.0.0/8")
	roots := x509.NewCertPool()
	roots.AddCert(sink.Certificate())
	policy := outbound.Policy{PrivateNetworks: networks, Roots: roots}
	auth := httpapi.NewAuth(db, cache, "", "it_quality", false)
	api := &platform.API{DB: db, ES: es, Redis: cache, Auth: auth, Vault: vault, Outbound: policy}
	server := httptest.NewServer(httpapi.Middleware(api.Handler()))
	defer server.Close()
	auth.Origin = server.URL
	login := func(name string) *liveHTTP {
		jar, err := cookiejar.New(nil)
		require(t, err)
		c := &liveHTTP{t: t, ctx: ctx, origin: server.URL, prefix: "/api/v1", client: &http.Client{Jar: jar, Timeout: 10 * time.Second}}
		c.login(name, password)
		return c
	}
	a, b, viewer := login(tenant), login(tenants[1]), login(tenant+"_viewer")
	enabled := true
	for _, entry := range []struct {
		id      string
		streams []string
		enabled bool
	}{{"channel_alerts", nil, true}, {"channel_quality", []string{"quality"}, true}, {"channel_muted", []string{"quality"}, false}} {
		change := store.ChannelChange{ID: entry.id, Name: entry.id, Kind: "webhook", Enabled: &entry.enabled, Severities: []string{"high"}, Streams: entry.streams, Connection: &notify.Config{Endpoint: sink.URL}}
		a.request("POST", "/notifications/channels", "", change, nil, 200)
	}
	_ = enabled
	notifier := worker.Notifier{DB: db, Vault: vault}
	require(t, notifier.Enqueue(ctx, message.Data))
	require(t, notifier.Enqueue(ctx, message.Data))
	var deliveries struct {
		Items []store.Delivery `json:"items"`
	}
	a.request("GET", "/notifications/deliveries", "", nil, &deliveries, 200)
	if len(deliveries.Items) != 2 {
		t.Fatal("未订阅渠道被外发或投递重复", deliveries)
	}
	for _, d := range deliveries.Items {
		if d.Stream != "quality" || d.RecordCount != 1 || d.AlertCount != 0 || d.ChannelID == "channel_alerts" {
			t.Fatal("投递列表类别与计数不一致", d)
		}
	}
	notice, err := db.LeaseNotification(ctx, tenant, vault)
	require(t, err)
	if notice.ID == "" || notice.Config.Streams[0] != "quality" {
		t.Fatal("未领取质量订阅")
	}
	out := (notify.Sender{Policy: policy}).Send(ctx, notice.Config, notice.Message)
	if out.State != "accepted" {
		t.Fatal(out)
	}
	require(t, db.FinishNotification(ctx, notice, out))
	if m := <-received; len(m.Quality) != 1 || m.Quality[0].ID != event.ID || len(m.Alerts) != 0 {
		t.Fatal("接收摘要来源不一致")
	}
	q := url.Values{"start": {event.CreatedAt.Add(-time.Minute).Format(time.RFC3339Nano)}, "end": {event.CreatedAt.Add(time.Minute).Format(time.RFC3339Nano)}, "sensor_id": {id.SensorID}, "registration_id": {id.RegistrationID}}
	var page store.QualityPage
	for _, c := range []*liveHTTP{a, viewer} {
		c.request("GET", "/sensors/quality-events?"+q.Encode(), "", nil, &page, 200)
		if page.Total != "1" || len(page.Items) != 1 || page.Items[0].ID != event.ID {
			t.Fatal("历史事件丢失或角色读取不一致", page)
		}
	}
	b.request("GET", "/sensors/quality-events?"+q.Encode(), "", nil, &page, 200)
	if page.Total != "0" || len(page.Items) != 0 {
		t.Fatal("质量历史跨租户可见")
	}
	a.request("GET", "/sensors/quality-events?"+q.Encode()+"&tenant_id=other", "", nil, nil, 400)
	// 未观测到当前完整层级时，只能核对原限制指标是否明确为零增量。
	quiet := qualityFixture(t, "engine_owned", nil)
	total := "2"
	quiet.Counters[1].Total = &total
	require(t, heartbeat(quiet))
	if count("sensor_quality_outbox") != 2 {
		t.Fatal("未记录原限制未再增量")
	}
	quiet.EvaluatedAt = time.Now().UTC()
	require(t, heartbeat(quiet))
	if count("sensor_quality_outbox") != 2 {
		t.Fatal("重复的零增量产生事件")
	}
	restart := qualityFixture(t, "engine_other", map[string]uint64{"detect.alerts_suppressed": 1})
	require(t, heartbeat(restart))
	if count("sensor_quality_outbox") != 3 {
		t.Fatal("策略影响未单独记录")
	}
	require(t, owner.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE sensor_quality_cursors SET event_created_at=now()-interval '16 minutes' WHERE tenant_id=$1`, tenant)
		return err
	}))
	restart = qualityFixture(t, "engine_other", map[string]uint64{"detect.alerts_suppressed": 2})
	require(t, heartbeat(restart))
	if count("sensor_quality_outbox") != 4 {
		t.Fatal("持续问题没有有界提醒")
	}
	masked := qualityFixture(t, "engine_other", map[string]uint64{"detect.alerts_suppressed": 3})
	masked.Counters[22].Delta = &zero
	one := "1"
	masked.Counters[22].ObservedResets = &one
	masked.Policy = detectionquality.Facet{State: "no_reported_change", Reasons: []string{}}
	require(t, heartbeat(masked))
	if count("sensor_quality_outbox") != 5 {
		t.Fatal("累计增长掩盖了心跳之间的原生观测复位")
	}
	var resetRaw string
	require(t, db.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT document->'event'->>'original' FROM sensor_quality_outbox WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 1`, tenant).Scan(&resetRaw)
	}))
	var resetEvent qualityevent.Event
	require(t, json.Unmarshal([]byte(resetRaw), &resetEvent))
	require(t, resetEvent.Validate())
	if resetEvent.Report.State != "counter_reset" || len(resetEvent.Report.ResetCounters) != 1 || resetEvent.Report.ResetCounters[0] != "detect.alerts_suppressed" {
		t.Fatal("复位被当作连续增量")
	}
	// 故障正文进入退避且后续任务仍可领取；不能在解码错误时回滚领取而阻塞队头。
	require(t, owner.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE sensor_quality_outbox SET document='{}',next_at=now()-interval '1 day' WHERE tenant_id=$1 AND state='pending' AND id=(SELECT id FROM sensor_quality_outbox WHERE tenant_id=$1 AND state='pending' ORDER BY created_at LIMIT 1)`, tenant)
		return err
	}))
	broken, err := db.LeaseQuality(ctx, tenant)
	if broken.ID == "" || err == nil {
		t.Fatal("故障正文未保留可退避租约")
	}
	require(t, db.FinishQuality(ctx, broken, false))
	next, err := db.LeaseQuality(ctx, tenant)
	require(t, err)
	if next.ID == "" || next.ID == broken.ID {
		t.Fatal("故障正文阻塞后续待办")
	}
	require(t, db.FinishQuality(ctx, next, true))
	// 过期记录不索引；当前身份去重状态独立保护。
	require(t, owner.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE sensor_quality_outbox SET expires_at=now()-interval '1 second',next_at=now()-interval '1 second' WHERE tenant_id=$1 AND state='pending'`, tenant)
		return err
	}))
	_, err = db.LeaseQuality(ctx, tenant)
	require(t, err)
	require(t, owner.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE sensor_quality_cursors SET expires_at=now()-interval '1 second' WHERE tenant_id=$1`, tenant)
		return err
	}))
	require(t, db.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM sensor_quality_cursors WHERE tenant_id=$1`, tenant)
		if err == nil && tag.RowsAffected() != 0 {
			t.Fatal("活动注册去重状态可删除")
		}
		return err
	}))
	require(t, owner.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE sensors SET registration_id='reg_replaced' WHERE tenant_id=$1 AND id=$2`, tenant, id.SensorID)
		return err
	}))
	require(t, db.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM sensor_quality_cursors WHERE tenant_id=$1`, tenant)
		if err == nil && tag.RowsAffected() != 1 {
			t.Fatal("旧注册到期水位未回收")
		}
		return err
	}))
	if heartbeat(restart) == nil {
		t.Fatal("旧注册身份仍可更新心跳")
	}
}
