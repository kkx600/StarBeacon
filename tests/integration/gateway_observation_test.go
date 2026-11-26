//go:build integration

package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/agent"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/gatewayblock"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/notify"
	"github.com/kkx600/StarBeacon/internal/outbound"
	"github.com/kkx600/StarBeacon/internal/response"
	"github.com/kkx600/StarBeacon/internal/secrets"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/watchlist"
)

// 与模板插件通过真实 TLS 交互，记录设备独立读取的租约及目标。
func gatewayPluginFixture(t *testing.T, f *gatewayFixture) (*agent.TaskManager, model.HostHealth, func() int) {
	t.Helper()
	const pluginID = "gateway_owned_plugin"
	dir, token := t.TempDir(), store.Token()
	var mu sync.Mutex
	var writes int
	leases := map[string]map[string]any{}
	device := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer "+token {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/status":
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "unit": "gateway_owned_device",
				"firmware": "fixture/1", "expires_locally": true, "isolated_rules": true,
				"checks_owner": true, "maximum_age": 120, "checked_at": time.Now().UTC()})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/acl":
			var body map[string]any
			if json.NewDecoder(r.Body).Decode(&body) != nil {
				w.WriteHeader(400)
				return
			}
			id, ok := body["comment"].(string)
			if !ok || leases[id] != nil || body["policy"] != "temporary" {
				w.WriteHeader(409)
				return
			}
			writes++
			body["unit"], body["key"], body["rule_state"] = "gateway_owned_device", "fixture_rule", "active"
			leases[id] = body
			w.WriteHeader(201)
			fmt.Fprint(w, `{"code":0,"key":"fixture_rule"}`)
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/acl/by-task/"):
			body := leases[strings.TrimPrefix(r.URL.Path, "/v1/acl/by-task/")]
			if body == nil {
				w.WriteHeader(404)
				fmt.Fprint(w, `{"code":"unassigned"}`)
				return
			}
			body["checked_at"] = time.Now().UTC()
			_ = json.NewEncoder(w).Encode(body)
		default:
			w.WriteHeader(405)
		}
	}))
	t.Cleanup(device.Close)
	cfg := response.Configuration{ID: "gateway_owned_connector", DeviceID: "gateway_owned_device", DeviceVersion: "fixture/1",
		Origin: device.URL, CAFile: filepath.Join(dir, "device.pem"), TokenFile: filepath.Join(dir, "device.token"),
		AllowedTargets: []string{"10.203.35.0/24", "10.203.36.0/24", "192.0.2.254/32"}, MaxTTLSeconds: 120}
	require(t, os.WriteFile(cfg.CAFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: device.Certificate().Raw}), 0600))
	require(t, os.WriteFile(cfg.TokenFile, []byte(token), 0600))
	path := filepath.Join(dir, "bindings.json")
	bindings, err := json.Marshal(map[string]any{"schema_version": "response.plugin-bindings.v1",
		"profiles": []map[string]any{{"plugin_id": pluginID, "device": cfg, "test_address": "192.0.2.254"}}})
	require(t, err)
	require(t, os.WriteFile(path, bindings, 0600))

	wal, err := agent.OpenWAL(filepath.Join(dir, "agent.db"), f.id.TenantID, f.id.SensorID, f.id.RegistrationID, 8<<20)
	require(t, err)
	t.Cleanup(func() { require(t, wal.Close()) })
	public := f.signer.Public().(ed25519.PublicKey)
	service, err := agent.NewPluginService(wal, path, "", public)
	require(t, err)
	t.Cleanup(service.Close)
	effect, err := agent.NewResponseService(wal, "")
	require(t, err)
	t.Cleanup(effect.Close)
	effect.Plugins = service
	engine := &agent.Engine{WAL: wal, Plugins: service, Response: effect}
	var template response.Template
	raw, err := os.ReadFile("../../internal/response/testdata/owned_acl_template.json")
	require(t, err)
	require(t, json.Unmarshal(raw, &template))
	template.Login = nil
	version := response.PluginVersion{ID: pluginID, Version: 1, Name: "验收插件", Device: "TLS 设备夹具",
		Kind: "template", State: "draft", CreatedBy: f.user.ID, CreatedAt: time.Now().UTC(), Template: template, TemplateSHA256: template.SHA256()}
	grant := response.PluginGrant{TenantID: f.id.TenantID, SensorID: f.id.SensorID, RegistrationID: f.id.RegistrationID,
		Binding: service.Bindings()[0], Version: 1, DefinitionSHA256: version.DefinitionSHA256(),
		TrialSHA256: [3]string{store.Hash("fixture_simulation"), store.Hash("fixture_read"), store.Hash("fixture_capability")}}
	signed, err := response.SignPlugin(grant, f.signer)
	require(t, err)
	artifact := response.PluginArtifact{Version: version, Release: signed}
	payload, err := json.Marshal(response.PluginActivation{PluginID: pluginID, Action: response.PluginPublish, Artifact: &artifact})
	require(t, err)
	now := time.Now().UTC()
	activateFixturePlugin(t, f.ctx, service, engine, wal, f.signer, control.Command{ID: "gateway_plugin_fixture_apply",
		TenantID: f.id.TenantID, SensorID: f.id.SensorID, RegistrationID: f.id.RegistrationID, Kind: response.PluginApplyCommand,
		IssuedAt: now, ExpiresAt: now.Add(time.Minute), Payload: payload})
	raw, err = json.Marshal(artifact)
	require(t, err)
	_, err = f.db.Owner.Pool.Exec(f.ctx, `INSERT INTO response_plugin_assignments
		(tenant_id,plugin_id,sensor_id,registration_id,generation,current_artifact) VALUES($1,$2,$3,$4,1,$5)`,
		f.id.TenantID, pluginID, f.id.SensorID, f.id.RegistrationID, raw)
	require(t, err)
	manager, err := agent.NewTaskManager(wal, public, engine)
	require(t, err)
	manager.Plugins = service
	active, stop := context.WithCancel(f.ctx)
	notices, tasks := make(chan error, 1), make(chan error, 1)
	go func() { notices <- effect.Run(active) }()
	go func() { tasks <- manager.Run(active) }()
	t.Cleanup(func() { stop(); require(t, <-tasks); require(t, <-notices) })
	var h model.HostHealth
	eventually(t, f.ctx, "模板插件通过设备 HTTPS 独立描述身份", func() bool {
		bindings := effect.Health()
		if len(bindings) != 1 || !bindings[0].Ready(time.Now().UTC()) {
			return false
		}
		h = model.HostHealth{CommandSignerSHA256: control.Digest(public), TaskCapabilities: engine.Capabilities(),
			PluginBindings: service.Bindings(), ResponseConnectors: bindings}
		return true
	})
	return manager, h, func() int { mu.Lock(); defer mu.Unlock(); return writes }
}

func storeGatewayObservation(f *gatewayFixture, source, dest string, port uint16, state string) (model.Alert, gatewayblock.Result) {
	f.t.Helper()
	alert := f.observe("1003340", source, dest, port)
	require(f.t, f.db.Runtime.RecordGatewayBlockMatches(f.ctx, f.id.TenantID, []model.Alert{alert}))
	return alert, acceptGatewayObservation(f, f.next(), gatewayblock.Rule, state)
}

func acceptGatewayObservation(f *gatewayFixture, delivery *store.TaskDelivery, trigger, state string) gatewayblock.Result {
	f.t.Helper()
	_, action := f.command(delivery, trigger)
	if !action.Observe || !action.FollowUp {
		f.t.Fatal("签名任务缺少观察和后续执行授权")
	}
	now := time.Now().UTC()
	o := gatewayblock.Observation{State: state, Interface: "eth0", StartedAt: now, FinishedAt: now}
	switch state {
	case gatewayblock.FlowPaused, gatewayblock.FlowContinued:
		o.FinishedAt = now.Add(gatewayblock.ObserveWindow)
		o.EgressPackets = 3
		if state == gatewayblock.FlowContinued {
			next := action.Flow
			next.SourcePort++
			o.Reconnect = &next
		}
		timer := time.NewTimer(time.Until(o.FinishedAt))
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-f.ctx.Done():
			f.t.Fatal(f.ctx.Err())
		}
	default:
		o.Code = "observer_unavailable"
	}
	result := gatewayblock.Result{RequestID: action.RequestID, ConfigSHA256: action.ConfigSHA256, Flow: action.Flow,
		LeaseUntil: action.LeaseUntil, VerifiedAt: now, Observation: &o}
	f.receipt(delivery, result, true)
	return result
}

func TestGatewayObservationFollowUpDeviceAndNotification(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Second)
	defer cancel()
	f := newGatewayFixture(t, ctx, gatewayblock.Scope{Sources: []netip.Prefix{netip.MustParsePrefix("10.203.35.0/24")},
		Destinations: []netip.Prefix{netip.MustParsePrefix("10.203.36.0/24")}})
	manager, host, writes := gatewayPluginFixture(t, f)
	local := gatewayblock.LocalConfig{Enabled: true, Scope: f.scope, ObserveInterface: "eth0"}.Binding()
	heartbeat := func() {
		host.ObservedAt = time.Now().UTC()
		host.GatewayBlock = &local
		host.ResponseConnectors[0].ObservedAt = host.ObservedAt
		require(t, f.db.Runtime.Heartbeat(ctx, f.id, host))
	}
	path := "/gateway-block/plugins?sensor_id=" + f.id.SensorID + "&registration_id=" + f.id.RegistrationID
	catalog := func(count int) []gatewayblock.FollowUpDevice {
		t.Helper()
		var result struct{ Items []gatewayblock.FollowUpDevice }
		f.client.request("GET", path, "", nil, &result, 200)
		if len(result.Items) != count {
			t.Fatal("可预授权目录与当前设备绑定不符", result.Items)
		}
		return result.Items
	}
	catalog(0)
	ready := host.ResponseConnectors[0]
	other := ready
	other.DeviceID, other.ConnectorID = "independent_device", "independent_connector"
	host.ResponseConnectors = []response.Health{other}
	heartbeat()
	catalog(0)
	ambiguous := ready
	ambiguous.ConnectorID = "additional_connector"
	host.ResponseConnectors = []response.Health{ready, ambiguous}
	heartbeat()
	catalog(0)
	host.ResponseConnectors = []response.Health{ready}
	unpublished := host.PluginBindings[0]
	unpublished.PluginID, unpublished.DeviceID = "unpublished_plugin", other.DeviceID
	host.PluginBindings = append(host.PluginBindings, unpublished)
	heartbeat()
	device := catalog(1)[0]
	host.PluginBindings = host.PluginBindings[:1]
	heartbeat()
	if _, err := f.db.Runtime.GatewayFollowUpDevices(ctx, f.user, "wrong/sensor", f.id.RegistrationID); err != gatewayblock.ErrInput {
		t.Fatal("插件目录接受了无效采集器标识", err)
	}
	f.viewer.request("GET", path, "", nil, nil, 403)
	f.peer.request("GET", path, "", nil, nil, 404)
	f.client.request("GET", path+"&sensor_id=duplicate", "", nil, nil, 400)
	f.settings(true, 20)
	follow := &gatewayblock.FollowUp{PluginID: device.PluginID, Generation: device.Generation, ConnectorID: device.ConnectorID,
		ConfigSHA256: device.ConfigSHA256, TargetSide: "destination", TTLSeconds: 60}
	d := gatewayblock.Definition{Name: "出侧暂停后执行已授权动作", Enabled: true, Trigger: gatewayblock.Rule, SensorID: f.id.SensorID,
		RegistrationID: f.id.RegistrationID, RuleID: "1003340", RuleRevision: "1", Scope: f.scope,
		LeaseSeconds: 18, ValidUntil: time.Now().UTC().Add(time.Hour), FollowUp: follow}
	savePolicy := func(revision int64, status int) {
		f.client.request("PUT", "/gateway-block/policies/"+testRulePolicy, "", gatewayblock.PolicyChange{ExpectedRevision: revision, Definition: d}, nil, status)
	}
	follow.PluginID = "unregistered_plugin"
	savePolicy(0, 409)
	follow.PluginID = device.PluginID
	local.Observation = false
	heartbeat()
	savePolicy(0, 409)
	local.Observation = true
	heartbeat()
	follow.Generation++
	savePolicy(0, 409)
	follow.Generation--
	savePolicy(0, 200)
	const source, dest = "10.203.35.3", "10.203.36.3"
	paused, native := storeGatewayObservation(f, source, dest, 41070, gatewayblock.FlowPaused)
	if d := f.next(); d != nil {
		t.Fatal("没有观察完成后的心跳仍签发了任务")
	}
	heartbeat()
	exec := func(sql string, args ...any) {
		t.Helper()
		_, err := f.db.Owner.Pool.Exec(ctx, sql, args...)
		require(t, err)
	}
	fault := func(install, restore string, check func()) {
		t.Helper()
		exec(install)
		defer exec(restore)
		check()
	}
	dispatchError := func() {
		t.Helper()
		result, err := f.db.Runtime.NextGatewayBlock(ctx, f.id, f.signer)
		if err == nil || result != nil {
			t.Fatal("数据库故障时仍返回了联动任务", result, err)
		}
	}
	assertRetryable := func() {
		t.Helper()
		current := f.gatewayRecord(paused.EventID)
		var count int
		require(t, f.db.Owner.Pool.QueryRow(ctx, `SELECT count(*) FROM sensor_tasks WHERE tenant_id=$1 AND kind='response.block'`, f.id.TenantID).Scan(&count))
		if current.FollowUpState != "pending" || current.FollowUpTaskID != "" || count != 0 || writes() != 0 {
			t.Fatal("失败事务遗留了任务或消耗了预授权", current, count)
		}
	}
	for _, table := range []string{"gateway_block_settings", "gateway_block_policies", "response_plugin_assignments", "users", "watchlists"} {
		fault("REVOKE SELECT ON "+table+" FROM starbeacon_app", "GRANT SELECT ON "+table+" TO starbeacon_app", func() {
			dispatchError()
			switch table {
			case "gateway_block_settings":
				f.client.request("GET", "/gateway-block/requests", "", nil, nil, 503)
			case "response_plugin_assignments":
				f.client.request("GET", path, "", nil, nil, 503)
			}
		})
		assertRetryable()
	}
	fault("REVOKE INSERT ON sensor_tasks FROM starbeacon_app", "GRANT INSERT ON sensor_tasks TO starbeacon_app", dispatchError)
	assertRetryable()
	exec(`CREATE FUNCTION fail_gateway_fixture_write() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN RAISE EXCEPTION '验收模拟写入失败'; END;
		$$`)
	for _, step := range []struct{ table, hook string }{
		{"sensor_tasks", "BEFORE UPDATE OF state ON sensor_tasks FOR EACH ROW WHEN (NEW.kind='response.block' AND NEW.state='delivered')"},
		{"gateway_block_requests", "BEFORE UPDATE OF follow_up_state ON gateway_block_requests FOR EACH ROW WHEN (NEW.follow_up_state='issued')"},
		{"operation_audits", "BEFORE INSERT ON operation_audits FOR EACH ROW WHEN (NEW.action='gateway.block.follow_up')"},
	} {
		fault("CREATE TRIGGER fail_gateway_fixture_write "+step.hook+" EXECUTE FUNCTION fail_gateway_fixture_write()",
			"DROP TRIGGER fail_gateway_fixture_write ON "+step.table, dispatchError)
		assertRetryable()
	}
	delivery := f.next()
	if delivery == nil {
		t.Fatal("没有签发已预授权的联动任务", f.gatewayRecord(paused.EventID))
	}
	command, err := control.Decode(delivery.Command, delivery.Signature, f.signer.Public().(ed25519.PublicKey),
		f.id.TenantID, f.id.SensorID, f.id.RegistrationID, time.Now().UTC())
	require(t, err)
	action, err := response.ReadAction(command.Payload)
	require(t, err)
	if command.Kind != "response.block" || action.TargetIP != dest || action.DeviceID != device.DeviceID ||
		action.ExpiresAt.Sub(action.RequestedAt) != time.Minute {
		t.Fatal("签发的方向、设备或时长与策略不一致", action)
	}
	require(t, manager.Accept(delivery.Command, delivery.Signature))
	receipt := waitPluginReceipt(t, ctx, manager, delivery.ID)
	verified, err := response.ReadResult(receipt.Result, action, "response.block", time.Now().UTC())
	require(t, err)
	require(t, f.db.Runtime.SaveReceipt(ctx, f.id, receipt))
	record := f.gatewayRecord(paused.EventID)
	if !verified.Verified || writes() != 1 || record.FollowUpState != "issued" || record.FollowUpTaskState != "succeeded" ||
		record.FollowUpTaskID != delivery.ID || record.GatewayResult == nil || !record.GatewayResult.VerifiedAt.Equal(native.VerifiedAt) || f.next() != nil {
		t.Fatal("设备实际回读、观察原件和防重签结果不一致", record, verified)
	}

	continued, continuedNative := storeGatewayObservation(f, source, dest, 41072, gatewayblock.FlowContinued)
	unknown, _ := storeGatewayObservation(f, source, dest, 41074, gatewayblock.FlowUnknown)
	if f.next() != nil || f.gatewayRecord(continued.EventID).FollowUpCode != "traffic_continued" ||
		f.gatewayRecord(unknown.EventID).FollowUpCode != "observation_unavailable" {
		t.Fatal("继续流量或未核对观察签发了处置任务")
	}
	var page gatewayblock.RequestPage
	f.client.request("GET", "/gateway-block/requests?limit=10", "", nil, &page, 200)
	if !page.Enabled || page.OnlineGateways != 1 || len(page.Items) != 3 || page.NextCursor != "" ||
		page.LastDay != (gatewayblock.RequestCounts{Total: 3, Paused: 1, Continued: 1, Unknown: 1}) {
		t.Fatal("记录目录未独立统计回读和观察", page)
	}
	f.client.request("GET", "/gateway-block/requests?limit=2", "", nil, nil, 400)
	f.client.request("GET", "/gateway-block/requests?cursor=absent", "", nil, nil, 404)
	f.viewer.request("GET", "/gateway-block/requests", "", nil, nil, 403)
	f.peer.request("GET", "/gateway-block/requests", "", nil, &page, 200)
	if len(page.Items) != 0 || page.LastDay.Total != 0 {
		t.Fatal("观察记录越过租户边界", page)
	}

	sink := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var message notify.Message
		if err := json.NewDecoder(req.Body).Decode(&message); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		if message.Gateway == nil || !message.Gateway.Reconnected || message.Gateway.RequestID != continuedNative.RequestID ||
			len(message.Alerts) != 0 || len(message.Quality) != 0 {
			t.Error("通知未按观察结果引用正确的记录", message)
		}
		w.WriteHeader(204)
	}))
	t.Cleanup(sink.Close)
	networks, err := outbound.ParseNetworks("127.0.0.0/8")
	require(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(sink.Certificate())
	policy := outbound.Policy{PrivateNetworks: networks, Roots: roots}
	vault, err := secrets.New(store.Token())
	require(t, err)
	enabled := true
	for _, stream := range []string{"quality", "alerts"} {
		_, err = f.db.Runtime.SaveNotificationChannel(ctx, f.user, store.ChannelChange{ID: "gateway_" + stream,
			Name: "值班验收", Kind: "webhook", Enabled: &enabled, Streams: []string{stream}, Severities: []string{"high"},
			Connection: &notify.Config{Endpoint: sink.URL}}, vault, policy, "gateway_notice")
		require(t, err)
	}
	fault("REVOKE INSERT ON notification_batches FROM starbeacon_app", "GRANT INSERT ON notification_batches TO starbeacon_app", func() {
		if err := f.db.Runtime.EnqueueGatewayNotices(ctx, f.id.TenantID, vault); err == nil {
			t.Fatal("通知入队失败却清除了待投递记录")
		}
	})
	for range 2 {
		require(t, f.db.Runtime.EnqueueGatewayNotices(ctx, f.id.TenantID, vault))
	}
	notice, err := f.db.Runtime.LeaseNotification(ctx, f.id.TenantID, vault)
	require(t, err)
	if notice.Message.Gateway == nil || !strings.Contains(notice.Message.Text(), "重连") || notice.Config.Streams[0] != "quality" {
		t.Fatal("观察提示未正确进入值班渠道", notice.Message)
	}
	out := (notify.Sender{Policy: policy}).Send(ctx, notice.Config, notice.Message)
	if out.State != "accepted" {
		t.Fatal("真实 HTTPS 通知未投递", out)
	}
	require(t, f.db.Runtime.FinishNotification(ctx, notice, out))
	items, _, err := f.db.Runtime.NotificationDeliveries(ctx, f.id.TenantID, "", "", 10)
	require(t, err)
	if len(items) != 1 || items[0].Stream != "quality" || items[0].RecordCount != 1 {
		t.Fatal("观察通知重复或投递到了未订阅渠道", items)
	}

	cooldown, _ := storeGatewayObservation(f, source, dest, 41076, gatewayblock.FlowPaused)
	heartbeat()
	if f.next() != nil || f.gatewayRecord(cooldown.EventID).FollowUpCode != "target_cooldown" {
		t.Fatal("同一设备目标收到重复租约")
	}
	protected, _ := storeGatewayObservation(f, source, dest, 41078, gatewayblock.FlowPaused)
	list := watchlistInput("gateway_new_protection")
	list.Definition.Sensors = []watchlist.Sensor{{SensorID: f.id.SensorID, RegistrationID: f.id.RegistrationID}}
	list.Definition.Values = []string{source}
	f.client.request("POST", "/watchlists", list.ID, list, nil, 200)
	heartbeat()
	if f.next() != nil || f.gatewayRecord(protected.EventID).FollowUpCode != "protected_endpoint" || writes() != 1 {
		t.Fatal("观察后的双端保护名单未被复核")
	}

	for index, check := range []struct {
		code   string
		change func(gatewayblock.Request)
	}{
		{"gateway_setting_changed", func(gatewayblock.Request) { f.settings(true, 19) }},
		{"policy_changed", func(gatewayblock.Request) { savePolicy(1, 200) }},
		{"observer_changed", func(gatewayblock.Request) { local.Observation = false }},
		{"observation_unavailable", func(r gatewayblock.Request) {
			exec("UPDATE sensor_tasks SET signature=$3 WHERE tenant_id=$1 AND id=$2",
				f.id.TenantID, r.TaskID, make([]byte, ed25519.SignatureSize))
		}},
		{"observation_unavailable", func(r gatewayblock.Request) {
			exec(`UPDATE sensor_tasks SET receipt=jsonb_set(receipt,'{result,observation,egress_packets}','4'::jsonb)
				WHERE tenant_id=$1 AND id=$2`, f.id.TenantID, r.TaskID)
		}},
		{"device_changed", func(gatewayblock.Request) {
			exec(`UPDATE response_plugin_assignments SET generation=generation+1
				WHERE tenant_id=$1 AND sensor_id=$2 AND registration_id=$3 AND plugin_id=$4`,
				f.id.TenantID, f.id.SensorID, f.id.RegistrationID, device.PluginID)
		}},
	} {
		alert, _ := storeGatewayObservation(f, "10.203.35.4", "10.203.36.4", uint16(41080+index), gatewayblock.FlowPaused)
		check.change(f.gatewayRecord(alert.EventID))
		heartbeat()
		if f.next() != nil {
			t.Fatal("预授权失效后仍签发设备任务", check.code)
		}
		record := f.gatewayRecord(alert.EventID)
		if record.FollowUpState != "skipped" || record.FollowUpCode != check.code || writes() != 1 {
			t.Fatal("预授权失效原因或写入数量异常", check.code, record)
		}
		local.Observation = true
		heartbeat()
	}

	f.client.request("GET", "/gateway-block/requests?limit=10", "", nil, &page, 200)
	if len(page.Items) != 10 || page.NextCursor != page.Items[9].ID || page.LastDay.Total != 11 {
		t.Fatal("新记录未按限制返回完整第一页", page)
	}
	f.client.request("GET", "/gateway-block/requests?limit=10&cursor="+page.NextCursor, "", nil, &page, 200)
	if len(page.Items) != 1 || page.Items[0].ID != native.RequestID || page.NextCursor != "" {
		t.Fatal("记录分页重复或遗漏", page)
	}

	fault("REVOKE SELECT ON sensors FROM starbeacon_app", "GRANT SELECT ON sensors TO starbeacon_app", func() {
		f.client.request("GET", "/gateway-block/requests", "", nil, nil, 503)
	})
	exec(`UPDATE response_plugin_assignments SET generation=1
		WHERE tenant_id=$1 AND sensor_id=$2 AND registration_id=$3 AND plugin_id=$4`,
		f.id.TenantID, f.id.SensorID, f.id.RegistrationID, device.PluginID)
	review := d
	review.Trigger, review.RuleID = gatewayblock.Review, "1003341"
	f.client.request("PUT", "/gateway-block/policies/"+testReviewPolicy, "", gatewayblock.PolicyChange{Definition: review}, nil, 200)
	createReviewedObservation := func(port uint16) model.Alert {
		t.Helper()
		a := f.observe("1003341", "10.203.35.4", "10.203.36.4", port)
		f.indexAlerts(a)
		input := f.assessment(a, 0, "confirmed")
		f.client.request("POST", "/alerts/"+a.EventID+"/gateway-blocks", store.RandomID("t34_review_"), input, nil, 202)
		acceptGatewayObservation(f, f.next(), gatewayblock.Review, gatewayblock.FlowPaused)
		return a
	}
	reviewed := createReviewedObservation(41200)
	heartbeat()
	fault("REVOKE SELECT ON alert_assessments FROM starbeacon_app", "GRANT SELECT ON alert_assessments TO starbeacon_app", dispatchError)
	f.assessment(reviewed, 1, "false_positive")
	if f.next() != nil || f.gatewayRecord(reviewed.EventID).FollowUpCode != "assessment_changed" {
		t.Fatal("研判结论改变后仍然允许联动")
	}

	revoked := createReviewedObservation(41202)
	heartbeat()
	exec("UPDATE users SET active=false WHERE tenant_id=$1 AND id=$2", f.id.TenantID, f.user.ID)
	issued := f.next()
	exec("UPDATE users SET active=true WHERE tenant_id=$1 AND id=$2", f.id.TenantID, f.user.ID)
	if issued != nil || f.gatewayRecord(revoked.EventID).FollowUpCode != "authorization_revoked" || writes() != 1 {
		t.Fatal("原授权账号停用后仍然允许联动")
	}
}
