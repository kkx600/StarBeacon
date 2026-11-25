package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sensorv1 "github.com/kkx600/StarBeacon/api/sensor/v1"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/response"
	"github.com/kkx600/StarBeacon/internal/responsescript"
	bolt "go.etcd.io/bbolt"
)

func requirePlugin(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestPluginReadbackRequiresOriginalDeviceTargetAndExpiry(t *testing.T) {
	fields := []string{"device_id", "lease_id", "owner_sha256", "target_ip", "expires_at", "state", "observed_at", "rule_id"}
	plan := pluginVerifyPlan{Path: "/lease/{rule_id}", MissingField: "code", MissingValue: "missing"}
	now := time.Now().UTC()
	want := pluginLease{DeviceID: "device", LeaseID: "lease", OwnerSHA256: strings.Repeat("a", 64),
		TargetIP: "192.0.2.10", RuleID: "rule", ExpiresAt: now.Add(time.Minute), State: "active", ObservedAt: now}
	content, _ := json.Marshal(want)
	var values map[string]json.RawMessage
	requirePlugin(t, json.Unmarshal(content, &values))
	for _, field := range fields {
		plan.Fields = append(plan.Fields, response.TemplateField{Name: field, Value: field})
	}
	ok := responsescript.Readback{Status: http.StatusOK, Fields: values}
	if !plan.valid("block") {
		t.Fatal("回读配置缺少必要校验")
	}
	if actual, err := plan.readback(&ok, want); err != nil || actual.RuleID != want.RuleID {
		t.Fatal("本次独立回读通不过", actual, err)
	}
	for _, tc := range []struct {
		field string
		value any
	}{
		{"device_id", "other"}, {"lease_id", "old"}, {"owner_sha256", strings.Repeat("0", 64)}, {"target_ip", "192.0.2.11"},
		{"expires_at", now.Add(time.Hour)}, {"observed_at", now.Add(-time.Minute)}, {"rule_id", "wrong_rule"}, {"state", "unknown"},
	} {
		before := values[tc.field]
		values[tc.field], _ = json.Marshal(tc.value)
		if _, err := plan.readback(&ok, want); !errors.Is(err, response.ErrUnknown) {
			t.Fatal("回读错误匹配到设备租约", tc.field, err)
		}
		values[tc.field] = before
	}
	notFound := responsescript.Readback{Status: http.StatusNotFound, Fields: map[string]json.RawMessage{"code": json.RawMessage(`"wrong"`)}}
	if _, err := plan.readback(&notFound, want); !errors.Is(err, response.ErrUnknown) {
		t.Fatal("未知编号不能视为已确认解除", err)
	}
	for _, value := range []struct{ raw, want string }{{`"active"`, "active"}, {`"revoked"`, "revoked"}, {`false`, "missing"}} {
		if !reportedState([]byte(value.raw), value.want) {
			t.Fatal("脚本回报状态解析错误", value)
		}
	}
	if reportedState([]byte(`"active"`), "revoked") || reportedState([]byte("true"), "revoked") {
		t.Fatal("回读不一致的脚本状态仍被接受")
	}
}

func writeProfileFixture(t *testing.T, profile pluginProfile) string {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"schema_version": "response.plugin-bindings.v1", "profiles": []pluginProfile{profile}})
	requirePlugin(t, err)
	f := filepath.Join(t.TempDir(), "bindings.json")
	requirePlugin(t, os.WriteFile(f, raw, 0600))
	return f
}

func TestDeviceAlertWALAtomicCheckpointDedupAndRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "alerts.db")
	w, err := OpenWAL(path, "tenant_owned", "sensor_owned", "reg_owned", 64*1024)
	requirePlugin(t, err)
	defer func() { _ = w.Close() }()
	if _, err = w.deviceAlertCursor("plugin_owned", "device"); err == nil {
		t.Fatal("未配置插件的 WAL 提供了游标")
	}
	requirePlugin(t, w.DB.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(deviceAlertSources)
		return err
	}))
	newAlert := func(id string) contract.DeviceAlert {
		return contract.DeviceAlert{ID: id, Time: time.Now().UTC(), Severity: "critical", Name: "设备告警",
			SourceIP: "192.0.2.10", Host: "测试端", Raw: json.RawMessage(`{"details": {"value":"<保留>"}}`)}
	}
	const plugin, device = "plugin_owned", "device"
	add := func(expected, next, route string, records ...contract.DeviceAlert) error {
		return w.appendDeviceAlerts(plugin, "设备夹具", device, expected, route, contract.DeviceAlertPage{Cursor: next, Items: records})
	}
	if err := add("", "invalid", "", newAlert("1")); !errors.Is(err, contract.ErrDeviceAlert) {
		t.Fatal("缺少路由的页仍可入队", err)
	}
	if err := add("wrong", "skip", "route", newAlert("1")); !errors.Is(err, contract.ErrDeviceAlert) {
		t.Fatal("陈旧前置游标覆盖设备进度", err)
	}
	requirePlugin(t, add("", "first", "route", newAlert("1"), newAlert("1")))
	b, err := w.Next("alerts")
	requirePlugin(t, err)
	if len(b.Records) != 1 {
		t.Fatal("同页重复告警入队")
	}
	requirePlugin(t, contract.Validate(w.TenantID, w.SensorID, w.RegistrationID, b))
	invalid := newAlert("bad")
	invalid.Raw = json.RawMessage(`undefined`)
	if err := add("first", "skip", "route", newAlert("2"), invalid); !errors.Is(err, contract.ErrDeviceAlert) {
		t.Fatal("无效设备记录未拒绝整页", err)
	}
	if cursor, err := w.deviceAlertCursor(plugin, device); err != nil || cursor != "first" {
		t.Fatal("失败入队改写游标", cursor, err)
	}
	ack := &sensorv1.IngestAck{BatchId: b.BatchId, BatchSha256: b.BatchSha256, SensorRegistrationId: b.SensorRegistrationId,
		ProducerEpoch: b.ProducerEpoch, StreamId: b.StreamId, Status: sensorv1.AckStatus_ACK_STATUS_ACCEPTED, AcceptedRanges: contract.Ranges(b.Records)}
	requirePlugin(t, w.Confirm(b, ack))
	requirePlugin(t, w.Close())
	w, err = OpenWAL(path, "tenant_owned", "sensor_owned", "reg_owned", 1)
	requirePlugin(t, err)
	if err = add("first", "second", "route_2", newAlert("1"), newAlert("2")); !errors.Is(err, ErrWALFull) {
		t.Fatal("队列不足未显式背压", err)
	}
	w.MaxBytes = 64 * 1024
	requirePlugin(t, add("first", "second", "route_2", newAlert("1"), newAlert("2")))
	b, err = w.Next("alerts")
	requirePlugin(t, err)
	if len(b.Records) != 1 || b.Records[0].Sequence != 2 || b.RouteToken != "route_2" {
		t.Fatal("跨重启、跨路由重叠页没有正确去重")
	}
	if old, err := w.Source(); err != nil || old != (Source{}) {
		t.Fatal("插件游标改写了 EVE 检查点", old, err)
	}
	requirePlugin(t, w.DB.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("meta")).Put([]byte("device_alert_ids"), key(maxDeviceAlertIDs))
	}))
	if err = add("second", "third", "route_3", newAlert("3")); !errors.Is(err, ErrWALFull) {
		t.Fatal("达到身份预算时应该保留原游标", err)
	}
	if cursor, err := w.deviceAlertCursor(plugin, device); err != nil || cursor != "second" {
		t.Fatal("设备标识预算失败后游标不一致", cursor, err)
	}
}

func TestPluginBindingValidationAndLocalGuard(t *testing.T) {
	for _, ip := range []string{"192.0.2.2", "198.51.100.29", "203.0.113.19", "2001:db8::1"} {
		if !reservedTrialAddress(ip) {
			t.Fatal("保留测试地址未识别", ip)
		}
	}
	for _, ip := range []string{"bad", "127.0.0.1", "169.254.169.254", "10.3.0.2", "8.8.8.8", "::ffff:192.0.2.2"} {
		if reservedTrialAddress(ip) {
			t.Fatal("工作地址误认为保留测试地址", ip)
		}
	}
	p := pluginProfile{PluginID: "plugin", Device: response.Configuration{ID: "connector", DeviceID: "device",
		DeviceVersion: "fixture/1", Origin: "https://127.0.0.1", CAFile: "/not-used/ca", TokenFile: "/not-used/token", MaxTTLSeconds: 60}}
	file := writeProfileFixture(t, p)
	if got, err := readPluginProfiles(file); err != nil || len(got) != 1 || got[0].binding() != p.binding() {
		t.Fatal("绑定摘要不稳定", err)
	}
	for _, raw := range []string{
		`{}`, `{"schema_version":"other","profiles":[]}`,
		`{"schema_version":"response.plugin-bindings.v1","profiles":[],"untrusted":true}`,
		`{"schema_version":"response.plugin-bindings.v1","profiles":[{"plugin_id":"plugin","unknown":true}]}`,
		`{"schema_version":"response.plugin-bindings.v1","profiles":[{"plugin_id":"plugin","plugin_id":"p_two"}]}`,
	} {
		requirePlugin(t, os.WriteFile(file, []byte(raw), 0600))
		if _, err := readPluginProfiles(file); err == nil {
			t.Fatal("未知绑定结构仍被读取", raw)
		}
	}
	raw, _ := json.Marshal(map[string]any{"schema_version": "response.plugin-bindings.v1", "profiles": []pluginProfile{p, p}})
	requirePlugin(t, os.WriteFile(file, raw, 0600))
	if _, err := readPluginProfiles(file); err == nil {
		t.Fatal("两份不同设备范围共用同一插件绑定")
	}
	p.TestAddress = "192.0.2.9"
	if p.valid() {
		t.Fatal("测试目标越过本地授权范围")
	}
	p.Device.AllowedTargets = []string{"192.0.2.0/24"}
	if !p.valid() {
		t.Fatal("正确的保留地址无法登记")
	}
	p.Device.ProtectedTargets = []string{"192.0.2.9/32"}
	if p.valid() {
		t.Fatal("保护名单未覆盖插件测试目标")
	}
	for _, plan := range []pluginWritePlan{
		{Method: "PUT", Path: "/lease", Body: []response.TemplateField{{Name: "target", Value: "{{target_ip}}"}}},
		{Method: "DELETE", Path: "/lease/../lease/{rule_id}"},
		{Method: "GET", Path: "/lease"},
	} {
		if plan.valid("block") {
			t.Fatal("错误的写入计划被接受")
		}
	}
	if (pluginVerifyPlan{Path: "/lease/{rule_id}", MissingField: "code", MissingValue: "not_found"}).valid("block") {
		t.Fatal("缺少所有者和期限输出的计划被接受")
	}
}

func TestSignedTemplatePluginUsesExistingResponseLeaseProtection(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	dir := t.TempDir()
	device := &templateACLFixture{leases: map[string]response.Lease{}}
	server := httptest.NewTLSServer(device)
	defer server.Close()
	cfg := response.Configuration{ID: "plugin_connector", DeviceID: "device_fixture", DeviceVersion: "fixture/1",
		Origin: server.URL, CAFile: filepath.Join(dir, "ca.pem"), TokenFile: filepath.Join(dir, "token.json"),
		AllowedTargets: []string{"198.51.100.10/32"}, MaxTTLSeconds: 60}
	requirePlugin(t, os.WriteFile(cfg.TokenFile, []byte(`{"username":"fixture-user","password":"fixture-password"}`), 0600))
	requirePlugin(t, os.WriteFile(cfg.CAFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600))
	raw, err := os.ReadFile("../response/testdata/owned_acl_template.json")
	requirePlugin(t, err)
	var template response.Template
	requirePlugin(t, json.Unmarshal(raw, &template))
	profile := pluginProfile{PluginID: "plugin_acl", Device: cfg, TestAddress: "198.51.100.10"}
	pub, signer, err := ed25519.GenerateKey(rand.Reader)
	requirePlugin(t, err)
	w, err := OpenWAL(filepath.Join(dir, "agent.db"), "tenant_owned", "sensor_owned", "reg_owned", 4*1024*1024)
	requirePlugin(t, err)
	defer w.Close()
	plugins, err := NewPluginService(w, writeProfileFixture(t, profile), "", pub, "127.0.0.1:443")
	requirePlugin(t, err)
	defer plugins.Close()
	s, err := NewResponseService(w, "")
	requirePlugin(t, err)
	defer s.Close()
	if s.CheckConfiguration().State != "not_configured" {
		t.Fatal("只有插件时误报固定连接器配置")
	}
	requirePlugin(t, s.connectPlugins(plugins))
	version := response.PluginVersion{ID: profile.PluginID, Version: 1, Name: "联动测试", Device: "设备夹具", Kind: "template", State: "draft",
		Template: template, TemplateSHA256: template.SHA256(), CreatedAt: time.Now().UTC(), CreatedBy: "owner"}
	newCommand := func(id, kind string, payload any) control.Command {
		raw, _ := json.Marshal(payload)
		return control.Command{ID: id, TenantID: w.TenantID, SensorID: w.SensorID, RegistrationID: w.RegistrationID,
			Kind: kind, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(time.Minute).UTC(), Payload: raw}
	}
	t3 := response.PluginTrial{Version: version, Binding: profile.binding(), Stage: response.PluginCapability}
	trial := newCommand("task_trial_acl", response.PluginTrialCommand, t3)
	foreign := trial
	foreign.RegistrationID = "reg_foreign"
	if _, code, err := plugins.execute(ctx, foreign); !errors.Is(err, response.ErrInput) || code != "plugin_scope" {
		t.Fatal("跨注册代次试运行仍能调用设备", code, err)
	}
	changed := t3
	changed.Binding.BindingSHA256 = strings.Repeat("0", 64)
	if _, code, err := plugins.execute(ctx, newCommand("task_changed_binding", response.PluginTrialCommand, changed)); err == nil || code != "plugin_binding" {
		t.Fatal("本机绑定不匹配仍能试运行", code, err)
	}
	blocked, err := NewPluginService(w, writeProfileFixture(t, profile), "", pub, profile.TestAddress+":443")
	requirePlugin(t, err)
	if _, code, err := blocked.execute(ctx, trial); err == nil || code != "plugin_test_address" {
		t.Fatal("保留验收地址与管理地址冲突时仍能试运行", code, err)
	}
	blocked.Close()
	executed, code, err := plugins.execute(ctx, trial)
	if err != nil || code != "" {
		t.Fatalf("模板保留目标试运行失败 %s/%v %s", code, err, executed)
	}
	_, err = response.ReadPluginTrialResult(executed, t3)
	requirePlugin(t, err)
	toDeploy := func(v response.PluginVersion, gen int64) control.Command {
		signed, err := response.SignPlugin(response.PluginGrant{TenantID: w.TenantID, SensorID: w.SensorID, RegistrationID: w.RegistrationID,
			Binding: profile.binding(), Version: v.Version, DefinitionSHA256: v.DefinitionSHA256(),
			TrialSHA256: [3]string{strings.Repeat("1", 64), strings.Repeat("2", 64), strings.Repeat("3", 64)}}, signer)
		requirePlugin(t, err)
		return newCommand("task_activate_acl", response.PluginApplyCommand, response.PluginActivation{PluginID: v.ID, Action: response.PluginPublish,
			ExpectedGeneration: gen, Artifact: &response.PluginArtifact{Version: v, Release: signed}})
	}
	apply := func(c control.Command) error {
		report, _, err := plugins.execute(ctx, c)
		if err != nil {
			return err
		}
		return w.DB.Update(func(tx *bolt.Tx) error { return plugins.commitActivation(tx, c, report) })
	}
	requirePlugin(t, apply(toDeploy(version, 0)))
	plugins.observeConnector(ctx, version.ID)
	items := s.Health()
	if len(items) != 1 || items[0].Status != "ready" || items[0].ConfigSHA256 == cfg.SHA256() {
		t.Fatal("已签名模板未绑定到平台联动目录", items)
	}
	now := time.Now().UTC()
	a := response.Action{SchemaVersion: response.ActionSchema, ConnectorID: cfg.ID, ConfigSHA256: items[0].ConfigSHA256, DeviceID: cfg.DeviceID,
		LeaseID: "task_live_acl", OwnerSHA256: response.Owner(w.TenantID, w.SensorID, w.RegistrationID, "task_live_acl"),
		TargetIP: profile.TestAddress, RequestedAt: now, ExpiresAt: now.Add(time.Minute), Reason: "授权响应夹具"}
	block := newCommand(a.LeaseID, "response.block", a)
	got, _, err := s.Execute(ctx, block)
	requirePlugin(t, err)
	_, err = response.ReadResult(got, a, "response.block", time.Now().UTC())
	requirePlugin(t, err)
	next := version
	next.Version = 2
	if err := apply(toDeploy(next, 1)); err == nil {
		t.Fatal("没有保护仍在执行的旧版本租约")
	}
	stale := toDeploy(next, 1)
	activation, err := response.ReadPluginActivation(stale.Payload)
	requirePlugin(t, err)
	outcome, _ := json.Marshal(activation.Result())
	tasks, err := NewTaskManager(w, pub, terminalRunner{result: outcome})
	requirePlugin(t, err)
	tasks.Plugins = plugins
	encoded, signature, err := control.Encode(stale, signer)
	requirePlugin(t, err)
	requirePlugin(t, tasks.Accept(encoded, signature))
	func() {
		run, stop := context.WithTimeout(ctx, 2*time.Second)
		finished := make(chan error, 1)
		go func() { finished <- tasks.Run(run) }()
		defer func() { stop(); requirePlugin(t, <-finished) }()
		for run.Err() == nil {
			items, err := tasks.Pending()
			requirePlugin(t, err)
			for _, raw := range items {
				var receipt control.Receipt
				requirePlugin(t, json.Unmarshal(raw, &receipt))
				if receipt.State != "running" {
					if receipt.State != "failed" || receipt.Code != "plugin_deployment_changed" {
						t.Fatal("提交时出现租约冲突仍启用了新版本", receipt)
					}
					return
				}
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatal("提交冲突后采集器未交付失败回执")
	}()
	revoke := newCommand("task_revoke_acl", "response.revoke", a)
	got, _, err = s.Execute(ctx, revoke)
	requirePlugin(t, err)
	_, err = response.ReadResult(got, a, "response.revoke", time.Now().UTC())
	requirePlugin(t, err)
	requirePlugin(t, apply(toDeploy(next, 1)))
	if _, _, err = s.Execute(ctx, block); err == nil {
		t.Fatal("旧签名版本仍可发起新写入")
	}
	_, _, err = s.Execute(ctx, newCommand("task_read_old_acl", "response.read", a))
	requirePlugin(t, err)

	incompatible := profile
	incompatible.Device.MaxTTLSeconds = 120
	reopened, err := NewPluginService(w, writeProfileFixture(t, incompatible), "", pub)
	requirePlugin(t, err)
	defer reopened.Close()
	if r, err := reopened.current(version.ID); err == nil || r != nil {
		t.Fatal("改变本地安全边界后的旧签名仍能回载", err)
	}
	requirePlugin(t, w.DB.View(func(tx *bolt.Tx) error {
		if err := plugins.commitActivation(tx, toDeploy(next, 2), []byte(`{}`)); !errors.Is(err, response.ErrInput) {
			t.Fatal("本机提交接受未核实的部署证明", err)
		}
		return nil
	}))

	device.mu.Lock()
	defer device.mu.Unlock()
	if device.writes != 2 || device.removes != 2 {
		t.Fatal("试运行与授权处置各应有一对设备写入和解除")
	}
}
