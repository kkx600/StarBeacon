//go:build integration

package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/admin"
	"github.com/kkx600/StarBeacon/internal/agent"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/platform"
	"github.com/kkx600/StarBeacon/internal/store"
)

// 此用例核对独立 PostgreSQL 的任务准入与回执约束；实际网卡由 captureintegration 验收。
func TestCaptureTaskTransactionsRejectStaleHealthAndFalseSuccess(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	f := newIsolatedDatabase(t, ctx)
	tenant, password := store.RandomID("it_capture_task_"), store.Token()
	require(t, admin.Bootstrap(ctx, f.Owner, tenant, "采集任务验收", tenant, password, "admin"))
	dir := t.TempDir()
	ca := filepath.Join(dir, "pki")
	require(t, admin.DevPKI(ca))
	identity, err := admin.Provision(ctx, f.Owner, tenant, "sensor_capture", "采集验收探针", ca, filepath.Join(dir, "sensor"))
	require(t, err)
	pub, signer, err := ed25519.GenerateKey(rand.Reader)
	require(t, err)
	client := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime, Signer: signer}, tenant, password)
	var u model.Principal
	client.request("GET", "/auth/me", "", nil, &u, 200)
	value := false
	settings := agent.CaptureSettings{Interfaces: []string{"eth0"}, Threads: 1, BPFFilter: "tcp port 80", Promiscuous: &value}
	state := agent.CaptureState{CaptureSettings: settings, Managed: true, Revision: 4, AppliedRevision: 4, Status: "running", ConfigSHA256: control.Digest([]byte("fixture-config")), PID: 1234, ObservedAt: time.Now().UTC()}
	baseHealth := func() model.HostHealth {
		raw, _ := json.Marshal(state)
		return model.HostHealth{ObservedAt: time.Now().UTC(), Capture: raw, CaptureStatus: "running", TaskCapabilities: []string{"capture.configure", "diagnostics"}, CommandSignerSHA256: control.Digest(pub), NetworkInterfaces: []model.NetworkInterface{{Name: "eth0", MAC: "02:00:00:00:00:01", Up: true, MTU: 1500}}}
	}
	input := control.CaptureConfiguration{ExpectedRevision: &state.Revision, ExpectedConfigSHA256: state.ConfigSHA256, ExpectedSettingsSHA256: control.CaptureSettingsDigest(control.CaptureSettings(settings)), Settings: control.CaptureSettings(settings)}
	input.Settings.BPFFilter = "tcp port 8088"
	body := map[string]any{"kind": "capture.configure", "capture_configuration": input}
	countTasks := func() int {
		var n int
		require(t, f.Runtime.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM sensor_tasks WHERE tenant_id=$1`, tenant).Scan(&n)
		}))
		return n
	}
	for name, change := range map[string]func(*model.HostHealth){
		"missing_capture": func(h *model.HostHealth) { h.Capture = nil },
		"not_managed": func(h *model.HostHealth) {
			var v map[string]any
			_ = json.Unmarshal(h.Capture, &v)
			v["managed"] = false
			h.Capture, _ = json.Marshal(v)
		},
		"changed_revision": func(h *model.HostHealth) {
			var v map[string]any
			_ = json.Unmarshal(h.Capture, &v)
			v["revision"] = 5
			h.Capture, _ = json.Marshal(v)
		},
		"changed_digest": func(h *model.HostHealth) {
			var v map[string]any
			_ = json.Unmarshal(h.Capture, &v)
			v["config_sha256"] = control.Digest([]byte("other"))
			h.Capture, _ = json.Marshal(v)
		},
		"changed_settings": func(h *model.HostHealth) {
			var v map[string]any
			_ = json.Unmarshal(h.Capture, &v)
			v["bpf_filter"] = "udp"
			h.Capture, _ = json.Marshal(v)
		},
		"pending": func(h *model.HostHealth) {
			var v map[string]any
			_ = json.Unmarshal(h.Capture, &v)
			v["status"] = "pending"
			h.Capture, _ = json.Marshal(v)
		},
		"stale_observation":  func(h *model.HostHealth) { h.ObservedAt = time.Now().UTC().Add(-time.Minute) },
		"future_observation": func(h *model.HostHealth) { h.ObservedAt = time.Now().UTC().Add(2 * time.Minute) },
		"closed_interface":   func(h *model.HostHealth) { h.NetworkInterfaces[0].Up = false },
		"loopback":           func(h *model.HostHealth) { h.NetworkInterfaces[0].Loopback = true },
		"missing_inventory":  func(h *model.HostHealth) { h.NetworkInterfaces = nil },
		"wrong_mac":          func(h *model.HostHealth) { h.NetworkInterfaces[0].MAC = "01:02:03:04:05:06:07:08" },
		"wrong_trust":        func(h *model.HostHealth) { h.CommandSignerSHA256 = control.Digest([]byte("other-key")) },
		"missing_capability": func(h *model.HostHealth) { h.TaskCapabilities = []string{"diagnostics"} },
	} {
		t.Run(name, func(t *testing.T) {
			h := baseHealth()
			change(&h)
			require(t, f.Runtime.Heartbeat(ctx, identity, h))
			c := *client
			c.t = t
			c.request("POST", "/sensors/"+identity.SensorID+"/tasks", "capture_reject_"+name, body, nil, 409)
			if countTasks() != 0 {
				t.Fatal("准入失败留下任务")
			}
		})
	}
	require(t, f.Runtime.Heartbeat(ctx, identity, baseHealth()))
	require(t, f.Owner.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE sensors SET last_seen=now()-interval '60 seconds' WHERE tenant_id=$1 AND id=$2`, tenant, identity.SensorID)
		return err
	}))
	client.request("POST", "/sensors/"+identity.SensorID+"/tasks", "capture_offline", body, nil, 409)
	require(t, f.Runtime.Heartbeat(ctx, identity, baseHealth()))
	for _, bad := range []map[string]any{{"kind": "capture.configure"}, {"kind": "diagnostics", "capture_configuration": input}, {"kind": "capture.configure", "capture_configuration": input, "package_id": "rules_unwanted", "revision": 1}} {
		client.request("POST", "/sensors/"+identity.SensorID+"/tasks", "capture_bad_parameters", bad, nil, 400)
	}
	badInput := input
	badInput.ExpectedRevision = nil
	client.request("POST", "/sensors/"+identity.SensorID+"/tasks", "capture_bad_revision", map[string]any{"kind": "capture.configure", "capture_configuration": badInput}, nil, 400)
	var accepted struct {
		ID string `json:"id"`
	}
	client.request("POST", "/sensors/"+identity.SensorID+"/tasks", "capture_valid_task", body, &accepted, 202)
	var repeated struct {
		ID string `json:"id"`
	}
	client.request("POST", "/sensors/"+identity.SensorID+"/tasks", "capture_valid_task", body, &repeated, 202)
	if accepted.ID == "" || accepted.ID != repeated.ID || countTasks() != 1 {
		t.Fatal("并发幂等依据没有保留单个任务")
	}
	client.request("POST", "/sensors/"+identity.SensorID+"/tasks", "capture_other_task", body, nil, 409)
	delivery, err := f.Runtime.NextTask(ctx, identity)
	require(t, err)
	if delivery == nil {
		t.Fatal("任务未进入投递链路")
	}
	command, err := control.Decode(delivery.Command, delivery.Signature, pub, tenant, identity.SensorID, identity.RegistrationID, time.Now().UTC())
	require(t, err)
	proof := state
	proof.CaptureSettings = agent.CaptureSettings(input.Settings)
	proof.AppliedSettings = &proof.CaptureSettings
	proof.Revision, proof.AppliedRevision = 5, 5
	proof.ConfigSHA256 = control.Digest([]byte("fixture-target-config"))
	proof.ObservedAt = time.Now().UTC()
	finished := time.Now().UTC()
	receipt := control.Receipt{CommandID: command.ID, CommandSHA256: control.Digest(delivery.Command), State: "succeeded", StartedAt: finished.Add(-time.Second), FinishedAt: &finished}
	for _, change := range []func(*agent.CaptureState){func(s *agent.CaptureState) { s.Status = "pending" }, func(s *agent.CaptureState) { s.PID = 0 }, func(s *agent.CaptureState) { s.AppliedRevision = 4 }, func(s *agent.CaptureState) { s.BPFFilter = "udp" }} {
		r := proof
		change(&r)
		receipt.Result, _ = json.Marshal(r)
		if f.Runtime.SaveReceipt(ctx, identity, receipt) == nil {
			t.Fatal("无实际生效回读仍被记为成功")
		}
	}
	receipt.Result, _ = json.Marshal(proof)
	receipt.Code = "failed"
	if f.Runtime.SaveReceipt(ctx, identity, receipt) == nil {
		t.Fatal("矛盾成功代码被接受")
	}
	receipt.Code = ""
	require(t, f.Runtime.SaveReceipt(ctx, identity, receipt))
	require(t, f.Runtime.SaveReceipt(ctx, identity, receipt))
	rows, err := f.Runtime.Tasks(ctx, tenant, identity.SensorID)
	require(t, err)
	if len(rows) != 1 || rows[0].State != "succeeded" {
		t.Fatal("有效回读未提交", rows)
	}
	other := store.RandomID("it_capture_other_")
	require(t, admin.Bootstrap(ctx, f.Owner, other, "作用域验收", other, password, "admin"))
	otherClient := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime, Signer: signer}, other, password)
	otherClient.request("POST", "/sensors/"+identity.SensorID+"/tasks", "capture_cross_tenant", body, nil, 404)
	otherRows, err := f.Runtime.Tasks(ctx, other, "")
	require(t, err)
	if len(otherRows) != 0 {
		t.Fatal("采集任务跨租户可见")
	}
	if _, err = f.Runtime.CreateTask(ctx, u, identity.SensorID, "capture.configure", "capture_bad_signer", mustJSON(t, input), nil); err == nil {
		t.Fatal("无效签名密钥被接受")
	}
}

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(v)
	require(t, err)
	return raw
}
