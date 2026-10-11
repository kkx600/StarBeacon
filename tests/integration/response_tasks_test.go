//go:build integration

package integration

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
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/kkx600/StarBeacon/internal/accounts"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/platform"
	responseapi "github.com/kkx600/StarBeacon/internal/response"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/transport"
)

// 此端点仅证明协议行为，不连接商业设备，不把受理或回读称为流量阻断。
type genericHTTPDevice struct {
	mu      sync.Mutex
	config  responseapi.Configuration
	file    string
	leases  map[string]responseapi.Lease
	writes  int
	deletes int
}

func newGenericHTTPDevice(t *testing.T, dir string) *genericHTTPDevice {
	t.Helper()
	f := &genericHTTPDevice{leases: map[string]responseapi.Lease{}}
	token := store.Token()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") != "Bearer "+token {
			w.WriteHeader(401)
			_, _ = w.Write([]byte(`{}`))
			return
		}
		if r.URL.Path == "/starbeacon/v1/device" && r.Method == "GET" {
			_ = json.NewEncoder(w).Encode(map[string]any{"schema_version": "response.device.v1", "device_id": "device_protocol", "version": "protocol-fixture/1", "native_ttl": true, "separate_leases": true, "conditional_revoke": true, "max_ttl_seconds": 3600, "observed_at": time.Now().UTC()})
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/starbeacon/v1/leases/")
		value, found := f.leases[id]
		if r.Method == "PUT" {
			var a responseapi.Action
			if json.NewDecoder(r.Body).Decode(&a) != nil || a.LeaseID != id || !a.ExpiresAt.After(time.Now().UTC()) {
				w.WriteHeader(400)
				_, _ = w.Write([]byte(`{}`))
				return
			}
			if found {
				if value.OwnerSHA256 != a.OwnerSHA256 || value.TargetIP != a.TargetIP || !value.ExpiresAt.Equal(a.ExpiresAt) {
					w.WriteHeader(409)
					_, _ = w.Write([]byte(`{}`))
					return
				}
			} else {
				f.writes++
				value = responseapi.Lease{SchemaVersion: "response.lease.v1", DeviceID: "device_protocol", LeaseID: id, OwnerSHA256: a.OwnerSHA256, TargetIP: a.TargetIP, ExpiresAt: a.ExpiresAt, State: "active"}
				f.leases[id] = value
			}
			w.WriteHeader(202)
			_, _ = w.Write([]byte(`{}`))
			return
		}
		if !found {
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`{"schema_version":"response.error.v1","code":"lease_not_found"}`))
			return
		}
		if r.Method == "DELETE" {
			if r.Header.Get("If-Match") != `"`+value.OwnerSHA256+`"` {
				w.WriteHeader(412)
				_, _ = w.Write([]byte(`{}`))
				return
			}
			if value.State == "active" {
				f.deletes++
				value.State = "revoked"
			}
		}
		value.ObservedAt = time.Now().UTC()
		if value.State == "active" && !value.ExpiresAt.After(value.ObservedAt) {
			value.State = "expired"
		}
		f.leases[id] = value
		_ = json.NewEncoder(w).Encode(value)
	}))
	t.Cleanup(server.Close)
	ca := filepath.Join(dir, "response-device-ca.crt")
	secret := filepath.Join(dir, "response-device-token")
	require(t, os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600))
	require(t, os.WriteFile(secret, []byte(token), 0600))
	f.config = responseapi.Configuration{ID: "connector_protocol", DeviceID: "device_protocol", DeviceVersion: "protocol-fixture/1", Origin: server.URL, CAFile: ca, TokenFile: secret, AllowedTargets: []string{"198.51.100.0/24", "192.0.2.0/24"}, ProtectedTargets: []string{"198.51.100.1/32"}, MaxTTLSeconds: 3600}
	f.file = filepath.Join(dir, "response-connectors.json")
	raw, err := json.Marshal(responseapi.File{SchemaVersion: "response.connectors.v1", RetentionDays: 180, Connectors: []responseapi.Configuration{f.config}})
	require(t, err)
	require(t, os.WriteFile(f.file, raw, 0600))
	return f
}
func verifyNativeResponse(t *testing.T, ctx context.Context, client *liveHTTP, sensor string, device *genericHTTPDevice) {
	t.Helper()
	var sensors struct {
		Items []model.Sensor `json:"items"`
	}
	eventually(t, ctx, "采集器核验固定 HTTPS 联动设备", func() bool {
		client.request("GET", "/sensors", "", nil, &sensors, 200)
		for _, row := range sensors.Items {
			var health model.HostHealth
			if row.ID == sensor && json.Unmarshal(row.Health, &health) == nil {
				for _, h := range health.ResponseConnectors {
					if h.ConnectorID == device.config.ID && h.Status == "ready" && h.ConfigSHA256 == device.config.SHA256() {
						return true
					}
				}
			}
		}
		return false
	})
	input := responseapi.Request{Kind: "response.block", Intent: responseapi.Intent{ConnectorID: device.config.ID, ConfigSHA256: device.config.SHA256(), TargetIP: "198.51.100.10", TTLSeconds: 300, Reason: "受控 HTTP 协议验收"}}
	var accepted, again map[string]string
	key := store.RandomID("response_native_")
	path := "/sensors/" + sensor + "/response-tasks"
	client.request("POST", path, key, input, &accepted, 202)
	client.request("POST", path, key, input, &again, 202)
	if accepted["id"] == "" || again["id"] != accepted["id"] {
		t.Fatal("原封禁提交未稳定确认")
	}
	var tasks struct {
		Items []store.SensorTask `json:"items"`
	}
	wait := func(id string, kind string) store.SensorTask {
		var found store.SensorTask
		eventually(t, ctx, "签名联动任务完成设备回读", func() bool {
			client.request("GET", "/tasks/"+id, "", nil, &found, 200)
			return found.State == "succeeded"
		})
		if found.Kind != kind || found.ResponseAction == nil || !found.RetainUntil.After(time.Now()) {
			t.Fatal("任务未携带冻结联动授权")
		}
		var receipt control.Receipt
		require(t, json.Unmarshal(found.Receipt, &receipt))
		var result responseapi.Result
		require(t, json.Unmarshal(receipt.Result, &result))
		require(t, result.Validate(*found.ResponseAction, kind, receipt.FinishedAt.UTC()))
		return found
	}
	original := wait(accepted["id"], "response.block")
	initial := string(original.Receipt)
	for _, kind := range []string{"response.read", "response.revoke", "response.read"} {
		v := responseapi.Request{Kind: kind, Intent: responseapi.Intent{ConnectorID: device.config.ID, ConfigSHA256: device.config.SHA256(), OriginalTaskID: original.ID, Reason: "核对原租约，不延长期限"}}
		client.request("POST", path, store.RandomID("response_verify_"), v, &accepted, 202)
		current := wait(accepted["id"], kind)
		if current.ResponseAction.LeaseID != original.ID || !current.ResponseAction.ExpiresAt.Equal(original.ResponseAction.ExpiresAt) {
			t.Fatal("回读或解封改变原租约")
		}
	}
	client.request("GET", "/tasks?sensor_id="+sensor, "", nil, &tasks, 200)
	for _, task := range tasks.Items {
		if task.ID == original.ID && string(task.Receipt) != initial {
			t.Fatal("核对改写了原执行回执")
		}
	}
	client.request("POST", path, key, input, &again, 202)
	if again["id"] != original.ID {
		t.Fatal("解封后原提交被重新创建")
	}
	device.mu.Lock()
	defer device.mu.Unlock()
	if device.writes != 1 || device.deletes != 1 {
		t.Fatal("端到端重复写入或误解除", device.writes, device.deletes)
	}
}

func responseTaskFixture(t *testing.T, ctx context.Context) (*isolatedDatabase, model.Principal, ed25519.PrivateKey, responseapi.Request, string) {
	t.Helper()
	f, u, _, password := accountFixture(t, ctx)
	_, signer, err := ed25519.GenerateKey(rand.Reader)
	require(t, err)
	health := model.HostHealth{ObservedAt: time.Now().UTC(), CommandSignerSHA256: control.Digest(signer.Public().(ed25519.PublicKey)), TaskCapabilities: []string{"response.block", "response.read", "response.revoke"}, ResponseConnectors: []responseapi.Health{{ConnectorID: "connector_protocol", DeviceID: "device_protocol", Version: "protocol-fixture/1", ConfigSHA256: control.Digest([]byte("test-config")), Status: "ready", ObservedAt: time.Now().UTC(), MaxTTLSeconds: 3600}}}
	raw, _ := json.Marshal(health)
	require(t, f.Owner.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO sensors(tenant_id,id,name,registration_id,active,last_seen,health) VALUES($1,'sensor_response','受控联动','registration_response',true,now(),$2)`, u.TenantID, raw)
		return err
	}))
	input := responseapi.Request{Kind: "response.block", Intent: responseapi.Intent{ConnectorID: "connector_protocol", ConfigSHA256: health.ResponseConnectors[0].ConfigSHA256, TargetIP: "198.51.100.10", TTLSeconds: 60, Reason: "存储授权边界测试"}}
	return f, u, signer, input, password
}
func TestResponseTasksTenantRoleIdempotencyAndReceiptBinding(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	f, u, signer, input, _ := responseTaskFixture(t, ctx)
	id, err := f.Runtime.CreateResponseTask(ctx, u, "sensor_response", "response_original", input, signer)
	require(t, err)
	old, err := f.Runtime.CreateResponseTask(ctx, u, "sensor_response", "response_original", input, signer)
	require(t, err)
	if old != id {
		t.Fatal("不稳定提交")
	}
	changed := input
	changed.TTLSeconds = 61
	if _, err = f.Runtime.CreateResponseTask(ctx, u, "sensor_response", "response_original", changed, signer); !errors.Is(err, store.ErrConflict) {
		t.Fatal("请求键不同参数未冲突", err)
	}
	rows, err := f.Runtime.Tasks(ctx, u.TenantID, "sensor_response")
	require(t, err)
	if len(rows) != 1 || rows[0].ResponseAction == nil {
		t.Fatal("冻结联动授权缺失")
	}
	action := *rows[0].ResponseAction
	if action.LeaseID != id || action.OwnerSHA256 != responseapi.Owner(u.TenantID, "sensor_response", "registration_response", id) || action.ExpiresAt.Sub(action.RequestedAt) != time.Minute || !rows[0].ExpiresAt.Before(action.ExpiresAt) {
		t.Fatal("租约未固定")
	}
	identity := transport.SensorIdentity{TenantID: u.TenantID, SensorID: "sensor_response", RegistrationID: "registration_response"}
	delivery, err := f.Runtime.NextTask(ctx, identity)
	require(t, err)
	if delivery == nil || delivery.ID != id {
		t.Fatal("任务未进入独立控制投递")
	}
	finished := time.Now().UTC()
	result := responseapi.Result{SchemaVersion: "response.result.v1", ConnectorID: action.ConnectorID, ConfigSHA256: action.ConfigSHA256, Verified: true, Effect: "not_observed", Observation: responseapi.Lease{SchemaVersion: responseapi.LeaseSchema, DeviceID: action.DeviceID, LeaseID: action.LeaseID, OwnerSHA256: action.OwnerSHA256, TargetIP: action.TargetIP, ExpiresAt: action.ExpiresAt, State: "active", ObservedAt: finished}}
	receipt := control.Receipt{CommandID: id, CommandSHA256: control.Digest(delivery.Command), State: "succeeded", StartedAt: finished.Add(-time.Millisecond), FinishedAt: &finished}
	for _, change := range []func(*responseapi.Result){func(v *responseapi.Result) { v.Verified = false }, func(v *responseapi.Result) { v.Effect = "blocked" }, func(v *responseapi.Result) { v.Observation.TargetIP = "198.51.100.11" }, func(v *responseapi.Result) { v.Observation.OwnerSHA256 = control.Digest([]byte("other")) }} {
		v := result
		change(&v)
		receipt.Result, _ = json.Marshal(v)
		if err = f.Runtime.SaveReceipt(ctx, identity, receipt); err == nil {
			t.Fatal("无绑定回执被接受")
		}
	}
	receipt.Result, _ = json.Marshal(result)
	require(t, f.Runtime.SaveReceipt(ctx, identity, receipt))
	require(t, f.Runtime.SaveReceipt(ctx, identity, receipt))
	read := responseapi.Request{Kind: "response.read", Intent: responseapi.Intent{ConnectorID: input.ConnectorID, ConfigSHA256: input.ConfigSHA256, OriginalTaskID: id, Reason: "独立核对原状态"}}
	readID, err := f.Runtime.CreateResponseTask(ctx, u, "sensor_response", "response_read_original", read, signer)
	require(t, err)
	rows, err = f.Runtime.Tasks(ctx, u.TenantID, "sensor_response")
	require(t, err)
	for _, row := range rows {
		if row.ID == readID && (row.ResponseAction == nil || row.ResponseAction.LeaseID != id) {
			t.Fatal("回读引用了新租约")
		}
	}
	var role = model.Principal{ID: u.ID, TenantID: u.TenantID, Role: "viewer"}
	if _, err = f.Runtime.CreateResponseTask(ctx, role, "sensor_response", "response_viewer", input, signer); !errors.Is(err, responseapi.ErrPermission) {
		t.Fatal("只读账号")
	}
	other := u
	other.TenantID = "tenant_other"
	if _, err = f.Runtime.CreateResponseTask(ctx, other, "sensor_response", "response_cross", input, signer); err == nil {
		t.Fatal("跨租户授权")
	}
	require(t, f.Owner.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE users SET active=false,revision=revision+1 WHERE tenant_id=$1 AND id=$2`, u.TenantID, u.ID)
		return err
	}))
	if _, err = f.Runtime.CreateResponseTask(ctx, u, "sensor_response", "response_original", input, signer); !errors.Is(err, responseapi.ErrPermission) {
		t.Fatal("撤回账号仍确认原提交", err)
	}
}

func TestResponseTaskFailureCutsDoNotCommitAuthorization(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()
	f, u, signer, input, _ := responseTaskFixture(t, ctx)
	for _, cut := range []string{"SET LOCAL lock_timeout", "SELECT pg_advisory_xact_lock_shared", "SELECT u.active,u.role", "SELECT id,request_sha256", "SELECT registration_id", "SELECT health,last_seen", "SELECT count(*) FROM sensor_tasks", "INSERT INTO sensor_tasks", "INSERT INTO operation_audits"} {
		broken, _ := disconnectedStore(t, ctx, f.RuntimeDSN, cut)
		_, err := broken.CreateResponseTask(ctx, u, "sensor_response", store.RandomID("response_cut_"), input, signer)
		broken.Close()
		if err == nil {
			t.Fatal("故障注入未失败", cut)
		}
	}
	rows, err := f.Runtime.Tasks(ctx, u.TenantID, "sensor_response")
	require(t, err)
	if len(rows) != 0 {
		t.Fatal("中断事务留下有效授权")
	}
	for _, key := range []string{"bad", "UPPER_KEY", "invalid/key"} {
		if _, err = f.Runtime.CreateResponseTask(ctx, u, "sensor_response", key, input, signer); !errors.Is(err, responseapi.ErrInput) {
			t.Fatal("直接存储参数边界")
		}
	}
	for _, change := range []func(*model.HostHealth){func(v *model.HostHealth) { v.ObservedAt = time.Now().UTC().Add(-time.Minute) }, func(v *model.HostHealth) { v.CommandSignerSHA256 = control.Digest([]byte("other")) }, func(v *model.HostHealth) { v.ResponseConnectors = nil }, func(v *model.HostHealth) { v.ResponseConnectors[0].Status = "unavailable" }, func(v *model.HostHealth) { v.ResponseConnectors[0].ConfigSHA256 = control.Digest([]byte("other")) }, func(v *model.HostHealth) { v.ResponseConnectors[0].ObservedAt = time.Now().UTC().Add(time.Minute) }} {
		health := model.HostHealth{ObservedAt: time.Now().UTC(), TaskCapabilities: []string{"response.block", "response.read", "response.revoke"}, CommandSignerSHA256: control.Digest(signer.Public().(ed25519.PublicKey)), ResponseConnectors: []responseapi.Health{{ConnectorID: input.ConnectorID, DeviceID: "device_protocol", Version: "protocol-fixture/1", ConfigSHA256: input.ConfigSHA256, Status: "ready", ObservedAt: time.Now().UTC(), MaxTTLSeconds: 3600}}}
		change(&health)
		raw, _ := json.Marshal(health)
		require(t, f.Owner.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE sensors SET health=$3,last_seen=now() WHERE tenant_id=$1 AND id=$2`, u.TenantID, "sensor_response", raw)
			return err
		}))
		if _, err = f.Runtime.CreateResponseTask(ctx, u, "sensor_response", store.RandomID("response_unready_"), input, signer); !errors.Is(err, responseapi.ErrUnavailable) {
			t.Fatal("不具备条件的设备被授权", err)
		}
	}
}
func TestResponseHTTPProtocolNativeTTLActuallyExpires(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	f := newGenericHTTPDevice(t, t.TempDir())
	client, err := responseapi.NewClient(f.config)
	require(t, err)
	defer client.Close()
	now := time.Now().UTC()
	a := responseapi.Action{SchemaVersion: responseapi.ActionSchema, ConnectorID: f.config.ID, ConfigSHA256: f.config.SHA256(), DeviceID: f.config.DeviceID, LeaseID: "task_expiry", OwnerSHA256: responseapi.Owner("tenant_expiry", "sensor_expiry", "registration_expiry", "task_expiry"), TargetIP: "198.51.100.10", RequestedAt: now, ExpiresAt: now.Add(30 * time.Second), Reason: "原生绝对期限协议验证"}
	result, err := client.Execute(ctx, "response.block", a)
	require(t, err)
	if result.Observation.State != "active" {
		t.Fatal("尚未回读生效")
	}
	timer := time.NewTimer(time.Until(a.ExpiresAt) + 50*time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case <-timer.C:
	}
	result, err = client.Execute(ctx, "response.read", a)
	require(t, err)
	if result.Observation.State != "expired" {
		t.Fatal("到期未独立确认")
	}
	if _, err = client.Execute(ctx, "response.block", a); !errors.Is(err, responseapi.ErrInput) {
		t.Fatal("过期原授权再次创建")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.writes != 1 || f.deletes != 0 {
		t.Fatal("到期依赖平台 DELETE 或重新续期")
	}
}

func TestResponseTaskHTTPAuthorizationQuotaAndCurrentRegistration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Second)
	defer cancel()
	f, u, signer, input, password := responseTaskFixture(t, ctx)
	active := true
	viewer, err := f.Runtime.CreateUser(ctx, u, "response_viewer_create", accounts.Create{Username: "response_viewer", Password: password, Role: "viewer", Active: &active})
	require(t, err)
	a := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime, Signer: signer}, u.Username, password)
	v := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime, Signer: signer}, viewer.Username, password)
	b := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime, Signer: signer}, "users_owned_b", password)
	path := "/sensors/sensor_response/response-tasks"
	v.request("POST", path, "response_viewer_write", input, nil, 403)
	noCSRF := *a
	noCSRF.csrf = ""
	noCSRF.request("POST", path, "response_csrf_missing", input, nil, 403)
	b.request("POST", path, "response_foreign_write", input, nil, 404)
	a.request("POST", path+"?unexpected=1", "response_query_reject", input, nil, 400)
	missing := authenticatedFaultHTTP(t, ctx, f.Runtime, &platform.API{DB: f.Runtime}, u.Username, password)
	missing.request("POST", path, "response_missing_signer", input, nil, 503)
	require(t, f.Owner.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		var raw []byte
		if err := tx.QueryRow(ctx, `SELECT health FROM sensors WHERE tenant_id=$1 AND id='sensor_response'`, u.TenantID).Scan(&raw); err != nil {
			return err
		}
		var h model.HostHealth
		if err := json.Unmarshal(raw, &h); err != nil {
			return err
		}
		h.ObservedAt = time.Now().UTC()
		h.ResponseConnectors[0].ObservedAt = h.ObservedAt
		raw, _ = json.Marshal(h)
		_, err := tx.Exec(ctx, `UPDATE sensors SET last_seen=now(),health=$2 WHERE tenant_id=$1 AND id='sensor_response'`, u.TenantID, raw)
		return err
	}))
	var accepted, again map[string]string
	a.request("POST", path, "response_http_original", input, &accepted, 202)
	a.request("POST", path, "response_http_original", input, &again, 202)
	if accepted["id"] != again["id"] {
		t.Fatal("HTTP 同键重复任务")
	}
	require(t, f.Owner.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO sensor_tasks(tenant_id,id,sensor_id,registration_id,kind,idempotency_key,request_sha256,command,signature,command_sha256,created_by,expires_at,retain_until,state) SELECT tenant_id,'task_quota_'||g,sensor_id,registration_id,kind,'response_quota_'||g,request_sha256,command,signature,command_sha256,created_by,expires_at,retain_until,'cancelled' FROM sensor_tasks CROSS JOIN generate_series(1,1023) AS g WHERE tenant_id=$1 AND id=$2`, u.TenantID, accepted["id"])
		return err
	}))
	a.request("POST", path, "response_http_over_quota", input, nil, 429)
	a.request("POST", path, "response_http_original", input, &again, 202)
	if accepted["id"] != again["id"] {
		t.Fatal("额度用尽改变原提交")
	}
	// 历史任务引用注册身份时，注册代次不能通过直接更新解除归属约束。
	err = f.Owner.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE sensors SET registration_id='registration_replaced' WHERE tenant_id=$1 AND id='sensor_response'`, u.TenantID)
		return err
	})
	var constraint *pgconn.PgError
	if !errors.As(err, &constraint) || constraint.Code != "23503" || constraint.ConstraintName != "sensor_tasks_tenant_id_sensor_id_registration_id_fkey" {
		t.Fatal("历史任务的注册身份约束没有生效", err)
	}
	read := responseapi.Request{Kind: "response.read", Intent: responseapi.Intent{ConnectorID: input.ConnectorID, ConfigSHA256: input.ConfigSHA256, OriginalTaskID: accepted["id"], Reason: "核对原租约"}}
	a.request("POST", path, "response_replaced_read", read, nil, 429)
	require(t, f.Owner.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM sensor_tasks WHERE tenant_id=$1 AND id LIKE 'task_quota_%'`, u.TenantID)
		return err
	}))
	a.request("POST", path, "response_replaced_read", read, nil, 404)
	// 同一真实任务完成投递后允许回读；伪造另一注册代次的有效签名仍须拒绝。
	delivery, err := f.Runtime.NextTask(ctx, transport.SensorIdentity{TenantID: u.TenantID, SensorID: "sensor_response", RegistrationID: "registration_response"})
	require(t, err)
	if delivery == nil || delivery.ID != accepted["id"] {
		t.Fatal("没有投递原始联动任务")
	}
	a.request("POST", path, "response_delivered_busy", read, nil, 409)
	finished := time.Now().UTC()
	require(t, f.Runtime.SaveReceipt(ctx, transport.SensorIdentity{TenantID: u.TenantID, SensorID: "sensor_response", RegistrationID: "registration_response"}, control.Receipt{CommandID: delivery.ID, CommandSHA256: control.Digest(delivery.Command), State: "unknown", Code: "result_unknown", Result: json.RawMessage(`{}`), StartedAt: finished.Add(-time.Millisecond), FinishedAt: &finished}))
	a.request("POST", path, "response_delivered_read", read, nil, 202)
	var original control.Command
	require(t, json.Unmarshal(delivery.Command, &original))
	original.RegistrationID = "registration_replaced"
	raw, err := json.Marshal(original)
	require(t, err)
	signature := ed25519.Sign(signer, control.SignedBytes(raw))
	require(t, f.Owner.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE sensor_tasks SET command=$3,signature=$4,command_sha256=$5 WHERE tenant_id=$1 AND id=$2`, u.TenantID, accepted["id"], raw, signature, control.Digest(raw))
		return err
	}))
	a.request("POST", path, "response_wrong_registration", read, nil, 400)
}
