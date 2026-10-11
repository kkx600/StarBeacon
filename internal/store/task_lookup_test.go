package store

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/kkx600/StarBeacon/internal/control"
	responseapi "github.com/kkx600/StarBeacon/internal/response"
)

func TestStoredResponseCommandSeparatesEnvelopeFromNestedAuthorization(t *testing.T) {
	now := time.Now().UTC()
	a := responseapi.Action{SchemaVersion: "response.action.v1", ConnectorID: "connector_owned", ConfigSHA256: control.Digest([]byte("config")), DeviceID: "device_owned", LeaseID: "task_owned", OwnerSHA256: responseapi.Owner("tenant_owned", "sensor_owned", "registration_owned", "task_owned"), TargetIP: "198.51.100.10", RequestedAt: now, ExpiresAt: now.Add(time.Minute), Reason: "管理员明确授权"}
	payload, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	c := control.Command{ID: "task_owned", TenantID: "tenant_owned", SensorID: "sensor_owned", RegistrationID: "registration_owned", Kind: "response.block", IssuedAt: now, ExpiresAt: now.Add(30 * time.Second), Payload: payload}
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := storedResponseCommand(raw); err != nil || got.ID != c.ID || string(got.Payload) != string(payload) {
		t.Fatal("合法嵌套授权未保持原封套", err)
	}
	text := string(raw)
	for _, input := range []string{
		`null`, `[]`, `{}`, strings.Repeat(" ", 8193),
		strings.Replace(text, `"id":`, `"ID":`, 1),
		strings.Replace(text, `"kind":"response.block"`, `"kind":"response.block","kind":"response.read"`, 1),
		strings.Replace(text, `"reason":`, `"reason":"重复键","reason":`, 1),
		strings.Replace(text, `"reason":`, `"Reason":`, 1),
		strings.Replace(text, `"kind":"response.block"`, `"reason":"跨层级替换"`, 1),
		strings.Replace(text, `"kind":"response.block"`, `"kind":"response.block","reason":"额外根字段"`, 1),
		strings.Replace(text, `"target_ip":"198.51.100.10"`, `"target_ip":"198.51.100.10","kind":"response.block"`, 1),
		strings.Replace(text, `"lease_id":"task_owned"`, `"lease_id":"task_other"`, 1),
	} {
		if _, err := storedResponseCommand([]byte(input)); err == nil {
			t.Fatal("歧义、跨层级或不完整命令被接受")
		}
	}
}

func TestStoredTaskBindingPreservesSignedBytesAcrossDatabaseTimePrecision(t *testing.T) {
	// 使用实际驱动编解码，防止用本地时间运算冒充 PostgreSQL 往返行为。
	expiry := time.Date(2026, 10, 11, 7, 0, 0, 123456789, time.UTC)
	c := control.Command{ID: "task_owned", TenantID: "tenant_owned", SensorID: "sensor_owned", RegistrationID: "registration_owned", Kind: "diagnostics", IssuedAt: expiry.Add(-time.Minute), ExpiresAt: expiry, Payload: json.RawMessage(`{}`)}
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	codec := pgtype.NewMap()
	wire, err := codec.Encode(pgtype.TimestamptzOID, pgtype.BinaryFormatCode, expiry, nil)
	if err != nil {
		t.Fatal(err)
	}
	var databaseExpiry time.Time
	if err = codec.Scan(pgtype.TimestamptzOID, pgtype.BinaryFormatCode, wire, &databaseExpiry); err != nil {
		t.Fatal(err)
	}
	task := SensorTask{ID: c.ID, SensorID: c.SensorID, Kind: c.Kind, ExpiresAt: databaseExpiry}
	if expiry.Equal(databaseExpiry) || !storedTaskBinding(c, raw, task, c.TenantID, c.RegistrationID, control.Digest(raw)) {
		t.Fatal("真实驱动精度差异被误判为签名任务损坏")
	}
	for _, change := range []func(*SensorTask){func(v *SensorTask) { v.ID = "task_other" }, func(v *SensorTask) { v.SensorID = "sensor_other" }, func(v *SensorTask) { v.Kind = "response.block" }, func(v *SensorTask) { v.ExpiresAt = v.ExpiresAt.Add(time.Microsecond) }} {
		other := task
		change(&other)
		if storedTaskBinding(c, raw, other, c.TenantID, c.RegistrationID, control.Digest(raw)) {
			t.Fatal("元数据绑定变化被接受")
		}
	}
	if storedTaskBinding(c, append(raw, ' '), task, c.TenantID, c.RegistrationID, control.Digest(raw)) || storedTaskBinding(c, raw, task, "tenant_other", c.RegistrationID, control.Digest(raw)) || storedTaskBinding(c, raw, task, c.TenantID, "registration_other", control.Digest(raw)) {
		t.Fatal("原字节、租户或注册代次变化被接受")
	}
}
