package response

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestConnectorQueryCursorBindingAndHealth(t *testing.T) {
	q := ConnectorQuery{Limit: 20}
	if q.Validate() != nil {
		t.Fatal("默认查询无效")
	}
	q.Cursor = q.Next("sensor_b", "connector_a")
	if sensor, connector, err := q.Position(); err != nil || sensor != "sensor_b" || connector != "connector_a" {
		t.Fatal(sensor, connector, err)
	}
	for _, bad := range []ConnectorQuery{{Limit: 0}, {Limit: 101}, {Limit: 20, SensorID: "UPPER"}, {Limit: 20, DeviceID: "device/a"}, {Limit: 20, Status: "unknown"}, {Limit: 20, Cursor: strings.Repeat("x", 513)}, {Limit: 20, Cursor: "%%%"}, {Limit: 20, Cursor: base64.RawURLEncoding.EncodeToString([]byte(`{"sensor_id":"sensor_b","sensor_id":"sensor_b"}`))}, {Limit: 21, Cursor: q.Cursor}, {Limit: 20, DeviceID: "device_b", Cursor: q.Cursor}} {
		if bad.Validate() == nil {
			t.Fatal("非法条件或跨查询游标被接受", bad)
		}
	}
	for _, status := range []string{"ready", "unverified", "unavailable"} {
		v := ConnectorQuery{Limit: 100, Status: status, SensorID: "sensor_b", DeviceID: "device_b"}
		if v.Validate() != nil {
			t.Fatal(status)
		}
	}
	h := Health{ConnectorID: "connector_ok", DeviceID: "device_ok", Version: "fixture/1", Status: "ready", ConfigSHA256: strings.Repeat("a", 64), ObservedAt: time.Now().UTC(), MaxTTLSeconds: 30}
	if !h.Valid() {
		t.Fatal("合法观测无效")
	}
	for _, change := range []func(*Health){func(v *Health) { v.ConnectorID = "UPPER" }, func(v *Health) { v.DeviceID = "invalid/id" }, func(v *Health) { v.Version = "v\n" }, func(v *Health) { v.ConfigSHA256 = "bad" }, func(v *Health) { v.MaxTTLSeconds = 29 }, func(v *Health) { v.MaxTTLSeconds = 3601 }, func(v *Health) { v.Status = "unknown" }, func(v *Health) { v.ObservedAt = time.Time{} }} {
		v := h
		change(&v)
		if v.Valid() {
			t.Fatal("异常观测有效", v)
		}
	}
	h.Status = "unverified"
	h.ObservedAt = time.Time{}
	if !h.Valid() {
		t.Fatal("初始待核验状态无效")
	}
	var c connectorCursor
	raw, _ := base64.RawURLEncoding.DecodeString(q.Cursor)
	_ = json.Unmarshal(raw, &c)
	c.ConnectorID = "UPPER"
	raw, _ = json.Marshal(c)
	q.Cursor = base64.RawURLEncoding.EncodeToString(raw)
	if q.Validate() == nil {
		t.Fatal("异常游标标识未拒绝")
	}
}
