package control

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/response"
)

func TestResponseCommandsBindOriginalOwnerAndAbsoluteExpiry(t *testing.T) {
	now := time.Now().UTC()
	c := Command{ID: "task_response", TenantID: "tenant_response", SensorID: "sensor_response", RegistrationID: "registration_response", Kind: "response.block", IssuedAt: now, ExpiresAt: now.Add(25 * time.Second)}
	a := response.Action{SchemaVersion: response.ActionSchema, ConnectorID: "connector_response", DeviceID: "device_response", ConfigSHA256: Digest([]byte("config")), LeaseID: c.ID, OwnerSHA256: response.Owner(c.TenantID, c.SensorID, c.RegistrationID, c.ID), TargetIP: "198.51.100.10", RequestedAt: now, ExpiresAt: now.Add(30 * time.Second), Reason: "明确人工授权"}
	c.Payload, _ = json.Marshal(a)
	if err := Validate(c); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"response.read", "response.revoke"} {
		v := c
		v.Kind = kind
		v.ID = "task_observe"
		v.IssuedAt = now.Add(time.Hour)
		v.ExpiresAt = v.IssuedAt.Add(time.Minute)
		if err := Validate(v); err != nil {
			t.Fatal("回读不重新计时", err)
		}
	}
	for _, change := range []func(*Command){func(v *Command) { v.TenantID = "tenant_other" }, func(v *Command) { v.SensorID = "sensor_other" }, func(v *Command) { v.RegistrationID = "registration_other" }, func(v *Command) { v.ID = "task_other" }, func(v *Command) { v.ExpiresAt = a.ExpiresAt }, func(v *Command) { v.IssuedAt = now.Add(time.Second) }, func(v *Command) { v.Payload = json.RawMessage(`{}`) }} {
		v := c
		change(&v)
		if Validate(v) == nil {
			t.Fatal("签名任务未绑定原始授权")
		}
	}
}
