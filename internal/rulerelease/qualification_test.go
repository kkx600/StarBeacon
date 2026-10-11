package rulerelease

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/control"
)

func qualificationFixture(t *testing.T) (control.RulePackage, [3]Evidence, time.Time) {
	t.Helper()
	now := time.Date(2026, 10, 3, 8, 0, 0, 0, time.UTC)
	p := control.RulePackage{PackageID: "rules_test", Revision: 3, EngineVersion: "8.0.7", Text: `alert http any any -> any any (http.uri; content:"/test"; sid:1001001; rev:1;)`}
	p.SHA256 = control.Digest([]byte(p.Text))
	var facts [3]Evidence
	for i, id := range []string{"task_validate", "task_positive", "task_negative"} {
		c := control.Command{ID: id, TenantID: "tenant_test", SensorID: "sensor_test", RegistrationID: "reg_test", IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(29 * time.Minute), Kind: "rules.validate"}
		c.Payload, _ = control.RulePayload(p)
		v := map[string]any{"engine_version": p.EngineVersion, "package_id": p.PackageID, "revision": p.Revision, "config_sha256": strings.Repeat("a", 64), "profile_sha256": strings.Repeat("b", 64), "syntax": "passed", "replay": "not_run", "sha256": p.SHA256}
		if i > 0 {
			c.Kind = "rules.replay"
			sampleSHA := control.Digest([]byte(id))
			c.Payload, _ = control.ReplayPayload(control.Replay{SampleID: "sample_" + id, SampleSHA256: sampleSHA, SampleSize: 835, RuleMode: "package", Package: &p})
			v["replay"] = "completed"
			v["rule_mode"] = "package"
			v["profile"] = "offline-bounded-v1"
			v["checksum_validation"] = true
			v["rules_sha256"] = p.SHA256
			v["sample_sha256"] = sampleSHA
			v["packets_processed"] = "9"
			v["anomaly_count"] = 0
			v["sample_metadata"] = map[string]any{"packets": 9, "truncated_packets": 0}
			v["alert_count"] = map[bool]int{true: 1, false: 0}[i == 1]
		}
		raw, _ := json.Marshal(v)
		finished := now.Add(-time.Second)
		facts[i] = Evidence{Command: c, Receipt: control.Receipt{CommandID: id, State: "succeeded", StartedAt: now.Add(-10 * time.Second), FinishedAt: &finished, Result: raw}}
	}
	return p, facts, now
}

func alterResult(t *testing.T, facts *[3]Evidence, index int, key string, value any) {
	t.Helper()
	var v map[string]any
	if err := json.Unmarshal(facts[index].Receipt.Result, &v); err != nil {
		t.Fatal(err)
	}
	if value == nil {
		delete(v, key)
	} else {
		v[key] = value
	}
	facts[index].Receipt.Result, _ = json.Marshal(v)
}

func TestReleaseRequiresExactPackageDeviceProfileAndIndependentSamples(t *testing.T) {
	p, facts, now := qualificationFixture(t)
	grant, err := Qualify(p, facts, strings.Repeat("c", 64), now)
	if err != nil || grant.Validate() != nil || grant.PositiveReplayTaskID != facts[1].Command.ID {
		t.Fatal("完整正反样本资格未建立", err)
	}
	changed := facts
	alterResult(t, &changed, 1, "log", "different native log")
	next, err := Qualify(p, changed, strings.Repeat("c", 64), now)
	if err != nil || next.PositiveReceiptSHA256 == grant.PositiveReceiptSHA256 {
		t.Fatal("回执内容没有绑定授权摘要", err)
	}
	cases := []struct {
		name   string
		change func(control.RulePackage, *[3]Evidence)
	}{
		{"different device", func(_ control.RulePackage, f *[3]Evidence) { f[2].Command.SensorID = "another_sensor" }},
		{"different registration", func(_ control.RulePackage, f *[3]Evidence) { f[1].Command.RegistrationID = "another_reg" }},
		{"different tenant", func(_ control.RulePackage, f *[3]Evidence) { f[1].Command.TenantID = "another_tenant" }},
		{"reused validation", func(_ control.RulePackage, f *[3]Evidence) {
			f[1].Command.ID = f[0].Command.ID
			f[1].Receipt.CommandID = f[0].Command.ID
		}},
		{"reused replay", func(_ control.RulePackage, f *[3]Evidence) {
			f[2].Command.ID = f[1].Command.ID
			f[2].Receipt.CommandID = f[1].Command.ID
		}},
		{"failed receipt", func(_ control.RulePackage, f *[3]Evidence) { f[1].Receipt.State = "failed" }},
		{"unknown receipt", func(_ control.RulePackage, f *[3]Evidence) { f[2].Receipt.State = "unknown" }},
		{"error code", func(_ control.RulePackage, f *[3]Evidence) { f[1].Receipt.Code = "resource_limit" }},
		{"receipt task mismatch", func(_ control.RulePackage, f *[3]Evidence) { f[1].Receipt.CommandID = "another_task" }},
		{"missing finished", func(_ control.RulePackage, f *[3]Evidence) { f[0].Receipt.FinishedAt = nil }},
		{"before start", func(_ control.RulePackage, f *[3]Evidence) { v := now.Add(-time.Hour); f[0].Receipt.FinishedAt = &v }},
		{"expired qualification", func(_ control.RulePackage, f *[3]Evidence) {
			v := now.Add(-25 * time.Hour)
			f[0].Receipt.StartedAt = v.Add(-time.Second)
			f[0].Receipt.FinishedAt = &v
		}},
		{"future receipt", func(_ control.RulePackage, f *[3]Evidence) {
			v := now.Add(2 * time.Minute)
			f[1].Receipt.FinishedAt = &v
		}},
		{"after command expiry", func(_ control.RulePackage, f *[3]Evidence) { f[1].Command.ExpiresAt = now.Add(-20 * time.Second) }},
		{"future command", func(_ control.RulePackage, f *[3]Evidence) { f[1].Command.IssuedAt = now.Add(time.Hour) }},
		{"wrong check command", func(_ control.RulePackage, f *[3]Evidence) { f[0].Command.Kind = "diagnostics" }},
		{"wrong replay command", func(_ control.RulePackage, f *[3]Evidence) { f[1].Command.Kind = "diagnostics" }},
		{"damaged package", func(_ control.RulePackage, f *[3]Evidence) { f[0].Command.Payload = json.RawMessage(`{`) }},
		{"damaged replay", func(_ control.RulePackage, f *[3]Evidence) { f[1].Command.Payload = json.RawMessage(`{`) }},
		{"missing replay package", func(_ control.RulePackage, f *[3]Evidence) {
			f[1].Command.Payload = json.RawMessage(`{"rule_mode":"registered"}`)
		}},
		{"different revision", func(p control.RulePackage, f *[3]Evidence) {
			p.Revision++
			f[1].Command.Payload, _ = control.ReplayPayload(control.Replay{RuleMode: "package", Package: &p})
		}},
		{"damaged result", func(_ control.RulePackage, f *[3]Evidence) { f[0].Receipt.Result = json.RawMessage(`{`) }},
		{"bad syntax", func(_ control.RulePackage, f *[3]Evidence) { alterResult(t, f, 0, "syntax", "failed") }},
		{"different package hash", func(_ control.RulePackage, f *[3]Evidence) { alterResult(t, f, 0, "sha256", strings.Repeat("d", 64)) }},
		{"different engine", func(_ control.RulePackage, f *[3]Evidence) { alterResult(t, f, 1, "engine_version", "7.0.0") }},
		{"different config", func(_ control.RulePackage, f *[3]Evidence) {
			alterResult(t, f, 1, "config_sha256", strings.Repeat("d", 64))
		}},
		{"different profile", func(_ control.RulePackage, f *[3]Evidence) {
			alterResult(t, f, 2, "profile_sha256", strings.Repeat("d", 64))
		}},
		{"missing config", func(_ control.RulePackage, f *[3]Evidence) { alterResult(t, f, 1, "config_sha256", nil) }},
		{"resource limited", func(_ control.RulePackage, f *[3]Evidence) { alterResult(t, f, 1, "resource_limit", "memory") }},
		{"no packet evidence", func(_ control.RulePackage, f *[3]Evidence) { alterResult(t, f, 1, "packets_processed", "0") }},
		{"bad packet evidence", func(_ control.RulePackage, f *[3]Evidence) { alterResult(t, f, 1, "packets_processed", "bad") }},
		{"positive missed", func(_ control.RulePackage, f *[3]Evidence) { alterResult(t, f, 1, "alert_count", 0) }},
		{"negative alerted", func(_ control.RulePackage, f *[3]Evidence) { alterResult(t, f, 2, "alert_count", 1) }},
		{"missing alert count", func(_ control.RulePackage, f *[3]Evidence) { alterResult(t, f, 1, "alert_count", nil) }},
		{"negative count", func(_ control.RulePackage, f *[3]Evidence) { alterResult(t, f, 1, "alert_count", -1) }},
		{"incomplete replay", func(_ control.RulePackage, f *[3]Evidence) { alterResult(t, f, 1, "replay", "failed") }},
		{"unknown profile", func(_ control.RulePackage, f *[3]Evidence) { alterResult(t, f, 1, "profile", "unknown") }},
		{"checksum disabled", func(_ control.RulePackage, f *[3]Evidence) { alterResult(t, f, 1, "checksum_validation", false) }},
		{"missing checksum", func(_ control.RulePackage, f *[3]Evidence) { alterResult(t, f, 1, "checksum_validation", nil) }},
		{"truncated sample", func(_ control.RulePackage, f *[3]Evidence) {
			alterResult(t, f, 1, "sample_metadata", map[string]any{"packets": 9, "truncated_packets": 1})
		}},
		{"packet count mismatch", func(_ control.RulePackage, f *[3]Evidence) {
			alterResult(t, f, 1, "sample_metadata", map[string]any{"packets": 10, "truncated_packets": 0})
		}},
		{"missing metadata", func(_ control.RulePackage, f *[3]Evidence) { alterResult(t, f, 1, "sample_metadata", nil) }},
		{"native anomaly", func(_ control.RulePackage, f *[3]Evidence) { alterResult(t, f, 1, "anomaly_count", 1) }},
		{"sample hash mismatch", func(_ control.RulePackage, f *[3]Evidence) {
			alterResult(t, f, 1, "sample_sha256", strings.Repeat("d", 64))
		}},
		{"same positive and negative", func(_ control.RulePackage, f *[3]Evidence) {
			var p control.Replay
			_ = json.Unmarshal(f[1].Command.Payload, &p)
			f[2].Command.Payload = f[1].Command.Payload
			alterResult(t, f, 2, "sample_sha256", p.SampleSHA256)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, facts, now := qualificationFixture(t)
			tc.change(p, &facts)
			if _, err := Qualify(p, facts, strings.Repeat("c", 64), now); !errors.Is(err, ErrQualification) {
				t.Fatal("未经核对的证据取得发布资格", err)
			}
		})
	}
	for _, hash := range []string{"", "short", strings.Repeat("C", 64), strings.Repeat("z", 64)} {
		if _, err := Qualify(p, facts, hash, now); !errors.Is(err, ErrQualification) {
			t.Fatal("非法基线摘要取得发布资格", err)
		}
	}
}
