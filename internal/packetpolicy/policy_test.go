package packetpolicy

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestChangeAndObservationBindRevisionAndDigest(t *testing.T) {
	encrypted, dedup := 0, 10
	base := Policy{NetworkDomain: "domain_demo", Revision: 1, Mode: Smart, PlainBytes: 65536,
		EncryptedBytes: &encrypted, DedupMillis: &dedup, Protect: []netip.Prefix{netip.MustParsePrefix("2001:db8::/64")}}
	next := base
	next.Revision, next.Mode = 2, Full
	change := Change{ExpectedRevision: 1, ExpectedSHA256: base.Digest(), Policy: next}
	data, err := json.Marshal(change)
	if err != nil || json.Unmarshal(data, &change) != nil || change.Validate() != nil {
		t.Fatal("合法策略不能解析", err)
	}
	for _, raw := range []string{"{}", `null`, "{" + strings.Repeat(" ", MaxBytes+1) + string(data[1:]),
		strings.Replace(string(data), `"expected_revision":1`, `"expected_revision":1,"expected_revision":1`, 1),
		strings.Replace(string(data), `"expected_revision":1`, `"expected_revision":"1"`, 1),
		strings.Replace(string(data), `"expected_revision":1`, `"expected_revision":2`, 1),
		strings.Replace(string(data), `"expected_revision":1`, `"expected_revision":1,"mode":"smart"`, 1),
		strings.Replace(string(data), `"encrypted_bytes":0`, `"encrypted_bytes":null`, 1),
		strings.Replace(string(data), `"dedup_millis":10`, `"dedup_millis":9`, 1),
		strings.Replace(string(data), `"2001:db8::/64"`, `"2001:db8::1/64"`, 1),
		strings.Replace(string(data), `"2001:db8::/64"`, `"2001:db8::/64","2001:db8::/64"`, 1)} {
		var rejected Change
		if json.Unmarshal([]byte(raw), &rejected) == nil {
			t.Fatal("非法参数通过校验")
		}
	}
	old := Observation{Policy: base, SHA256: base.Digest(), Origin: "file"}
	if !old.Matches(change) {
		t.Fatal("文件策略应能作为基线")
	}
	now := time.Now().UTC()
	remote := Observation{Policy: next, SHA256: next.Digest(), Origin: "platform", TaskID: "task_id", AppliedAt: &now}
	if !change.Confirms(remote, "task_id") || change.Confirms(remote, "wrong_task") || old.Matches(Change{ExpectedRevision: 1, ExpectedSHA256: next.Digest(), Policy: next}) {
		t.Fatal("任务身份或基线未绑定")
	}
	for _, mutate := range []func(*Observation){
		func(o *Observation) { o.SHA256 = "" }, func(o *Observation) { o.TaskID = "../bad" },
		func(o *Observation) { o.AppliedAt = nil }, func(o *Observation) { o.Origin = "local" },
		func(o *Observation) { o.Origin = "guess" },
	} {
		bad := remote
		mutate(&bad)
		if bad.Valid() {
			t.Fatal("异常策略回执通过校验")
		}
	}
	if policy := (Observation{Policy: next, SHA256: next.Digest(), Origin: "local", AppliedAt: &now}); !policy.Valid() {
		t.Fatal("拒绝有效本机策略")
	}
	tooMany := next
	tooMany.Observe = make([]netip.Prefix, 129)
	if tooMany.Valid() {
		t.Fatal("超过名单限额")
	}
}

func TestStatusDistinguishesUnavailableAndZeroUsage(t *testing.T) {
	now := time.Now().UTC()
	blank := Status{State: "not_configured", ObservedAt: now, QuotaBytes: "0", SegmentBytes: "0"}
	if !blank.Valid() || (Status{}).Valid() {
		t.Fatal("未启用状态与空响应不可混淆")
	}
	base := Status{State: "unavailable", ObservedAt: now, QuotaBytes: "1073741824", SegmentBytes: "16777216", RotateSeconds: 300}
	if !base.Valid() {
		t.Fatal("缺少可用配置的心跳仍应报告真实暂存范围")
	}
	for _, mutate := range []func(*Status){
		func(s *Status) { s.State = "ready" }, func(s *Status) { s.State = "bad" },
		func(s *Status) { s.QuotaBytes = "099" }, func(s *Status) { s.SegmentBytes = "20" },
		func(s *Status) { s.RotateSeconds = 0 }, func(s *Status) { v := "-1"; s.ReservedBytes = &v },
	} {
		bad := base
		mutate(&bad)
		if bad.Valid() {
			t.Fatal("不正确的统计通过检查")
		}
	}
}
