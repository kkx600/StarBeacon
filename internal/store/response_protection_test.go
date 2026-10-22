package store

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/control"
	responseapi "github.com/kkx600/StarBeacon/internal/response"
	"github.com/kkx600/StarBeacon/internal/watchlist"
)

func TestResponseProtectionBindsOriginalCommandAndAuthorizedInstant(t *testing.T) {
	now := time.Now().UTC()
	check := watchlist.ResponseCheck{SchemaVersion: watchlist.ResponseSchema, CheckedAt: now, StateSHA256: watchlist.Digest([]watchlist.Reference{}), Matches: []watchlist.Reference{}}
	checkRaw, _ := json.Marshal(check)
	proof := ResponseProtection{SchemaVersion: "response.protection.v1", CommandSHA256: control.Digest([]byte("original signed command")), CheckSHA256: control.Digest(checkRaw), Check: check}
	task := SensorTask{Kind: "response.block", ResponseAction: &responseapi.Action{RequestedAt: now, ExpiresAt: now.Add(time.Minute)}}
	raw, _ := json.Marshal(proof)
	if got, err := readResponseProtection(raw, proof.CommandSHA256, task); err != nil || got == nil || got.CheckSHA256 != proof.CheckSHA256 {
		t.Fatal("原命令名单核对依据读取失败", err)
	}
	later := proof
	later.Check.CheckedAt = now.Add(time.Second)
	laterRaw, _ := json.Marshal(later.Check)
	later.CheckSHA256 = control.Digest(laterRaw)
	laterRaw, _ = json.Marshal(later)
	if _, err := readResponseProtection(laterRaw, proof.CommandSHA256, task); err != nil {
		t.Fatal("锁后实际数据库核对时刻被误判", err)
	}
	for _, at := range []time.Time{now.Add(-31 * time.Second), now.Add(31 * time.Second), now.Add(time.Minute)} {
		changed := check
		changed.CheckedAt = at
		if validResponseProtectionCheck(changed, *task.ResponseAction) {
			t.Fatal("越过授权时钟窗口或绝对到期的核对被接受")
		}
	}
	for _, mutate := range []func(*ResponseProtection){
		func(p *ResponseProtection) { p.SchemaVersion = "unknown" },
		func(p *ResponseProtection) { p.CommandSHA256 = control.Digest([]byte("other")) },
		func(p *ResponseProtection) { p.CheckSHA256 = strings.Repeat("0", 64) },
		func(p *ResponseProtection) { p.Check.SchemaVersion = "unknown" },
		func(p *ResponseProtection) { p.Check.CheckedAt = now.Add(time.Nanosecond) },
		func(p *ResponseProtection) { p.Check.StateSHA256 = strings.Repeat("z", 64) },
		func(p *ResponseProtection) { p.Check.StateSHA256 = strings.Repeat("A", 64) },
		func(p *ResponseProtection) { p.Check.StateSHA256 = "" },
		func(p *ResponseProtection) { p.Check.Matches = nil },
		func(p *ResponseProtection) { p.Check.Matches = []watchlist.Reference{{ID: "protected"}} },
	} {
		other := proof
		mutate(&other)
		value, _ := json.Marshal(other)
		if _, err := readResponseProtection(value, proof.CommandSHA256, task); err == nil {
			t.Fatal("命令、时刻或名单材料变化被接受")
		}
	}
	for _, kind := range []string{"response.read", "response.revoke", "diagnostics"} {
		other := task
		other.Kind = kind
		if _, err := readResponseProtection(raw, proof.CommandSHA256, other); err == nil {
			t.Fatal("名单依据被嫁接到其他动作")
		}
	}
	for _, value := range [][]byte{nil, []byte("null")} {
		if got, err := readResponseProtection(value, proof.CommandSHA256, task); err != nil || got != nil {
			t.Fatal("历史任务缺少名单依据不能被当作曾核验", err)
		}
	}
	for _, value := range []string{"{}", "[]", "not json", strings.Repeat(" ", 32769), strings.Replace(string(raw), `"schema_version":`, `"extra":true,"schema_version":`, 1), strings.Replace(string(raw), `"check":{`, `"check":{"schema_version":"duplicate",`, 1), strings.Replace(string(raw), `"check":{`, `"check":{"extra":1,`, 1)} {
		if _, err := readResponseProtection([]byte(value), proof.CommandSHA256, task); err == nil {
			t.Fatal("损坏或歧义的名单依据被接受")
		}
	}
	task.ResponseAction = nil
	if _, err := readResponseProtection(raw, proof.CommandSHA256, task); err == nil {
		t.Fatal("没有原始响应授权仍接受名单依据")
	}
}
