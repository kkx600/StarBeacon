package control

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func reconciliationContract() RuleReconcile {
	return RuleReconcile{UnknownTaskID: "task_interrupted", UnknownCommandSHA256: Digest([]byte("command")), ExpectedSHA256: Digest([]byte("target")), TargetSHA256: Digest([]byte("target")), PreviousSHA256: Digest([]byte("previous")), ConfigSHA256: Digest([]byte("config")), ProfileSHA256: Digest([]byte("profile"))}
}

func TestSignedRuleReconciliationIsLimitedToOriginalTransaction(t *testing.T) {
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := reconciliationContract()
	now := time.Now().UTC()
	c := Command{ID: "task_reconcile", TenantID: "tenant", SensorID: "sensor", RegistrationID: "registration", Kind: "rules.reconcile", IssuedAt: now, ExpiresAt: now.Add(time.Minute)}
	c.Payload, _ = json.Marshal(p)
	raw, signature, err := Encode(c, private)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Decode(raw, signature, pub, c.TenantID, c.SensorID, c.RegistrationID, now); err != nil {
		t.Fatal(err)
	}
	p.ExpectedSHA256 = p.PreviousSHA256
	if err = p.Validate(); err != nil {
		t.Fatal("已回滚的文件也必须可核实", err)
	}
	for _, change := range []func(*RuleReconcile){
		func(p *RuleReconcile) { p.UnknownTaskID = "../foreign" },
		func(p *RuleReconcile) { p.UnknownCommandSHA256 = "" },
		func(p *RuleReconcile) { p.ExpectedSHA256 = Digest([]byte("third-party")) },
		func(p *RuleReconcile) { p.TargetSHA256 = "gg" },
		func(p *RuleReconcile) { p.PreviousSHA256 = strings.ToUpper(p.PreviousSHA256) },
		func(p *RuleReconcile) { p.ConfigSHA256 = "01" },
		func(p *RuleReconcile) { p.ProfileSHA256 = " " + p.ProfileSHA256 },
	} {
		candidate := reconciliationContract()
		change(&candidate)
		c.Payload, _ = json.Marshal(candidate)
		if _, _, err = Encode(c, private); err == nil {
			t.Fatal("签发了超出原事务的核实任务", candidate)
		}
	}
	for _, payload := range []string{`null`, `{}`, `{"unknown_task_id":"task_interrupted","path":"/tmp/foreign"}`, string(raw) + ` {}`} {
		c.Payload = json.RawMessage(payload)
		if Validate(c) == nil {
			t.Fatal("核实接受了路径、缺失或多余参数", payload)
		}
	}
}

func TestRuleReconciliationNeedsCompleteNativeReceipt(t *testing.T) {
	p := reconciliationContract()
	valid := RuleReconcileResult{Verified: true, UnknownTaskID: p.UnknownTaskID, UnknownCommandSHA256: p.UnknownCommandSHA256, ActiveSHA256: p.ExpectedSHA256, ConfigSHA256: p.ConfigSHA256, ProfileSHA256: p.ProfileSHA256, Stats: json.RawMessage(`[{"rules_loaded":2,"rules_failed":0}]`)}
	if valid.Validate(p) != nil {
		t.Fatal("完整核实回执被拒绝")
	}
	for _, change := range []func(*RuleReconcileResult){
		func(r *RuleReconcileResult) { r.Verified = false },
		func(r *RuleReconcileResult) { r.UnknownTaskID = "other" },
		func(r *RuleReconcileResult) { r.UnknownCommandSHA256 = Digest([]byte("foreign")) },
		func(r *RuleReconcileResult) { r.ActiveSHA256 = p.PreviousSHA256 },
		func(r *RuleReconcileResult) { r.ConfigSHA256 = Digest([]byte("different config")) },
		func(r *RuleReconcileResult) { r.ProfileSHA256 = Digest([]byte("different profile")) },
	} {
		candidate := valid
		change(&candidate)
		if candidate.Validate(p) == nil {
			t.Fatal("不属于原事务的回执被接受", candidate)
		}
	}
	for _, stats := range []string{`{`, `null`, `[]`, `[{}]`, `[{"rules_loaded":2}]`, `[{"rules_failed":0}]`, `[{"rules_loaded":0,"rules_failed":0}]`, `[{"rules_loaded":2,"rules_failed":1}]`, `[{"rules_loaded":2,"rules_failed":0},{"rules_loaded":2,"rules_failed":0}]`} {
		candidate := valid
		candidate.Stats = json.RawMessage(stats)
		if candidate.Validate(p) == nil {
			t.Fatal("缺失或不完整装载被报告为核实成功", stats)
		}
	}
	p.ExpectedSHA256 = "invalid"
	if valid.Validate(p) == nil {
		t.Fatal("回执绕过无效核实契约")
	}
}
