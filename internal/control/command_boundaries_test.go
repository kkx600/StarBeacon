package control

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func boundaryCommand() Command {
	now := time.Now().UTC()
	return Command{ID: "task_bound", TenantID: "tenant_bound", SensorID: "sensor_bound", RegistrationID: "reg_bound", Kind: "diagnostics", IssuedAt: now, ExpiresAt: now.Add(time.Hour), Payload: json.RawMessage(`{}`)}
}

func TestCommandValidationRejectsUnsafeSignedInputs(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	valid := boundaryCommand()
	pkg := RulePackage{PackageID: "pkg_bound", Revision: 1, EngineVersion: "8.0.7", Text: `alert tcp any any -> any any (sid:1000001;)`}
	pkg.SHA256 = Digest([]byte(pkg.Text))
	rp := Replay{SampleID: "sample_bound", SampleSHA256: Digest([]byte("sample")), SampleSize: 24, RuleMode: "registered"}
	cases := []struct {
		name   string
		change func(*Command)
	}{
		{"invalid_id", func(c *Command) { c.ID = "../task" }},
		{"missing_identity", func(c *Command) { c.RegistrationID = "" }},
		{"zero_time", func(c *Command) { c.IssuedAt = time.Time{} }},
		{"reversed_time", func(c *Command) { c.ExpiresAt = c.IssuedAt }},
		{"overlong_lifetime", func(c *Command) { c.ExpiresAt = c.IssuedAt.Add(25 * time.Hour) }},
		{"empty_payload", func(c *Command) { c.Payload = nil }},
		{"malformed_payload", func(c *Command) { c.Payload = json.RawMessage(`{`) }},
		{"oversized_payload", func(c *Command) { c.Payload = json.RawMessage(`"` + strings.Repeat("a", MaxPayload) + `"`) }},
		{"diagnostics_parameters", func(c *Command) { c.Payload = json.RawMessage(`{"shell":"id"}`) }},
		{"replay_unknown_field", func(c *Command) { c.Kind = "rules.replay"; c.Payload = json.RawMessage(`{"extra":true}`) }},
		{"replay_bad_digest", func(c *Command) {
			p := rp
			p.SampleSHA256 = "zz"
			c.Kind = "rules.replay"
			c.Payload, _ = ReplayPayload(p)
		}},
		{"replay_bad_size", func(c *Command) {
			p := rp
			p.SampleSize = MaxPayload * 101
			c.Kind = "rules.replay"
			c.Payload, _ = ReplayPayload(p)
		}},
		{"replay_bad_mode", func(c *Command) {
			p := rp
			p.RuleMode = "current"
			c.Kind = "rules.replay"
			c.Payload, _ = ReplayPayload(p)
		}},
		{"replay_missing_package", func(c *Command) {
			p := rp
			p.RuleMode = "package"
			c.Kind = "rules.replay"
			c.Payload, _ = ReplayPayload(p)
		}},
		{"replay_invalid_package", func(c *Command) {
			p := rp
			bad := pkg
			bad.SHA256 = "bad"
			p.Package = &bad
			p.RuleMode = "package"
			c.Kind = "rules.replay"
			c.Payload, _ = ReplayPayload(p)
		}},
		{"rule_unknown_field", func(c *Command) { c.Kind = "rules.validate"; c.Payload = json.RawMessage(`{"shell":true}`) }},
		{"rule_wrong_version", func(c *Command) {
			p := pkg
			p.EngineVersion = "7.0.0"
			c.Kind = "rules.validate"
			c.Payload, _ = RulePayload(p)
		}},
		{"rule_wrong_digest", func(c *Command) { p := pkg; p.SHA256 = "bad"; c.Kind = "rules.apply"; c.Payload, _ = RulePayload(p) }},
		{"rule_missing_revision", func(c *Command) { p := pkg; p.Revision = 0; c.Kind = "rules.validate"; c.Payload, _ = RulePayload(p) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := valid
			tc.change(&c)
			if Validate(c) == nil {
				t.Fatal("非法任务通过了参数校验")
			}
			raw, err := json.Marshal(c)
			if err == nil {
				sig := ed25519.Sign(priv, SignedBytes(raw))
				if _, err = Decode(raw, sig, pub, c.TenantID, c.SensorID, c.RegistrationID, time.Now()); err == nil {
					t.Fatal("已签名非法任务进入执行入口")
				}
			}
		})
	}
	for _, mode := range []string{"registered", "package"} {
		p := rp
		p.RuleMode = mode
		if mode == "package" {
			p.Package = &pkg
		}
		c := valid
		c.Kind = "rules.replay"
		c.Payload, err = ReplayPayload(p)
		if err != nil {
			t.Fatal(err)
		}
		raw, sig, err := Encode(c, priv)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = Decode(raw, sig, pub, c.TenantID, c.SensorID, c.RegistrationID, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	base, _, err := Encode(valid, priv)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range [][]byte{[]byte(`{`), append(append([]byte(nil), base...), []byte(` {}`)...), []byte(strings.Replace(string(base), `"kind":"diagnostics"`, `"kind":"diagnostics","shell":"id"`, 1))} {
		if _, err = Decode(raw, ed25519.Sign(priv, SignedBytes(raw)), pub, valid.TenantID, valid.SensorID, valid.RegistrationID, time.Now()); err == nil {
			t.Fatal("签名不能使无效或多余 JSON 成为有效任务")
		}
	}
	if _, _, err = Encode(valid, nil); err == nil {
		t.Fatal("缺少私钥仍签发任务")
	}
	if _, _, err = Encode(Command{}, priv); err == nil {
		t.Fatal("签发了无效任务")
	}
	if _, err = encodeJSON(make(chan int)); err == nil {
		t.Fatal("编码失败没有传递")
	}
	for _, raw := range []string{`{`, `{} {}`, `{} trailing`} {
		if _, err = JSONDigest([]byte(raw)); err == nil {
			t.Fatal("无效 JSON 摘要被接受")
		}
	}
	large := pkg
	large.Text = strings.Repeat("\n", 600*1024)
	if _, err = RulePayload(large); err == nil {
		t.Fatal("JSON 转义后的规则包超限未拒绝")
	}
	p := rp
	p.Package = &large
	if _, err = ReplayPayload(p); err == nil {
		t.Fatal("JSON 转义后的重放参数超限未拒绝")
	}
}

func TestSigningKeysProtectPrivateFilesAndAtomicCreation(t *testing.T) {
	dir := t.TempDir()
	privPath := filepath.Join(dir, "sign.key")
	pubPath := filepath.Join(dir, "sign.pub")
	if err := GenerateKeys(privPath, privPath); err == nil {
		t.Fatal("私钥与公钥覆盖同一文件")
	}
	if err := GenerateKeys(privPath, pubPath); err != nil {
		t.Fatal(err)
	}
	priv, err := PrivateKey(privPath)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := PublicKey(pubPath)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(pub, []byte("binding"), ed25519.Sign(priv, []byte("binding"))) {
		t.Fatal("生成密钥不能验签")
	}
	for _, path := range []string{privPath, pubPath} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("密钥权限错误", err)
		}
	}
	if _, err := PrivateKey(""); err != nil {
		t.Fatal(err)
	}
	if _, err := PublicKey(""); err != nil {
		t.Fatal(err)
	}
	if _, err := PrivateKey(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("接受不存在的私钥")
	}
	if _, err := PublicKey(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("接受不存在的公钥")
	}
	if err := os.Chmod(privPath, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := PrivateKey(privPath); err == nil {
		t.Fatal("接受公开可读的私钥")
	}
	if err := os.Chmod(privPath, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.key")
	if err := os.Symlink(privPath, link); err != nil {
		t.Fatal(err)
	}
	if _, err := PrivateKey(link); err == nil {
		t.Fatal("接受符号链接私钥")
	}
	if _, err := PrivateKey(dir); err == nil {
		t.Fatal("接受目录作为私钥")
	}
	for _, raw := range [][]byte{[]byte("invalid"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("invalid")})} {
		p := filepath.Join(dir, "invalid.key")
		if err := os.WriteFile(p, raw, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := PrivateKey(p); err == nil {
			t.Fatal("接受损坏私钥")
		}
		if _, err := PublicKey(p); err == nil {
			t.Fatal("接受损坏公钥")
		}
	}
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, public := range []bool{false, true} {
		var der []byte
		if public {
			der, err = x509.MarshalPKIXPublicKey(&ec.PublicKey)
		} else {
			der, err = x509.MarshalPKCS8PrivateKey(ec)
		}
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, "wrong.key")
		if err = os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "KEY", Bytes: der}), 0600); err != nil {
			t.Fatal(err)
		}
		if public {
			_, err = PublicKey(p)
		} else {
			_, err = PrivateKey(p)
		}
		if err == nil {
			t.Fatal("接受不支持的签名算法")
		}
	}
	fresh := filepath.Join(dir, "fresh.key")
	before, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatal(err)
	}
	if err = GenerateKeys(fresh, pubPath); err == nil {
		t.Fatal("覆盖已有公钥")
	}
	if _, err = os.Stat(fresh); !os.IsNotExist(err) {
		t.Fatal("生成失败留下半套密钥", err)
	}
	after, err := os.ReadFile(pubPath)
	if err != nil || string(before) != string(after) {
		t.Fatal("已有公钥被破坏", err)
	}
}
