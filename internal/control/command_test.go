package control

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestSignedDeviceBinding(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC()
	c := Command{ID: "task_a", TenantID: "tenant_a", SensorID: "sensor_a", RegistrationID: "reg_a", Kind: "diagnostics", IssuedAt: now, ExpiresAt: now.Add(time.Minute), Payload: json.RawMessage(`{}`)}
	raw, sig, e := Encode(c, priv)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Decode(raw, sig, pub, "tenant_a", "sensor_a", "reg_a", now); e != nil {
		t.Fatal(e)
	}
	for _, ids := range [][3]string{{"tenant_b", "sensor_a", "reg_a"}, {"tenant_a", "sensor_b", "reg_a"}, {"tenant_a", "sensor_a", "reg_b"}} {
		if _, e = Decode(raw, sig, pub, ids[0], ids[1], ids[2], now); e == nil {
			t.Fatal("跨身份任务被接受")
		}
	}
	tampered := append([]byte(nil), raw...)
	tampered[len(tampered)-2] ^= 1
	if _, e = Decode(tampered, sig, pub, "tenant_a", "sensor_a", "reg_a", now); e == nil {
		t.Fatal("篡改任务被接受")
	}
	if _, e = Decode(raw, sig, pub, "tenant_a", "sensor_a", "reg_a", now.Add(2*time.Minute)); !errors.Is(e, ErrExpired) {
		t.Fatal("过期任务被接受")
	}
	c.Kind = "shell"
	if _, _, e = Encode(c, priv); e == nil {
		t.Fatal("任意命令被签发")
	}
}
func TestJSONDigestOrdering(t *testing.T) {
	a, e := JSONDigest([]byte(`{"b":2,"a":18446744073709551614}`))
	if e != nil {
		t.Fatal(e)
	}
	b, e := JSONDigest([]byte(`{"a":18446744073709551614,"b":2}`))
	if e != nil || a != b {
		t.Fatal("JSONB 重排破坏幂等")
	}
}
