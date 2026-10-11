package secrets

import (
	"bytes"
	"strings"
	"testing"
)

func TestTenantObjectAndRevisionBinding(t *testing.T) {
	vault, err := New(strings.Repeat("01", 32))
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("opaque-credential-value")
	first, err := vault.Seal("tenant_a", "notification", "channel_a", 1, plain)
	if err != nil {
		t.Fatal(err)
	}
	second, err := vault.Seal("tenant_a", "notification", "channel_a", 1, plain)
	if err != nil || first == second {
		t.Fatal("密文随机数未隔离", err)
	}
	got, err := vault.Open("tenant_a", "notification", "channel_a", 1, first)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatal("凭据无法解密", err)
	}
	for _, binding := range []struct {
		tenant, kind, id string
		revision         int64
	}{{"tenant_b", "notification", "channel_a", 1}, {"tenant_a", "llm", "channel_a", 1}, {"tenant_a", "notification", "channel_b", 1}, {"tenant_a", "notification", "channel_a", 2}} {
		if _, err := vault.Open(binding.tenant, binding.kind, binding.id, binding.revision, first); err != ErrUnavailable {
			t.Fatal("接受不匹配的凭据作用域", binding, err)
		}
	}
	other, _ := New(strings.Repeat("02", 32))
	if _, err := other.Open("tenant_a", "notification", "channel_a", 1, first); err != ErrUnavailable {
		t.Fatal("错误密钥被接受")
	}
}

func TestInvalidCredentialInputs(t *testing.T) {
	for _, key := range []string{"", strings.Repeat("g", 64), strings.Repeat("00", 31)} {
		if _, err := New(key); err != ErrUnavailable {
			t.Fatal("接受无效密钥")
		}
	}
	vault, _ := New(strings.Repeat("00", 32))
	for _, data := range []string{"", "invalid", strings.Repeat("A", 90001), "AA=="} {
		if _, err := vault.Open("t", "n", "c", 1, data); err != ErrUnavailable {
			t.Fatal("接受损坏密文")
		}
	}
	for _, value := range []struct {
		tenant, kind, id string
		rev              int64
	}{{"", "n", "c", 1}, {"t", "", "c", 1}, {"t", "n", "", 1}, {"t", "n", "c", 0}} {
		if _, err := vault.Seal(value.tenant, value.kind, value.id, value.rev, nil); err != ErrUnavailable {
			t.Fatal("接受空作用域")
		}
	}
	if _, err := vault.Seal("t", "n", "c", 1, make([]byte, 65537)); err != ErrUnavailable {
		t.Fatal("接受超限凭据")
	}
	var missing *Vault
	if _, err := missing.Seal("t", "n", "c", 1, nil); err != ErrUnavailable {
		t.Fatal(err)
	}
	if _, err := missing.Open("t", "n", "c", 1, "AA=="); err != ErrUnavailable {
		t.Fatal(err)
	}
}
