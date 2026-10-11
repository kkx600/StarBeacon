package platform

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestResponseTaskHTTPRejectsAliasesDuplicatesAndMixedTargets(t *testing.T) {
	_, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	a := &API{Signer: signer}
	for _, body := range []string{`null`, `[]`, `{}`, `{"kind":"response.block","kind":"response.revoke"}`, `{"Kind":"response.block"}`, `{"extra":1}`, strings.Repeat(" ", 8193), `{"kind":"response.block","connector_id":"connector_test","config_sha256":"` + strings.Repeat("a", 64) + `","target_ip":"127.0.0.1","ttl_seconds":30,"reason":"说明"}`} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/", strings.NewReader(body))
		r.Header.Set("Idempotency-Key", "response_submit")
		r.SetPathValue("id", "sensor_test")
		a.createResponseTask(w, r)
		if w.Code != 400 {
			t.Fatal("严格参数边界", w.Code)
		}
	}
	for _, key := range []string{"", "short", "space key", "UPPER_KEY"} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/", strings.NewReader(`{}`))
		r.Header.Set("Idempotency-Key", key)
		r.SetPathValue("id", "sensor_test")
		a.createResponseTask(w, r)
		if w.Code != 400 {
			t.Fatal("请求键")
		}
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/?unknown=1", strings.NewReader(`{}`))
	r.Header.Set("Idempotency-Key", "response_submit")
	r.SetPathValue("id", "sensor_test")
	a.createResponseTask(w, r)
	if w.Code != 400 {
		t.Fatal("查询边界")
	}
	w = httptest.NewRecorder()
	r = httptest.NewRequest("POST", "/", strings.NewReader(`{}`))
	r.Header.Add("Idempotency-Key", "response_submit")
	r.Header.Add("Idempotency-Key", "response_submit")
	r.SetPathValue("id", "sensor_test")
	a.createResponseTask(w, r)
	if w.Code != 400 {
		t.Fatal("多值键")
	}
	w = httptest.NewRecorder()
	(&API{}).createResponseTask(w, httptest.NewRequest("POST", "/", nil))
	if w.Code != 503 {
		t.Fatal("无签名服务")
	}
}
