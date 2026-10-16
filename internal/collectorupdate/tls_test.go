package collectorupdate

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestCollectorReadinessRequiresExplicitVerifiedTLS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer server.Close()
	ca := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0644); err != nil {
		t.Fatal(err)
	}
	if err := Probe(context.Background(), server.URL+"/readyz", ca); err != nil {
		t.Fatal("有效生产 TLS 就绪探测失败", err)
	}
	for _, path := range []string{"relative", "/not/found", filepath.Dir(ca)} {
		if Probe(context.Background(), server.URL+"/readyz", path) == nil {
			t.Fatal("无效 CA 仍通过探测")
		}
	}
	if err := os.WriteFile(ca, []byte("invalid certificate"), 0644); err != nil {
		t.Fatal(err)
	}
	if Probe(context.Background(), server.URL+"/readyz", ca) == nil {
		t.Fatal("忽略损坏 CA")
	}
	if Probe(context.Background(), server.URL+"/readyz", ca, ca) == nil {
		t.Fatal("接受多个未定义 CA 参数")
	}
}
