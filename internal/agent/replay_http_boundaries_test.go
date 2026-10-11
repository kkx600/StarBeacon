package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/config"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/replay"
	bolt "go.etcd.io/bbolt"
)

func TestLocalReplayHTTPListCorruptionQuotaAndClosedIndex(t *testing.T) {
	s, packet := sampleFixture(t)
	s.Engine = &Engine{Config: config.Config{}}
	authWAL, err := OpenWAL(filepath.Join(t.TempDir(), "auth.db"), s.WAL.TenantID, s.WAL.SensorID, s.WAL.RegistrationID, 4<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer authWAL.Close()
	identity, err := NewLocalIdentity(authWAL, "owned-local-password")
	if err != nil {
		t.Fatal(err)
	}
	u, _, err := identity.Password(context.Background(), "admin")
	if err != nil {
		t.Fatal(err)
	}
	token, csrf, err := identity.CreateSession(context.Background(), u)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	server := httptest.NewServer(httpapi.Middleware(mux))
	defer server.Close()
	auth := httpapi.NewAuth(identity, nil, server.URL, "replay_boundary", false)
	s.Register(mux, auth)
	request := func(method, path, key, content string, data []byte, want int) []byte {
		t.Helper()
		r, err := http.NewRequest(method, server.URL+"/api/local/v1/replay/"+path, bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Content-Type", content)
		r.Header.Set("X-Filename", "capture.pcap")
		r.Header.Set("Origin", server.URL)
		r.Header.Set("X-CSRF-Token", csrf)
		r.Header.Set("Idempotency-Key", key)
		r.AddCookie(&http.Cookie{Name: "replay_boundary", Value: token})
		response, err := server.Client().Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		raw, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != want {
			t.Fatalf("%s %s 返回 %d，预期 %d：%s", method, path, response.StatusCode, want, raw)
		}
		return raw
	}
	request("GET", "samples", "", "", nil, 200)
	now := time.Now().UTC()
	for i := range 201 {
		recordSample(t, s, localSample{Sample: replay.Sample{ID: fmt.Sprintf("sample_%03d", i), Name: "capture.pcap", Size: int64(len(packet)), SHA256: "owned", Format: "pcap", CreatedAt: now.Add(time.Duration(i) * time.Second), ExpiresAt: now.Add(time.Hour)}})
	}
	recordSample(t, s, localSample{Sample: replay.Sample{ID: "sample_expired", SHA256: "owned", ExpiresAt: now.Add(-time.Hour)}})
	recordSample(t, s, localSample{Sample: replay.Sample{ID: "sample_pending", SHA256: "owned", ExpiresAt: now.Add(time.Hour)}, State: "uploading"})
	var page struct {
		Items []replay.Sample `json:"items"`
	}
	if err := json.Unmarshal(request("GET", "samples", "", "", nil, 200), &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 200 || page.Items[0].ID != "sample_200" || page.Items[199].ID != "sample_001" {
		t.Fatal("样本列表排序、数量或未发布过滤不正确")
	}
	request("POST", "samples", "", "application/json", packet, 400)
	request("POST", "tasks", "owned_key", "application/json", []byte(`{"unknown":true}`), 400)
	request("POST", "tasks", "short", "application/json", []byte(`{}`), 400)
	request("POST", "tasks", "owned_key", "application/json", []byte(`{"sample_id":"sample_000","rule_mode":"package","rules":"alert tcp any any -> any any (sid:1000001;)"}`), 409)
	retained, err := os.Create(filepath.Join(s.Storage.Dir, "retained.pcap"))
	if err != nil {
		t.Fatal(err)
	}
	if err = retained.Truncate(s.Storage.Quota); err != nil {
		t.Fatal(err)
	}
	_ = retained.Close()
	request("POST", "samples", "", "application/octet-stream", packet, 409)
	if err = s.WAL.DB.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("replay_samples")).Put([]byte("sample_broken"), []byte(`{`))
	}); err != nil {
		t.Fatal(err)
	}
	request("GET", "samples", "", "", nil, 503)
	if _, err = s.Sample("sample_broken"); err == nil {
		t.Fatal("损坏的样本索引被当作有效对象")
	}
	if err = s.WAL.Close(); err != nil {
		t.Fatal(err)
	}
	request("GET", "samples", "", "", nil, 503)
	request("POST", "samples", "", "application/octet-stream", packet, 503)
}
