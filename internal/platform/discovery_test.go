package platform

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/discovery"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/store"
)

func TestDiscoveryHTTPInputAndDependencyFailures(t *testing.T) {
	a := &API{}
	valid := `{"network_id":"net_owned","network_revision":1,"sensor_id":"sensor_owned","registration_id":"reg_owned","prefix":"192.0.2.0/24","start":"2026-10-18T00:00:00Z","end":"2026-10-18T01:00:00Z"}`
	for _, raw := range []string{`null`, `[]`, `{}`, `{"network_id":"first","network_id":"second"}`, strings.Replace(valid, `"network_revision":1`, `"network_revision":1,"tenant_id":"other"`, 1), strings.Replace(valid, `192.0.2.0/24`, `192.0.2.1/24`, 1), valid + ` {}`} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/", strings.NewReader(raw))
		r.Header.Set("Content-Type", "application/json")
		a.discoverAssets(w, r)
		if w.Code != 400 {
			t.Fatal("非法范围进入存储", w.Code)
		}
	}
	w := httptest.NewRecorder()
	a.discoverAssets(w, httptest.NewRequest("POST", "/?extra=1", strings.NewReader(valid)))
	if w.Code != 400 {
		t.Fatal(w.Code)
	}
	w = httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/", strings.NewReader(valid))
	r.Header.Set("Content-Type", "application/json")
	a.discoverAssets(w, r)
	if w.Code != 503 {
		t.Fatal(w.Code)
	}
	if _, err := a.discoverySlot(context.Background(), "tenant_owned"); !errors.Is(err, discovery.ErrIncomplete) {
		t.Fatal(err)
	}
}

func TestDiscoveryFailureStatusAndRetryMeaning(t *testing.T) {
	for _, row := range []struct {
		err    error
		status int
		code   string
	}{{discovery.ErrInput, 400, "invalid_discovery"}, {model.ErrUnauthenticated, 401, "session_expired"}, {pgx.ErrNoRows, 404, "not_found"}, {store.ErrConflict, 409, "discovery_scope_changed"}, {discovery.ErrLimit, 413, "discovery_limit"}, {errDiscoveryBusy, 429, "discovery_busy"}, {discovery.ErrIncomplete, 503, "discovery_unavailable"}} {
		w := httptest.NewRecorder()
		discoveryFailure(w, httptest.NewRequest("POST", "/", nil), row.err)
		if w.Code != row.status || !strings.Contains(w.Body.String(), row.code) || row.status == 429 && w.Header().Get("Retry-After") != "60" {
			t.Fatal(w.Code, w.Body.String())
		}
	}
}
