package platform

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/watchlist"
)

func platformWatchlistInput() watchlist.Change {
	active := false
	at := time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC)
	return watchlist.Change{ID: "list_owned", Name: "管理链路保护", Description: "限定探针的管理地址", Active: &active, Definition: watchlist.Definition{SchemaVersion: watchlist.Schema, Kind: "protect", MatchType: "ip", Values: []string{"192.0.2.1"}, Sensors: []watchlist.Sensor{{SensorID: "probe_owned", RegistrationID: "registration_owned"}}, ValidFrom: at, ValidUntil: at.Add(180 * 24 * time.Hour)}}
}
func TestWatchlistHTTPRejectsUnknownDuplicateAndUnsupportedMaterials(t *testing.T) {
	a := &API{}
	change := platformWatchlistInput()
	preview := watchlist.PreviewRequest{Definition: change.Definition, Active: change.Active, Targets: []watchlist.Target{}}
	for _, item := range []struct {
		handler http.HandlerFunc
		value   any
	}{{a.saveWatchlist, change}, {a.previewWatchlist, preview}} {
		raw, _ := json.Marshal(item.value)
		for _, body := range []string{"null", "[]", "{}", `{"id":"a","id":"b"}`, `{"definition":{"kind":"other"}}`, `{"unknown":true}`, `{"Definition":{}}`, string(raw) + " {}", strings.Repeat(" ", 32769) + string(raw), string(raw)} {
			w := httptest.NewRecorder()
			r := httptest.NewRequest("POST", "/", strings.NewReader(body))
			r.Header.Set("Idempotency-Key", "watchlist_original")
			r.Header.Set("Content-Type", "application/json")
			item.handler(w, r)
			want := 400
			if body == string(raw) {
				want = 503
			}
			if w.Code != want {
				t.Fatal("长度", len(body), "实际", w.Code, "期望", want)
			}
		}
	}
	raw, _ := json.Marshal(change)
	for _, url := range []string{"/", "/?unexpected=1"} {
		r := httptest.NewRequest("POST", url, strings.NewReader(string(raw)))
		w := httptest.NewRecorder()
		a.saveWatchlist(w, r)
		if w.Code != 400 {
			t.Fatal("缺失幂等键或查询未拒绝")
		}
	}
	for _, url := range []string{"/?limit=0", "/?limit=101", "/?limit=020", "/?limit=x", "/?active=yes", "/?kind=allow", "/?keyword=a&keyword=b", "/?unknown=1", "/?cursor=bad", "/?keyword=%zz", "/?kind=protect;other=true"} {
		w := httptest.NewRecorder()
		a.watchlists(w, httptest.NewRequest("GET", url, nil))
		if w.Code != 400 {
			t.Fatal(url, w.Code)
		}
	}
	for _, rev := range []string{"0", "01", "1000001", "bad", "1"} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/", nil)
		r.SetPathValue("id", change.ID)
		r.SetPathValue("revision", rev)
		a.watchlistRevision(w, r)
		want := 400
		if rev == "1" {
			want = 503
		}
		if w.Code != want {
			t.Fatal(rev, w.Code)
		}
	}
}
func TestWatchlistHTTPFailuresDoNotLeakInternalSources(t *testing.T) {
	for _, c := range []struct {
		e      error
		status int
		code   string
	}{{watchlist.ErrInput, 400, "invalid_watchlist"}, {watchlist.ErrPermission, 403, "watchlist_forbidden"}, {model.ErrUnauthenticated, 401, "session_expired"}, {watchlist.ErrQuota, 429, "watchlist_quota"}, {watchlist.ErrLimit, 429, "watchlist_quota"}, {store.ErrConflict, 409, "watchlist_conflict"}, {pgx.ErrNoRows, 404, "not_found"}, {watchlist.ErrSource, 503, "watchlist_unavailable"}, {errors.New("private_credential_path"), 503, "watchlist_unavailable"}} {
		w := httptest.NewRecorder()
		watchlistFailure(w, httptest.NewRequest("GET", "/", nil), c.e)
		var out struct {
			Code string `json:"code"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		if w.Code != c.status || out.Code != c.code || strings.Contains(w.Body.String(), "private_credential_path") {
			t.Fatal(w.Code, out)
		}
	}
}
