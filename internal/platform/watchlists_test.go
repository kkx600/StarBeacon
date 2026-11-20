package platform

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
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

// 命中列表只接受有界的观测时间窗与规范游标；缺失、重复、未知参数都不进入存储。
func TestWatchlistHitsHTTPRejectsUnboundedAndMalformedWindows(t *testing.T) {
	a := &API{}
	end := time.Now().UTC().Truncate(time.Second)
	start := end.Add(-time.Hour)
	window := func(extra string) string {
		v := url.Values{"start": {start.Format(time.RFC3339Nano)}, "end": {end.Format(time.RFC3339Nano)}}
		if extra == "" {
			return "/?" + v.Encode()
		}
		return "/?" + v.Encode() + "&" + extra
	}
	for _, c := range []struct {
		url  string
		id   string
		want int
	}{
		{"/", "list_owned", 400},
		{"/?start=" + start.Format(time.RFC3339Nano), "list_owned", 400},
		{"/?end=" + end.Format(time.RFC3339Nano), "list_owned", 400},
		{"/?start=" + end.Format(time.RFC3339Nano) + "&end=" + end.Format(time.RFC3339Nano), "list_owned", 400},
		{"/?start=" + end.Add(-32*24*time.Hour).Format(time.RFC3339Nano) + "&end=" + end.Format(time.RFC3339Nano), "list_owned", 400},
		{"/?start=" + start.Format(time.RFC3339Nano) + "&end=" + end.Add(10*time.Minute).Format(time.RFC3339Nano), "list_owned", 400},
		{"/?start=yesterday&end=" + end.Format(time.RFC3339Nano), "list_owned", 400},
		{window("limit=0"), "list_owned", 400},
		{window("limit=101"), "list_owned", 400},
		{window("limit=020"), "list_owned", 400},
		{window("limit=x"), "list_owned", 400},
		{window("cursor=bad"), "list_owned", 400},
		{window("cursor=" + strings.Repeat("a", 513)), "list_owned", 400},
		{window("unknown=1"), "list_owned", 400},
		{window("limit=20&limit=20"), "list_owned", 400},
		{"/?start=" + start.Format(time.RFC3339Nano) + "&start=" + start.Format(time.RFC3339Nano) + "&end=" + end.Format(time.RFC3339Nano), "list_owned", 400},
		{window("keyword=%zz"), "list_owned", 400},
		{window(""), "List_Owned", 400},
		{window(""), "", 400},
		{window(""), strings.Repeat("a", 65), 400},
		{window(""), "list_owned", 503},
		{window("limit=100"), "list_owned", 503},
	} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", c.url, nil)
		r.SetPathValue("id", c.id)
		a.watchlistHits(w, r)
		if w.Code != c.want {
			t.Fatal(c.url, c.id, "实际", w.Code, "期望", c.want)
		}
	}
}

// 告警命中要求告警身份与原始摘要同时规范，摘要不一致的材料不能借用其他告警的关联。
func TestAlertWatchlistHitsHTTPRequiresExactDigest(t *testing.T) {
	a := &API{}
	digest := strings.Repeat("ab", 32)
	for _, c := range []struct {
		url  string
		id   string
		want int
	}{
		{"/", "evt_owned", 400},
		{"/?sha256=", "evt_owned", 400},
		{"/?sha256=" + strings.Repeat("ab", 31), "evt_owned", 400},
		{"/?sha256=" + strings.Repeat("ab", 33), "evt_owned", 400},
		{"/?sha256=" + strings.ToUpper(digest), "evt_owned", 400},
		{"/?sha256=" + strings.Repeat("zz", 32), "evt_owned", 400},
		{"/?sha256=" + digest + "&sha256=" + digest, "evt_owned", 400},
		{"/?sha256=" + digest + "&unknown=1", "evt_owned", 400},
		{"/?sha256=%zz", "evt_owned", 400},
		{"/?sha256=" + digest, "Evt_Owned", 400},
		{"/?sha256=" + digest, "", 400},
		{"/?sha256=" + digest, "evt_owned", 503},
	} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", c.url, nil)
		r.SetPathValue("id", c.id)
		a.alertWatchlistHits(w, r)
		if w.Code != c.want {
			t.Fatal(c.url, c.id, "实际", w.Code, "期望", c.want)
		}
	}
}

// 影响预览只接受白名单字段与有界时间窗；告警索引缺失时不交付任何部分计数。
func TestWatchlistImpactHTTPRejectsUnboundedAndIncompleteMaterials(t *testing.T) {
	a := &API{}
	end := time.Now().UTC().Truncate(time.Second)
	body := func(revision int64, start, stop time.Time) string {
		raw, _ := json.Marshal(watchlist.ImpactRequest{Revision: revision, Start: start, End: stop})
		return string(raw)
	}
	valid := body(1, end.Add(-time.Hour), end)
	for _, c := range []struct {
		url  string
		id   string
		body string
		want int
	}{
		{"/", "list_owned", "null", 400},
		{"/", "list_owned", "[]", 400},
		{"/", "list_owned", "{}", 400},
		{"/", "list_owned", `{"unknown":true}`, 400},
		{"/", "list_owned", `{"Revision":1}`, 400},
		{"/", "list_owned", `{"revision":1,"revision":2}`, 400},
		{"/", "list_owned", valid + " {}", 400},
		{"/", "list_owned", body(0, end.Add(-time.Hour), end), 400},
		{"/", "list_owned", body(-1, end.Add(-time.Hour), end), 400},
		{"/", "list_owned", body(watchlist.MaxRevision+1, end.Add(-time.Hour), end), 400},
		{"/", "list_owned", body(1, end.Add(-32*24*time.Hour), end), 400},
		{"/", "list_owned", body(1, end, end), 400},
		{"/", "list_owned", body(1, end.Add(-time.Hour), end.Add(10*time.Minute)), 400},
		{"/", "list_owned", body(1, time.Time{}, end), 400},
		{"/?unexpected=1", "list_owned", valid, 400},
		{"/", "List_Owned", valid, 400},
		{"/", "", valid, 400},
		{"/", "list_owned", valid, 503},
	} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", c.url, strings.NewReader(c.body))
		r.Header.Set("Content-Type", "application/json")
		r.SetPathValue("id", c.id)
		a.watchlistImpact(w, r)
		if w.Code != c.want {
			t.Fatal(c.url, c.id, "长度", len(c.body), "实际", w.Code, "期望", c.want)
		}
	}
	// 名单存储可用但告警索引缺失时，预览必须以不完整告知，而不是回落成空结果。
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/", strings.NewReader(valid))
	r.Header.Set("Content-Type", "application/json")
	r.SetPathValue("id", "list_owned")
	(&API{DB: &store.Postgres{}}).watchlistImpact(w, r)
	var out struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if w.Code != 503 || out.Code != "watchlist_impact_incomplete" {
		t.Fatal("告警索引缺失未按不完整告知", w.Code, out.Code)
	}
}

func TestWatchlistImpactFailureCodeSeparatesIncompleteRetrieval(t *testing.T) {
	w := httptest.NewRecorder()
	watchlistFailure(w, httptest.NewRequest("GET", "/", nil), watchlist.ErrIncomplete)
	var out struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if w.Code != 503 || out.Code != "watchlist_impact_incomplete" {
		t.Fatal(w.Code, out.Code)
	}
}
