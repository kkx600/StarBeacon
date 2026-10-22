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
	"github.com/kkx600/StarBeacon/internal/correlation"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/searchsnapshot"
	"github.com/kkx600/StarBeacon/internal/store"
)

func TestCorrelationHTTPRejectsUnknownDuplicateAndUnsupportedInputsBeforeStorage(t *testing.T) {
	a := &API{}
	active := true
	change := correlation.Change{ID: "correlation_owned", Name: "同源多目标", Active: &active, Definition: correlation.Definition{SchemaVersion: correlation.Schema, Dataset: "alerts", GroupBy: "source.ip", Metric: "count", WindowSeconds: 60, Threshold: 2}}
	now := time.Now().UTC().Truncate(time.Second)
	query := correlation.Request{ExpectedRevision: 1, Start: now.Add(-time.Minute), End: now}
	for _, item := range []struct {
		handler http.HandlerFunc
		input   any
	}{{a.saveCorrelationRule, change}, {a.backtestCorrelation, query}} {
		raw, _ := json.Marshal(item.input)
		for _, body := range []string{"null", "[]", "{}", `{"id":"a","id":"b"}`, `{"Expected_revision":1}`, `{"definition":{"id":"unexpected"}}`, `{"unknown":true}`, string(raw) + " {}", strings.Repeat(" ", 32769) + string(raw), string(raw)} {
			w := httptest.NewRecorder()
			r := httptest.NewRequest("POST", "/", strings.NewReader(body))
			r.SetPathValue("id", change.ID)
			r.Header.Set("Idempotency-Key", "correlation_create")
			r.Header.Set("Content-Type", "application/json")
			item.handler(w, r)
			want := 400
			if body == string(raw) {
				want = 503
			}
			if w.Code != want {
				t.Fatalf("材料长度 %d，响应 %d，期望 %d", len(body), w.Code, want)
			}
		}
	}
	for _, url := range []string{"/?limit=0", "/?limit=101", "/?limit=020", "/?limit=x", "/?active=yes", "/?keyword=a&keyword=b", "/?unknown=true", "/?cursor=bad"} {
		w := httptest.NewRecorder()
		a.correlationRules(w, httptest.NewRequest("GET", url, nil))
		if w.Code != 400 {
			t.Fatal("无效目录参数进入存储", url, w.Code)
		}
	}
	for _, rev := range []string{"0", "01", "1000001", "bad", "1"} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/", nil)
		r.SetPathValue("id", change.ID)
		r.SetPathValue("revision", rev)
		a.correlationRule(w, r)
		want := 400
		if rev == "1" {
			want = 503
		}
		if w.Code != want {
			t.Fatal(rev, w.Code)
		}
	}
	raw, _ := json.Marshal(change)
	r := httptest.NewRequest("POST", "/", strings.NewReader(string(raw)))
	w := httptest.NewRecorder()
	a.saveCorrelationRule(w, r)
	if w.Code != 400 {
		t.Fatal("缺失请求键未拒绝")
	}
}

func TestCorrelationHTTPFailurePreservesMeaningWithoutSourceDetails(t *testing.T) {
	for _, item := range []struct {
		err    error
		status int
		code   string
	}{{correlation.ErrInput, 400, "invalid_correlation"}, {correlation.ErrPermission, 403, "correlation_forbidden"}, {model.ErrUnauthenticated, 401, "session_expired"}, {correlation.ErrQuota, 429, "correlation_rule_quota"}, {correlation.ErrLimit, 413, "correlation_limit"}, {searchsnapshot.ErrLimit, 413, "correlation_limit"}, {store.ErrConflict, 409, "correlation_conflict"}, {pgx.ErrNoRows, 404, "not_found"}, {errExportBusy, 429, "correlation_busy"}, {errors.New("private_source_information"), 503, "correlation_unavailable"}} {
		w := httptest.NewRecorder()
		correlationFailure(w, httptest.NewRequest("GET", "/", nil), item.err)
		var body struct {
			Code string `json:"code"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		if w.Code != item.status || body.Code != item.code || strings.Contains(w.Body.String(), "private_source_information") {
			t.Fatal(w.Code, body)
		}
		if item.err == errExportBusy && w.Header().Get("Retry-After") != "5" {
			t.Fatal("配额未提供重试时间")
		}
	}
}
