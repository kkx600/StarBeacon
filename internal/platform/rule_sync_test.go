package platform

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kkx600/StarBeacon/internal/rulesync"
)

func TestRuleSyncInputAndUnavailable(t *testing.T) {
	a := &API{}
	for _, path := range []string{"/api/v1/rule-sync-plans?extra=1", "/api/v1/rule-sync-plans?cursor=a&cursor=b", "/api/v1/rule-sync-plans?cursor=a&extra=1"} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", path, nil)
		a.ruleSyncPlans(w, r)
		if w.Code != 400 {
			t.Fatal(w.Code)
		}
	}
	w := httptest.NewRecorder()
	a.ruleSyncPlans(w, httptest.NewRequest("GET", "/api/v1/rule-sync-plans", nil))
	if w.Code != 503 {
		t.Fatal(w.Code)
	}
	for _, body := range []string{`{}`, `null`, `[]`, `{"id":"x","extra":1}`, `{"id":"a","id":"b"}`} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/api/v1/rule-sync-plans", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		a.saveRuleSyncPlan(w, r)
		if w.Code != 400 {
			t.Fatal(w.Code)
		}
	}
	body := `{"id":"sync_1","expected_revision":0,"spec":{"name":"规则同步","enabled":false,"sensor_id":"sensor_1","registration_id":"registration_1","package_id":"package_1","package_revision":1,"positive_sample_id":"sample_hit","negative_sample_id":"sample_miss","interval_seconds":30}}`
	for _, path := range []string{"/api/v1/rule-sync-plans", "/api/v1/rule-sync-plans?extra=1"} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		a.saveRuleSyncPlan(w, r)
		want := 503
		if strings.Contains(path, "?") {
			want = 400
		}
		if w.Code != want {
			t.Fatal(w.Code)
		}
	}
	for _, err := range []error{rulesync.ErrInput, rulesync.ErrQuota, errors.New("storage")} {
		w := httptest.NewRecorder()
		ruleSyncFailure(w, httptest.NewRequest("GET", "/", nil), err)
		want := 503
		if errors.Is(err, rulesync.ErrInput) {
			want = 400
		}
		if errors.Is(err, rulesync.ErrQuota) {
			want = 429
		}
		if w.Code != want {
			t.Fatal(w.Code)
		}
	}
	if after, n, err := a.SweepRuleSync(context.Background(), "cursor"); err != nil || n != 0 || after != "cursor" {
		t.Fatal("未配置服务不应创建任务")
	}
}
