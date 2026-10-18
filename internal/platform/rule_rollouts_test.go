package platform

import (
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kkx600/StarBeacon/internal/rulerollout"
)

func TestRuleRolloutStrictInputsAndDependencies(t *testing.T) {
	a := &API{}
	for _, q := range []string{"?bad=1", "?cursor=a&cursor=b", "?cursor=", "?cursor=bad/id", "?cursor=x&bad=1"} {
		w := httptest.NewRecorder()
		a.ruleRollouts(w, httptest.NewRequest("GET", "/api/v1/rule-rollouts"+q, nil))
		if w.Code != 400 {
			t.Fatal(q, w.Code)
		}
	}
	w := httptest.NewRecorder()
	a.ruleRollouts(w, httptest.NewRequest("GET", "/api/v1/rule-rollouts", nil))
	if w.Code != 503 {
		t.Fatal(w.Code)
	}
	for _, target := range []string{"rollout_test", "bad/id"} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/api/v1/rule-rollouts/rollout_test", nil)
		r.SetPathValue("id", target)
		a.ruleRollout(w, r)
		want := 503
		if target == "bad/id" {
			want = 400
		}
		if w.Code != want {
			t.Fatal(w.Code)
		}
	}
	valid := `{"id":"rollout_test","spec":{"name":"规则分批发布","plans":[{"plan_id":"a","revision":1},{"plan_id":"b","revision":1}],"canary_count":1,"batch_size":1,"observation_seconds":30,"timeout_seconds":300}}`
	for _, body := range []string{`{}`, `null`, `[]`, `{"id":"x","id":"x"}`, strings.Replace(valid, `"name":`, `"extra":true,"name":`, 1), valid} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/api/v1/rule-rollouts", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		a.createRuleRollout(w, r)
		want := 400
		if body == valid {
			want = 503
		}
		if w.Code != want {
			t.Fatal(w.Code, body)
		}
	}
	for _, body := range []string{`{}`, `null`, `{"reason":""}`, `{"reason":"维护","extra":1}`, `{"reason":"维护"}`} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/api/v1/rule-rollouts/rollout_test/stop", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.SetPathValue("id", "rollout_test")
		a.stopRuleRollout(w, r)
		want := 400
		if body == `{"reason":"维护"}` {
			want = 503
		}
		if w.Code != want {
			t.Fatal(w.Code, body)
		}
	}
	for _, err := range []error{rulerollout.ErrInput, rulerollout.ErrQuota, errors.New("storage")} {
		w := httptest.NewRecorder()
		rolloutFailure(w, httptest.NewRequest("GET", "/", nil), err)
		want := 503
		if errors.Is(err, rulerollout.ErrInput) {
			want = 400
		}
		if errors.Is(err, rulerollout.ErrQuota) {
			want = 429
		}
		if w.Code != want {
			t.Fatal(w.Code)
		}
	}
}
