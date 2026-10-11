package platform

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kkx600/StarBeacon/internal/decision"
)

func TestDecisionEvaluationHTTPBoundsKeysAndUnavailableStorage(t *testing.T) {
	a := &API{}
	good, _ := json.Marshal(decision.EvaluationRequest{PolicyID: "policy_owned", ExpectedRevision: 1, TriageID: "triage_owned"})
	for _, body := range []string{"null", "{}", `{"policy_id":"policy_owned","Policy_id":"other","expected_revision":1,"triage_id":"owned"}`, `{"policy_id":"a","policy_id":"b","expected_revision":1,"triage_id":"owned"}`, strings.Repeat(" ", 16385) + string(good), string(good)} {
		r := httptest.NewRequest("POST", "/", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Idempotency-Key", "evaluation_owned")
		w := httptest.NewRecorder()
		a.createDecisionEvaluation(w, r)
		want := 400
		if body == string(good) {
			want = 503
		}
		if w.Code != want {
			t.Fatal("档案输入边界不同", w.Code, want)
		}
	}
	for _, key := range []string{"", "/", "owned"} {
		r := httptest.NewRequest("POST", "/", strings.NewReader(string(good)))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Idempotency-Key", key)
		if key == "owned" {
			r.Header.Add("Idempotency-Key", "other")
		}
		w := httptest.NewRecorder()
		a.createDecisionEvaluation(w, r)
		if w.Code != 400 {
			t.Fatal("无效或重复请求键被接受")
		}
	}
	for _, url := range []string{"/?limit=0", "/?limit=101", "/?limit=020", "/?limit=x", "/?cursor=/", "/?policy_id=/", "/?triage_id=/", "/?status=approved", "/?status=matched&status=protected", "/?unknown=x", "/"} {
		w := httptest.NewRecorder()
		a.decisionEvaluations(w, httptest.NewRequest("GET", url, nil))
		want := 400
		if url == "/" {
			want = 503
		}
		if w.Code != want {
			t.Fatal("档案目录边界不同", url, w.Code)
		}
	}
	q, err := evaluationListQuery(httptest.NewRequest("GET", "/?limit=1&cursor=evaluation_owned&policy_id=policy_owned&triage_id=triage_owned&status=matched", nil))
	if err != nil || q.Limit != 1 || q.Cursor != "evaluation_owned" || q.Status != "matched" {
		t.Fatal("合法目录查询被拒绝")
	}
	for _, url := range []string{"/", "/?unexpected=x"} {
		for _, id := range []string{"/", "evaluation_owned"} {
			r := httptest.NewRequest("GET", url, nil)
			r.SetPathValue("id", id)
			w := httptest.NewRecorder()
			a.decisionEvaluation(w, r)
			want := 400
			if id == "evaluation_owned" && url == "/" {
				want = 503
			}
			if w.Code != want {
				t.Fatal("档案详情边界不同")
			}
		}
	}
}
