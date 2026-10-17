package platform

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kkx600/StarBeacon/internal/incident"
	"github.com/kkx600/StarBeacon/internal/store"
)

func TestIncidentTaskHTTPRejectsUnknownFieldsIdentityAndAmbiguousKeys(t *testing.T) {
	a := &API{}
	for _, body := range []string{`null`, `[]`, `{"spec":{},"spec":{}}`, `{"incident_revision":1,"tenant_id":"other","spec":{}}`, `{"incident_revision":1,"spec":{"title":"one","description":"说明","priority":"high","status":"open","assignee_id":"","due_at":null,"resolution":"","unknown":true}}`, `{"incident_revision":1,"spec":{}} {}`, strings.Repeat(" ", 32769) + `{}`, `{"incident_revision":1,"spec":{"due_at":"not-a-date"}}`} {
		for _, handler := range []http.HandlerFunc{a.createIncidentTask, a.changeIncidentTask} {
			r := httptest.NewRequest("POST", "/api/v1/incidents/incident_owned/tasks", strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Idempotency-Key", "owned_request")
			w := httptest.NewRecorder()
			handler(w, r)
			if w.Code != 400 {
				t.Fatal("非法请求进入存储", w.Code)
			}
		}
	}
	valid := `{"incident_revision":1,"spec":{"title":"核对","description":"说明","priority":"high","status":"open","assignee_id":"","due_at":null,"resolution":""}}`
	for _, keys := range [][]string{nil, {"bad/key"}, {"first", "second"}} {
		r := httptest.NewRequest("POST", "/", strings.NewReader(valid))
		for _, key := range keys {
			r.Header.Add("Idempotency-Key", key)
		}
		w := httptest.NewRecorder()
		a.createIncidentTask(w, r)
		if w.Code != 400 {
			t.Fatal("歧义提交身份没有被拒绝")
		}
	}
	for _, handler := range []http.HandlerFunc{a.incidentTask, a.incidentTaskHistory, a.incidentTasks} {
		r := httptest.NewRequest("GET", "/?extra=invalid", nil)
		r.SetPathValue("id", "bad/id")
		w := httptest.NewRecorder()
		handler(w, r)
		if w.Code != 400 {
			t.Fatal("越界身份进入存储")
		}
	}
	w := httptest.NewRecorder()
	a.incidentTasks(w, httptest.NewRequest("GET", "/?status=blocked", nil))
	if w.Code != 400 {
		t.Fatal("非法状态未被拒绝")
	}
}

func TestIncidentTaskHTTPUnavailableAndClosureFailureMeaning(t *testing.T) {
	a := &API{}
	for _, handler := range []http.HandlerFunc{a.incidentTask, a.incidentTaskHistory, a.incidentTasks} {
		r := httptest.NewRequest("GET", "/", nil)
		r.SetPathValue("id", "incident_owned")
		r.SetPathValue("task", "task_owned")
		w := httptest.NewRecorder()
		handler(w, r)
		if w.Code != 503 {
			t.Fatal("存储缺失仍返回任务成功", w.Code)
		}
	}
	for _, change := range []bool{false, true} {
		input := map[string]any{"incident_revision": 1, "spec": map[string]any{"title": "核对", "description": "说明", "priority": "high", "status": "open", "assignee_id": "", "due_at": nil, "resolution": ""}}
		handler := a.createIncidentTask
		if change {
			input["expected_revision"], input["note"] = 1, "核对计划"
			handler = a.changeIncidentTask
		}
		raw, _ := json.Marshal(input)
		r := httptest.NewRequest("POST", "/", strings.NewReader(string(raw)))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Idempotency-Key", "owned_request")
		r.SetPathValue("id", "incident_owned")
		r.SetPathValue("task", "task_owned")
		w := httptest.NewRecorder()
		handler(w, r)
		if w.Code != 503 {
			t.Fatal("缺少依赖未保留未知提交含义", w.Code)
		}
	}
	for _, entry := range []struct {
		err  error
		code string
		want int
	}{{incident.ErrTaskInput, "invalid_incident_task", 400}, {store.ErrIncidentTasksPending, "incident_tasks_pending", 409}, {store.ErrIncidentTaskClosed, "incident_task_readonly", 409}, {store.ErrIncidentTaskQuota, "incident_task_quota", 429}} {
		w := httptest.NewRecorder()
		incidentFailure(w, httptest.NewRequest("GET", "/", nil), entry.err)
		if w.Code != entry.want || !strings.Contains(w.Body.String(), entry.code) {
			t.Fatal("调查任务错误含义不准确", w.Code, w.Body.String())
		}
	}
}
