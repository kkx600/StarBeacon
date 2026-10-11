package platform

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/incident"
	"github.com/kkx600/StarBeacon/internal/store"
)

func TestIncidentHTTPRejectsAmbiguousInputBeforeStorage(t *testing.T) {
	a := &API{}
	for _, body := range []string{`null`, `[]`, `{"spec":{},"spec":{},"alerts":[]}`, `{"Spec":{},"alerts":[]}`, `{"spec":{"title":"case","reason":"wrong-level"},"alerts":[]}`, `{"reason":"wrong-root","spec":{},"alerts":[]}`, `{"spec":{},"alerts":[]} {}`, `{"spec":{},"alerts":null}`, `{"spec":{},"alerts":[]}`, strings.Repeat(" ", 65537) + `{}`} {
		r := httptest.NewRequest("POST", "/api/v1/incidents", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Idempotency-Key", "owned_request")
		w := httptest.NewRecorder()
		a.createIncident(w, r)
		if w.Code != 400 {
			t.Fatal("歧义输入访问了存储", w.Code, body[:min(len(body), 80)])
		}
	}
	for _, target := range []string{"/api/v1/incidents?status=open&status=closed", "/api/v1/incidents?status=auto_blocked", "/api/v1/incidents?severity=unknown", "/api/v1/incidents?extra=ignored"} {
		w := httptest.NewRecorder()
		a.incidents(w, httptest.NewRequest("GET", target, nil))
		if w.Code != 400 {
			t.Fatal("非法筛选进入存储", target, w.Code)
		}
	}
	for _, handler := range []http.HandlerFunc{a.incident, a.incidentHistory} {
		r := httptest.NewRequest("GET", "/api/v1/incidents/invalid", nil)
		r.SetPathValue("id", "bad/id")
		w := httptest.NewRecorder()
		handler(w, r)
		if w.Code != 400 {
			t.Fatal("非法事件身份进入存储")
		}
	}
}

func TestIncidentHTTPDependenciesAndFailureMeaning(t *testing.T) {
	a := &API{}
	for _, handler := range []http.HandlerFunc{a.incidents, a.incident, a.incidentAssignees, a.incidentHistory} {
		r := httptest.NewRequest("GET", "/api/v1/incidents", nil)
		r.SetPathValue("id", "incident_owned")
		w := httptest.NewRecorder()
		handler(w, r)
		if w.Code != 503 {
			t.Fatal("未配置仍返回正常事件", w.Code)
		}
	}
	valid := `{"spec":{"title":"人工事件","category":"other","severity":"low","status":"open","summary":"调查线索","owner_id":"","closure":null},"alerts":[]}`
	for _, key := range []string{"", "owned_request"} {
		r := httptest.NewRequest("POST", "/api/v1/incidents", strings.NewReader(valid))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Idempotency-Key", key)
		w := httptest.NewRecorder()
		a.createIncident(w, r)
		expected := 503
		if key == "" {
			expected = 400
		}
		if w.Code != expected {
			t.Fatal("建立失败含义不准确", w.Code)
		}
	}
	for _, item := range []struct {
		err    error
		status int
		code   string
	}{{incident.ErrInput, 400, "invalid_incident"}, {pgx.ErrNoRows, 404, "not_found"}, {store.ErrConflict, 409, "incident_conflict"}, {store.ErrIncidentOwner, 409, "assignee_unavailable"}, {store.ErrIncidentExpired, 410, "incident_expired"}, {store.ErrIncidentQuota, 429, "incident_quota_exceeded"}, {store.ErrAlertIdentity, 409, "alert_identity_conflict"}, {&store.IncidentLinked{ID: "incident_owned"}, 409, "alert_already_linked"}, {&store.IncidentLinked{ID: "bad/id"}, 503, "incident_unavailable"}, {errors.New("broken"), 503, "incident_unavailable"}} {
		w := httptest.NewRecorder()
		incidentFailure(w, httptest.NewRequest("GET", "/api/v1/incidents", nil), item.err)
		var body struct {
			Code string `json:"code"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		if w.Code != item.status || body.Code != item.code {
			t.Fatal("错误含义不准确", w.Code, body.Code)
		}
		if item.status == 429 && w.Header().Get("Retry-After") == "" {
			t.Fatal("缺少重试提示")
		}
	}
}
