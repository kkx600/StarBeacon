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

func TestIncidentNoteHTTPInputIdentityAndDependencyFailures(t *testing.T) {
	a := &API{}
	for _, body := range []string{`null`, `[]`, `{"spec":{},"spec":{}}`, `{"incident_revision":1,"tenant_id":"other","spec":{}}`, `{"incident_revision":1,"spec":{"title":"核对","body":"材料","status":"active","withdrawal_reason":"","author_id":"other"}}`, `{"incident_revision":1,"spec":{}} {}`, strings.Repeat(" ", 65537) + `{}`, `{"incident_revision":"1","spec":{}}`, `{"incident_revision":1,"spec":{"title":"核对","body":"材料","status":"active"}}`, `{"incident_revision":1,"spec":{"title":"核对","body":"材料","status":"active","withdrawal_reason":null}}`} {
		for _, handler := range []http.HandlerFunc{a.createIncidentNote, a.changeIncidentNote} {
			r := httptest.NewRequest("POST", "/", strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Idempotency-Key", "owned_request")
			w := httptest.NewRecorder()
			handler(w, r)
			if w.Code != 400 {
				t.Fatal("非法笔记进入存储", w.Code, w.Body.String())
			}
		}
	}
	valid := `{"incident_revision":1,"spec":{"title":"核对","body":"材料","status":"active","withdrawal_reason":""}}`
	for _, keys := range [][]string{nil, {"bad/key"}, {"first", "second"}} {
		r := httptest.NewRequest("POST", "/", strings.NewReader(valid))
		for _, key := range keys {
			r.Header.Add("Idempotency-Key", key)
		}
		w := httptest.NewRecorder()
		a.createIncidentNote(w, r)
		if w.Code != 400 {
			t.Fatal("歧义提交身份被接受")
		}
	}
	for _, handler := range []http.HandlerFunc{a.incidentNotes, a.incidentNote, a.incidentNoteHistory} {
		for _, path := range []string{"/?extra=1", "/?before=one&before=two"} {
			r := httptest.NewRequest("GET", path, nil)
			r.SetPathValue("id", "case_owned")
			r.SetPathValue("note", "case_note_owned")
			w := httptest.NewRecorder()
			handler(w, r)
			if w.Code != 400 {
				t.Fatal("歧义参数被接受", w.Code)
			}
		}
		r := httptest.NewRequest("GET", "/", nil)
		r.SetPathValue("id", "case_owned")
		r.SetPathValue("note", "case_note_owned")
		w := httptest.NewRecorder()
		handler(w, r)
		if w.Code != 503 {
			t.Fatal("未配置存储仍报告成功", w.Code)
		}
	}
	for _, change := range []bool{false, true} {
		input := map[string]any{"incident_revision": 1, "spec": map[string]any{"title": "核对", "body": "材料", "status": "active", "withdrawal_reason": ""}}
		handler := a.createIncidentNote
		if change {
			input["expected_revision"] = 1
			input["reason"] = "核对引用"
			handler = a.changeIncidentNote
		}
		raw, _ := json.Marshal(input)
		r := httptest.NewRequest("POST", "/", strings.NewReader(string(raw)))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Idempotency-Key", "owned_request")
		r.SetPathValue("id", "case_owned")
		r.SetPathValue("note", "case_note_owned")
		w := httptest.NewRecorder()
		handler(w, r)
		if w.Code != 503 {
			t.Fatal("存储故障未保留未知结果边界", w.Code, w.Body.String())
		}
	}
	w := httptest.NewRecorder()
	a.incidentNotes(w, httptest.NewRequest("GET", "/?status=deleted", nil))
	if w.Code != 400 {
		t.Fatal("非法状态被接受")
	}
}

func TestIncidentNoteHTTPFailureSemantics(t *testing.T) {
	for _, entry := range []struct {
		err    error
		status int
		code   string
	}{{incident.ErrNoteInput, 400, "invalid_incident_note"}, {store.ErrIncidentNoteClosed, 409, "incident_note_readonly"}, {store.ErrIncidentNoteAuthor, 403, "incident_note_author_required"}, {store.ErrIncidentNoteQuota, 429, "incident_note_quota"}, {store.ErrConflict, 409, "incident_conflict"}} {
		w := httptest.NewRecorder()
		incidentNoteFailure(w, httptest.NewRequest("GET", "/", nil), entry.err)
		if w.Code != entry.status || !strings.Contains(w.Body.String(), entry.code) {
			t.Fatal("笔记错误含义错误", w.Code, w.Body.String())
		}
	}
}
