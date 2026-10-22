package platform

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/incident"
	"github.com/kkx600/StarBeacon/internal/store"
)

func (a *API) registerIncidentNotes(m *http.ServeMux) {
	m.HandleFunc("GET /api/v1/incidents/{id}/notes", a.Auth.Require(true, a.incidentNotes))
	m.HandleFunc("POST /api/v1/incidents/{id}/notes", a.Auth.Require(true, a.createIncidentNote))
	m.HandleFunc("GET /api/v1/incidents/{id}/notes/{note}", a.Auth.Require(true, a.incidentNote))
	m.HandleFunc("POST /api/v1/incidents/{id}/notes/{note}", a.Auth.Require(true, a.changeIncidentNote))
	m.HandleFunc("GET /api/v1/incidents/{id}/notes/{note}/history", a.Auth.Require(true, a.incidentNoteHistory))
}

func (a *API) incidentNoteReady(w http.ResponseWriter, r *http.Request, task bool, allowed ...string) bool {
	if !incidentQuery(r, allowed...) || !contract.ValidID(r.PathValue("id")) || task && !contract.ValidID(r.PathValue("note")) {
		incidentNoteFailure(w, r, incident.ErrNoteInput)
		return false
	}
	if a.DB == nil {
		incidentNoteFailure(w, r, errors.New("调查笔记存储未配置"))
		return false
	}
	return true
}

func decodeIncidentNote(w http.ResponseWriter, r *http.Request, target any) bool {
	if len(r.Header.Values("Idempotency-Key")) != 1 || !contract.ValidID(r.Header.Get("Idempotency-Key")) {
		incidentNoteFailure(w, r, incident.ErrNoteInput)
		return false
	}
	var raw json.RawMessage
	if httpapi.Decode(w, r, &raw) != nil || contract.JSONFields(string(raw), []string{"incident_revision", "expected_revision", "spec", "title", "body", "status", "withdrawal_reason", "reason"}, 65536) != nil {
		incidentNoteFailure(w, r, incident.ErrNoteInput)
		return false
	}
	// 原文与回执使用同一字符串契约；null 或省略字段不能被 Go 零值静默替代。
	var fields struct {
		Spec map[string]json.RawMessage `json:"spec"`
	}
	if json.Unmarshal(raw, &fields) != nil || len(fields.Spec) != 4 {
		incidentNoteFailure(w, r, incident.ErrNoteInput)
		return false
	}
	for _, name := range []string{"title", "body", "status", "withdrawal_reason"} {
		var value string
		if json.Unmarshal(fields.Spec[name], &value) != nil || bytes.Equal(bytes.TrimSpace(fields.Spec[name]), []byte("null")) {
			incidentNoteFailure(w, r, incident.ErrNoteInput)
			return false
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		incidentNoteFailure(w, r, incident.ErrNoteInput)
		return false
	}
	return true
}

func (a *API) incidentNotes(w http.ResponseWriter, r *http.Request) {
	q := incident.NoteQuery{Status: r.URL.Query().Get("status"), Before: r.URL.Query().Get("before")}
	if q.Validate() != nil {
		incidentNoteFailure(w, r, incident.ErrNoteInput)
		return
	}
	if !a.incidentNoteReady(w, r, false, "status", "before") {
		return
	}
	result, err := a.DB.IncidentNotes(r.Context(), httpapi.Principal(r), r.PathValue("id"), q)
	if err != nil {
		incidentNoteFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, result)
}

func (a *API) incidentNote(w http.ResponseWriter, r *http.Request) {
	if !a.incidentNoteReady(w, r, true) {
		return
	}
	result, err := a.DB.IncidentNote(r.Context(), httpapi.Principal(r), r.PathValue("id"), r.PathValue("note"))
	if err != nil {
		incidentNoteFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, result)
}

func (a *API) incidentNoteHistory(w http.ResponseWriter, r *http.Request) {
	if !a.incidentNoteReady(w, r, true, "before") {
		return
	}
	result, err := a.DB.IncidentNoteHistory(r.Context(), httpapi.Principal(r), r.PathValue("id"), r.PathValue("note"), r.URL.Query().Get("before"))
	if err != nil {
		incidentNoteFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, result)
}

func (a *API) createIncidentNote(w http.ResponseWriter, r *http.Request) {
	var input incident.NoteCreate
	if !decodeIncidentNote(w, r, &input) {
		return
	}
	if input.Validate() != nil {
		incidentNoteFailure(w, r, incident.ErrNoteInput)
		return
	}
	if !a.incidentNoteReady(w, r, false) {
		return
	}
	result, err := a.DB.CreateIncidentNote(r.Context(), httpapi.Principal(r), r.PathValue("id"), r.Header.Get("Idempotency-Key"), input, httpapi.RequestID(r))
	if err != nil {
		incidentNoteFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, result)
}

func (a *API) changeIncidentNote(w http.ResponseWriter, r *http.Request) {
	var input incident.NoteChange
	if !decodeIncidentNote(w, r, &input) {
		return
	}
	if input.Validate() != nil {
		incidentNoteFailure(w, r, incident.ErrNoteInput)
		return
	}
	if !a.incidentNoteReady(w, r, true) {
		return
	}
	result, err := a.DB.ChangeIncidentNote(r.Context(), httpapi.Principal(r), r.PathValue("id"), r.PathValue("note"), r.Header.Get("Idempotency-Key"), input, httpapi.RequestID(r))
	if err != nil {
		incidentNoteFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, result)
}

func incidentNoteFailure(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, incident.ErrNoteInput):
		httpapi.Fail(w, r, 400, "invalid_incident_note", "请核对笔记标题、正文、状态、撤回说明及事件与笔记修订")
	case errors.Is(err, store.ErrIncidentNoteClosed):
		httpapi.Fail(w, r, 409, "incident_note_readonly", "事件已结案，调查笔记仅供查阅；需要继续记录时请先重开事件")
	case errors.Is(err, store.ErrIncidentNoteAuthor):
		httpapi.Fail(w, r, 403, "incident_note_author_required", "只有当前仍具备调查权限的笔记作者可以修改、撤回或恢复笔记")
	case errors.Is(err, store.ErrIncidentNoteQuota):
		w.Header().Set("Retry-After", "60")
		httpapi.Fail(w, r, 429, "incident_note_quota", "调查笔记或今日变更额度已用尽，请核对记录与留存范围")
	default:
		incidentFailure(w, r, err)
	}
}
