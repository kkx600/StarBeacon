package platform

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/incident"
)

func (a *API) registerIncidentTasks(m *http.ServeMux) {
	m.HandleFunc("GET /api/v1/incidents/{id}/tasks", a.Auth.Require(true, a.incidentTasks))
	m.HandleFunc("POST /api/v1/incidents/{id}/tasks", a.Auth.Require(true, a.createIncidentTask))
	m.HandleFunc("GET /api/v1/incidents/{id}/tasks/{task}", a.Auth.Require(true, a.incidentTask))
	m.HandleFunc("POST /api/v1/incidents/{id}/tasks/{task}", a.Auth.Require(true, a.changeIncidentTask))
	m.HandleFunc("GET /api/v1/incidents/{id}/tasks/{task}/history", a.Auth.Require(true, a.incidentTaskHistory))
}

func (a *API) incidentTaskReady(w http.ResponseWriter, r *http.Request, task bool, allowed ...string) bool {
	if !incidentQuery(r, allowed...) || !contract.ValidID(r.PathValue("id")) || task && !contract.ValidID(r.PathValue("task")) {
		incidentFailure(w, r, incident.ErrTaskInput)
		return false
	}
	if a.DB == nil {
		incidentFailure(w, r, errors.New("调查任务存储未配置"))
		return false
	}
	return true
}

func decodeIncidentTask(w http.ResponseWriter, r *http.Request, target any) bool {
	if len(r.Header.Values("Idempotency-Key")) != 1 || !contract.ValidID(r.Header.Get("Idempotency-Key")) {
		incidentFailure(w, r, incident.ErrTaskInput)
		return false
	}
	var raw json.RawMessage
	if httpapi.Decode(w, r, &raw) != nil || contract.JSONFields(string(raw), []string{"incident_revision", "expected_revision", "spec", "title", "description", "status", "priority", "assignee_id", "due_at", "resolution", "note"}, 32768) != nil {
		incidentFailure(w, r, incident.ErrTaskInput)
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		incidentFailure(w, r, incident.ErrTaskInput)
		return false
	}
	return true
}

func (a *API) incidentTasks(w http.ResponseWriter, r *http.Request) {
	q := incident.TaskQuery{Status: r.URL.Query().Get("status"), Before: r.URL.Query().Get("before")}
	if q.Validate() != nil {
		incidentFailure(w, r, incident.ErrTaskInput)
		return
	}
	if !a.incidentTaskReady(w, r, false, "status", "before") {
		return
	}
	result, err := a.DB.IncidentTasks(r.Context(), httpapi.Principal(r), r.PathValue("id"), q)
	if err != nil {
		incidentFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, result)
}

func (a *API) incidentTask(w http.ResponseWriter, r *http.Request) {
	if !a.incidentTaskReady(w, r, true) {
		return
	}
	result, err := a.DB.IncidentTask(r.Context(), httpapi.Principal(r), r.PathValue("id"), r.PathValue("task"))
	if err != nil {
		incidentFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, result)
}

func (a *API) incidentTaskHistory(w http.ResponseWriter, r *http.Request) {
	if !a.incidentTaskReady(w, r, true, "before") {
		return
	}
	result, err := a.DB.IncidentTaskHistory(r.Context(), httpapi.Principal(r), r.PathValue("id"), r.PathValue("task"), r.URL.Query().Get("before"))
	if err != nil {
		incidentFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, result)
}

func (a *API) createIncidentTask(w http.ResponseWriter, r *http.Request) {
	var input incident.TaskCreate
	if !decodeIncidentTask(w, r, &input) {
		return
	}
	if input.Validate() != nil {
		incidentFailure(w, r, incident.ErrTaskInput)
		return
	}
	if !a.incidentTaskReady(w, r, false) {
		return
	}
	result, err := a.DB.CreateIncidentTask(r.Context(), httpapi.Principal(r), r.PathValue("id"), r.Header.Get("Idempotency-Key"), input, httpapi.RequestID(r))
	if err != nil {
		incidentFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, result)
}

func (a *API) changeIncidentTask(w http.ResponseWriter, r *http.Request) {
	var input incident.TaskChange
	if !decodeIncidentTask(w, r, &input) {
		return
	}
	if input.Validate() != nil {
		incidentFailure(w, r, incident.ErrTaskInput)
		return
	}
	if !a.incidentTaskReady(w, r, true) {
		return
	}
	result, err := a.DB.ChangeIncidentTask(r.Context(), httpapi.Principal(r), r.PathValue("id"), r.PathValue("task"), r.Header.Get("Idempotency-Key"), input, httpapi.RequestID(r))
	if err != nil {
		incidentFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, result)
}
