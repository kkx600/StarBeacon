package platform

import (
	"bytes"
	"encoding/json"
	"net/http"
	"slices"

	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/decision"
	"github.com/kkx600/StarBeacon/internal/httpapi"
)

func (a *API) registerDecisionAutomation(m *http.ServeMux) {
	m.HandleFunc("GET /api/v1/decision-automation", a.Auth.Require(false, a.decisionAutomation))
	m.HandleFunc("PUT /api/v1/decision-automation", a.Auth.Require(true, a.saveDecisionAutomation))
	m.HandleFunc("POST /api/v1/decision-automation/pause", a.Auth.Require(true, a.pauseDecisionAutomation))
	m.HandleFunc("GET /api/v1/decision-plans", a.Auth.Require(false, a.decisionPlans))
	m.HandleFunc("POST /api/v1/decision-evaluations/{id}/response/reject", a.Auth.Require(true, a.rejectDecisionPlan))
}

func decodeAutomation(w http.ResponseWriter, r *http.Request, target any, fields ...string) error {
	if r.URL.RawQuery != "" {
		return decision.ErrInput
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	var raw json.RawMessage
	var keys map[string]json.RawMessage
	if httpapi.Decode(w, r, &raw) != nil || contract.JSONFields(string(raw), fields, 4096) != nil ||
		json.Unmarshal(raw, &keys) != nil || keys == nil || len(keys) != len(fields) || json.Unmarshal(raw, target) != nil {
		return decision.ErrInput
	}
	for _, value := range keys {
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return decision.ErrInput
		}
	}
	return nil
}

func (a *API) decisionAutomation(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		decisionFailure(w, r, decision.ErrInput)
		return
	}
	if !a.decisionReady(w, r) {
		return
	}
	result, err := a.DB.DecisionAutomation(r.Context(), httpapi.Principal(r))
	if err != nil {
		decisionFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, result)
}

func (a *API) saveDecisionAutomation(w http.ResponseWriter, r *http.Request) {
	var input decision.AutomationChange
	if decodeAutomation(w, r, &input, "expected_revision", "ceiling", "paused") != nil || !input.Valid() {
		decisionFailure(w, r, decision.ErrInput)
		return
	}
	a.changeDecisionAutomation(w, r, &input)
}

func (a *API) pauseDecisionAutomation(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" || r.ContentLength != 0 {
		decisionFailure(w, r, decision.ErrInput)
		return
	}
	a.changeDecisionAutomation(w, r, nil)
}

func (a *API) changeDecisionAutomation(w http.ResponseWriter, r *http.Request, input *decision.AutomationChange) {
	if !a.decisionReady(w, r) {
		return
	}
	result, err := a.DB.ChangeDecisionAutomation(r.Context(), httpapi.Principal(r), input)
	if err != nil {
		decisionFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, result)
}

func (a *API) decisionPlans(w http.ResponseWriter, r *http.Request) {
	limit, ok := requestListLimit(w, r)
	if !ok {
		return
	}
	query := r.URL.Query()
	view, cursor := query.Get("view"), query.Get("cursor")
	if view == "" {
		view = "pending"
	}
	if !incidentQuery(r, "view", "cursor", "limit") || !slices.Contains([]string{"pending", "history", "feedback"}, view) ||
		cursor != "" && !contract.ValidID(cursor) {
		decisionFailure(w, r, decision.ErrInput)
		return
	}
	if !a.decisionReady(w, r) {
		return
	}
	result, err := a.DB.DecisionPlans(r.Context(), httpapi.Principal(r), view, cursor, limit)
	if err != nil {
		decisionFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, result)
}

func (a *API) rejectDecisionPlan(w http.ResponseWriter, r *http.Request) {
	var input decision.RejectPlan
	if !contract.ValidID(r.PathValue("id")) || decodeAutomation(w, r, &input, "plan_sha256", "reason") != nil || !input.Valid() {
		decisionResponseFailure(w, r, decision.ErrInput)
		return
	}
	if !a.decisionReady(w, r) {
		return
	}
	result, err := a.DB.RejectDecisionPlan(r.Context(), httpapi.Principal(r), r.PathValue("id"), input)
	if err != nil {
		decisionResponseFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, result)
}
