package platform

import (
	"net/http"
	"strconv"

	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/decision"
	"github.com/kkx600/StarBeacon/internal/httpapi"
)

func (a *API) createDecisionEvaluation(w http.ResponseWriter, r *http.Request) {
	var input decision.EvaluationRequest
	if decodeDecision(w, r, &input) != nil || input.Validate() != nil || len(r.Header.Values("Idempotency-Key")) != 1 || !contract.ValidID(r.Header.Get("Idempotency-Key")) {
		decisionFailure(w, r, decision.ErrInput)
		return
	}
	if !a.decisionReady(w, r) {
		return
	}
	record, err := a.DB.CreateDecisionEvaluation(r.Context(), httpapi.Principal(r), r.Header.Get("Idempotency-Key"), input)
	if err != nil {
		decisionFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, record)
}

func evaluationListQuery(r *http.Request) (decision.EvaluationQuery, error) {
	q := decision.EvaluationQuery{Limit: 20}
	for key, values := range r.URL.Query() {
		if len(values) != 1 {
			return q, decision.ErrInput
		}
		switch key {
		case "cursor":
			q.Cursor = values[0]
		case "policy_id":
			q.PolicyID = values[0]
		case "triage_id":
			q.TriageID = values[0]
		case "status":
			q.Status = values[0]
		case "limit":
			var err error
			q.Limit, err = strconv.Atoi(values[0])
			if err != nil || strconv.Itoa(q.Limit) != values[0] {
				return q, decision.ErrInput
			}
		default:
			return q, decision.ErrInput
		}
	}
	return q, q.Validate()
}

func (a *API) decisionEvaluations(w http.ResponseWriter, r *http.Request) {
	q, err := evaluationListQuery(r)
	if err != nil {
		decisionFailure(w, r, err)
		return
	}
	if !a.decisionReady(w, r) {
		return
	}
	page, err := a.DB.DecisionEvaluations(r.Context(), httpapi.Principal(r), q)
	if err != nil {
		decisionFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, page)
}

func (a *API) decisionEvaluation(w http.ResponseWriter, r *http.Request) {
	if !contract.ValidID(r.PathValue("id")) || len(r.URL.Query()) > 0 {
		decisionFailure(w, r, decision.ErrInput)
		return
	}
	if !a.decisionReady(w, r) {
		return
	}
	record, err := a.DB.DecisionEvaluation(r.Context(), httpapi.Principal(r), r.PathValue("id"))
	if err != nil {
		decisionFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, record)
}
