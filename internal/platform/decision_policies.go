package platform

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/decision"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/store"
)

func (a *API) registerDecisionPolicies(m *http.ServeMux) {
	m.HandleFunc("GET /api/v1/decision-policies", a.Auth.Require(false, a.decisionPolicies))
	m.HandleFunc("GET /api/v1/decision-policies/{id}/revisions/{revision}", a.Auth.Require(false, a.decisionPolicy))
	m.HandleFunc("POST /api/v1/decision-policies", a.Auth.Require(true, a.saveDecisionPolicy))
	m.HandleFunc("POST /api/v1/decision-policies/validate", a.Auth.Require(false, a.validateDecisionPolicy))
	m.HandleFunc("POST /api/v1/decision-policies/{id}/evaluate", a.Auth.Require(true, a.evaluateDecisionPolicy))
	m.HandleFunc("POST /api/v1/decision-evaluations", a.Auth.Require(true, a.createDecisionEvaluation))
	m.HandleFunc("GET /api/v1/decision-evaluations", a.Auth.Require(false, a.decisionEvaluations))
	m.HandleFunc("GET /api/v1/decision-evaluations/{id}", a.Auth.Require(false, a.decisionEvaluation))
	m.HandleFunc("GET /api/v1/decision-evaluations/{id}/response", a.Auth.Require(false, a.decisionResponse))
	capacity := make(chan struct{}, 2)
	m.HandleFunc("POST /api/v1/decision-evaluations/{id}/response", a.Auth.Require(true, func(w http.ResponseWriter, r *http.Request) {
		select {
		case capacity <- struct{}{}:
			defer func() { <-capacity }()
			a.createDecisionResponse(w, r)
		default:
			httpapi.Fail(w, r, 429, "decision_response_capacity_exceeded", "处置材料正在核对其他请求，请稍后重试")
		}
	}))
}

func decodeDecision(w http.ResponseWriter, r *http.Request, target any) error {
	if len(r.URL.Query()) > 0 {
		return decision.ErrInput
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16384)
	var raw json.RawMessage
	if httpapi.Decode(w, r, &raw) != nil || contract.JSONFields(string(raw), []string{"id", "policy_id", "expected_revision", "name", "description", "active", "definition", "schema_version", "mode", "expression", "threshold", "candidate_action", "max_age_seconds", "protected_prefixes", "triage_id"}, 16384) != nil {
		return decision.ErrInput
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		return decision.ErrInput
	}
	return nil
}

func decisionFailure(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, decision.ErrInput):
		httpapi.Fail(w, r, 400, "invalid_decision_policy", "请核对策略名称、表达式类型、阈值、材料时限与保护网段")
	case errors.Is(err, decision.ErrMode):
		httpapi.Fail(w, r, 409, "decision_mode_unavailable", "当前仅支持影子评估；审批和自动执行需要独立的校准与设备执行资格")
	case errors.Is(err, decision.ErrPermission):
		httpapi.Fail(w, r, 403, "decision_policy_forbidden", "当前账号不再具有决策策略操作权限，请重新登录并核对权限")
	case errors.Is(err, decision.ErrQuota):
		httpapi.Fail(w, r, 429, "decision_policy_quota", "决策策略数量或最近 24 小时变更、评估额度已达上限")
	case errors.Is(err, store.ErrConflict):
		httpapi.Fail(w, r, 409, "decision_policy_conflict", "策略修订或原提交输入已变化，请刷新后核对")
	case errors.Is(err, pgx.ErrNoRows):
		httpapi.Fail(w, r, 404, "not_found", "策略修订、本人研判或评估记录不存在、已到期或不可访问")
	default:
		httpapi.Fail(w, r, 503, "decision_policy_unavailable", "决策策略或研判材料暂不可用；提交结果未确认时请核对原提交")
	}
}

func (a *API) decisionReady(w http.ResponseWriter, r *http.Request) bool {
	if a.DB != nil {
		return true
	}
	decisionFailure(w, r, errors.New("决策策略存储不可用"))
	return false
}

func decisionListQuery(r *http.Request) (decision.ListQuery, error) {
	q := decision.ListQuery{Limit: 20}
	for key, values := range r.URL.Query() {
		if len(values) != 1 {
			return q, decision.ErrInput
		}
		switch key {
		case "cursor":
			q.Cursor = values[0]
		case "keyword":
			q.Keyword = values[0]
		case "active":
			q.Active = values[0]
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

func (a *API) decisionPolicies(w http.ResponseWriter, r *http.Request) {
	q, err := decisionListQuery(r)
	if err != nil {
		decisionFailure(w, r, err)
		return
	}
	if !a.decisionReady(w, r) {
		return
	}
	result, err := a.DB.DecisionPolicies(r.Context(), httpapi.Principal(r), q)
	if err != nil {
		decisionFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, result)
}

func (a *API) decisionPolicy(w http.ResponseWriter, r *http.Request) {
	revision, err := strconv.ParseInt(r.PathValue("revision"), 10, 64)
	if err != nil || strconv.FormatInt(revision, 10) != r.PathValue("revision") || revision < 1 || revision > decision.MaxRevision || !contract.ValidID(r.PathValue("id")) || len(r.URL.Query()) > 0 {
		decisionFailure(w, r, decision.ErrInput)
		return
	}
	if !a.decisionReady(w, r) {
		return
	}
	result, err := a.DB.DecisionPolicy(r.Context(), httpapi.Principal(r), r.PathValue("id"), revision)
	if err != nil {
		decisionFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, result)
}

func (a *API) saveDecisionPolicy(w http.ResponseWriter, r *http.Request) {
	var input decision.Change
	if err := decodeDecision(w, r, &input); err != nil {
		decisionFailure(w, r, err)
		return
	}
	if err := input.Validate(); err != nil || !contract.ValidID(r.Header.Get("Idempotency-Key")) {
		if err == nil {
			err = decision.ErrInput
		}
		decisionFailure(w, r, err)
		return
	}
	if !a.decisionReady(w, r) {
		return
	}
	result, err := a.DB.SaveDecisionPolicy(r.Context(), httpapi.Principal(r), r.Header.Get("Idempotency-Key"), input)
	if err != nil {
		decisionFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, result)
}

func (a *API) validateDecisionPolicy(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Definition decision.Definition `json:"definition"`
	}
	if err := decodeDecision(w, r, &input); err != nil {
		decisionFailure(w, r, err)
		return
	}
	if err := input.Definition.Validate(); err != nil {
		decisionFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, map[string]any{"valid": true, "schema_version": decision.Schema, "definition_sha256": decision.Digest(input.Definition), "execution_authorized": false})
}

func (a *API) evaluateDecisionPolicy(w http.ResponseWriter, r *http.Request) {
	var input decision.EvaluateRequest
	if decodeDecision(w, r, &input) != nil || input.Validate() != nil || !contract.ValidID(r.PathValue("id")) {
		decisionFailure(w, r, decision.ErrInput)
		return
	}
	if !a.decisionReady(w, r) {
		return
	}
	result, err := a.DB.EvaluateDecisionPolicy(r.Context(), httpapi.Principal(r), r.PathValue("id"), input)
	if err != nil {
		decisionFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, result)
}
