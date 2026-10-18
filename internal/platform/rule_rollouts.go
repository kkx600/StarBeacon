package platform

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"io"
	"net/http"

	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/rulerollout"
)

func (a *API) registerRuleRollouts(m *http.ServeMux) {
	m.HandleFunc("GET /api/v1/rule-rollouts", a.Auth.Require(true, a.ruleRollouts))
	m.HandleFunc("GET /api/v1/rule-rollouts/{id}", a.Auth.Require(true, a.ruleRollout))
	m.HandleFunc("POST /api/v1/rule-rollouts", a.Auth.Require(true, a.createRuleRollout))
	m.HandleFunc("POST /api/v1/rule-rollouts/{id}/stop", a.Auth.Require(true, a.stopRuleRollout))
}
func rolloutFailure(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, rulerollout.ErrInput):
		httpapi.Fail(w, r, 400, "invalid_rule_rollout", err.Error())
	case errors.Is(err, rulerollout.ErrQuota):
		httpapi.Fail(w, r, 429, "rule_rollout_quota_exceeded", err.Error())
	default:
		operationError(w, r, err)
	}
}
func (a *API) ruleRollouts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if len(q) > 1 || len(q["cursor"]) > 1 || len(q) == 1 && !q.Has("cursor") || q.Has("cursor") && !contract.ValidID(q.Get("cursor")) {
		rolloutFailure(w, r, rulerollout.ErrInput)
		return
	}
	if a.DB == nil {
		httpapi.Fail(w, r, 503, "rule_rollout_unavailable", "分批发布数据服务暂不可用")
		return
	}
	out, err := a.DB.RuleRollouts(r.Context(), httpapi.Principal(r), q.Get("cursor"))
	if err != nil {
		rolloutFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, out)
}
func (a *API) ruleRollout(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" || !contract.ValidID(r.PathValue("id")) {
		rolloutFailure(w, r, rulerollout.ErrInput)
		return
	}
	if a.DB == nil {
		httpapi.Fail(w, r, 503, "rule_rollout_unavailable", "分批发布数据服务暂不可用")
		return
	}
	out, err := a.DB.RuleRollout(r.Context(), httpapi.Principal(r), r.PathValue("id"))
	if err != nil {
		rolloutFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, out)
}
func (a *API) createRuleRollout(w http.ResponseWriter, r *http.Request) {
	var input rulerollout.Create
	var raw bytes.Buffer
	r.Body = io.NopCloser(io.TeeReader(r.Body, &raw))
	if httpapi.Decode(w, r, &input) != nil || r.URL.RawQuery != "" || contract.JSONFields(raw.String(), []string{"id", "spec", "name", "plans", "plan_id", "revision", "canary_count", "batch_size", "observation_seconds", "timeout_seconds"}, 32768) != nil || input.Validate() != nil {
		rolloutFailure(w, r, rulerollout.ErrInput)
		return
	}
	if a.DB == nil || len(a.Signer) != ed25519.PrivateKeySize || a.Samples == nil {
		httpapi.Fail(w, r, 503, "rule_rollout_unavailable", "分批发布执行服务暂不可用")
		return
	}
	out, err := a.DB.CreateRuleRollout(r.Context(), httpapi.Principal(r), input, httpapi.RequestID(r))
	if err != nil {
		rolloutFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, out)
}
func (a *API) stopRuleRollout(w http.ResponseWriter, r *http.Request) {
	var input rulerollout.Stop
	var raw bytes.Buffer
	r.Body = io.NopCloser(io.TeeReader(r.Body, &raw))
	if httpapi.Decode(w, r, &input) != nil || r.URL.RawQuery != "" || !contract.ValidID(r.PathValue("id")) || contract.JSONFields(raw.String(), []string{"reason"}, 4096) != nil || input.Validate() != nil {
		rolloutFailure(w, r, rulerollout.ErrInput)
		return
	}
	// 停止不依赖任务签名或样本服务，避免这些服务故障时失去停止入口。
	if a.DB == nil {
		httpapi.Fail(w, r, 503, "rule_rollout_unavailable", "分批发布数据服务暂不可用")
		return
	}
	out, err := a.DB.StopRuleRollout(r.Context(), httpapi.Principal(r), r.PathValue("id"), input, httpapi.RequestID(r))
	if err != nil {
		rolloutFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, out)
}
