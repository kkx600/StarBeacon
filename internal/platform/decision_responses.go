package platform

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/decision"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/response"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/triage"
)

func decisionResponseFailure(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, decision.ErrInput), errors.Is(err, response.ErrInput):
		httpapi.Fail(w, r, 400, "invalid_decision_response", "请确认原评估、探针、联动设备、期限及处置依据")
	case errors.Is(err, decision.ErrSource), errors.Is(err, store.ErrAlertIdentity):
		httpapi.Fail(w, r, 409, "decision_response_source_changed", "评估、当前策略或告警材料已变化，未授权处置，请刷新后重新评估")
	case errors.Is(err, store.ErrConflict):
		httpapi.Fail(w, r, 409, "decision_response_conflict", "原评估已有处置记录，或请求输入、探针注册及在途任务已变化，请核对原记录")
	case errors.Is(err, response.ErrUnavailable):
		httpapi.Fail(w, r, 409, "response_device_unavailable", "探针或联动设备尚未就绪，请刷新后核对")
	case errors.Is(err, response.ErrQuota):
		httpapi.Fail(w, r, 429, "response_quota_exhausted", err.Error())
	case errors.Is(err, response.ErrPermission), errors.Is(err, decision.ErrPermission):
		httpapi.Fail(w, r, 403, "decision_response_forbidden", "当前账号不再具有处置确认权限，请核对账号状态")
	case errors.Is(err, pgx.ErrNoRows):
		httpapi.Fail(w, r, 404, "not_found", "本人评估、研判或探针不存在、已到期或不可访问")
	default:
		httpapi.Fail(w, r, 503, "decision_response_unavailable", "处置确认暂不可用；提交结果未确认时，请保留原请求键并核对原提交")
	}
}

func (a *API) decisionResponse(w http.ResponseWriter, r *http.Request) {
	if !contract.ValidID(r.PathValue("id")) || r.URL.RawQuery != "" {
		decisionResponseFailure(w, r, decision.ErrInput)
		return
	}
	if !a.decisionReady(w, r) {
		return
	}
	record, err := a.DB.DecisionResponse(r.Context(), httpapi.Principal(r), r.PathValue("id"))
	if err != nil {
		decisionResponseFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, map[string]any{"item": record})
}

func (a *API) createDecisionResponse(w http.ResponseWriter, r *http.Request) {
	keys := r.Header.Values("Idempotency-Key")
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8192))
	var input decision.ResponseRequest
	fields := []string{"evaluation_sha256", "sensor_id", "registration_id", "connector_id", "config_sha256", "ttl_seconds", "reason", "confirmed"}
	if err != nil || r.URL.RawQuery != "" || !contract.ValidID(r.PathValue("id")) || len(keys) != 1 || !contract.ValidID(keys[0]) || len(keys[0]) < 8 || contract.JSONFields(string(raw), fields, 8192) != nil || json.Unmarshal(raw, &input) != nil || input.Validate() != nil {
		decisionResponseFailure(w, r, decision.ErrInput)
		return
	}
	if !a.decisionReady(w, r) {
		return
	}
	u := httpapi.Principal(r)
	prior, err := a.DB.ExistingDecisionResponse(r.Context(), u, r.PathValue("id"), keys[0], input)
	if err == nil {
		httpapi.JSON(w, 200, prior)
		return
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		decisionResponseFailure(w, r, err)
		return
	}
	if a.ES == nil || len(a.Signer) != ed25519.PrivateKeySize {
		decisionResponseFailure(w, r, errors.New("告警材料或签名服务未就绪"))
		return
	}
	evaluation, err := a.DB.DecisionEvaluation(r.Context(), u, r.PathValue("id"))
	if err != nil {
		decisionResponseFailure(w, r, err)
		return
	}
	work, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	alert, err := a.ES.ReadAlertEvidence(work, u.TenantID, evaluation.Result.EventID, evaluation.Result.RawSHA256)
	if err != nil {
		decisionResponseFailure(w, r, err)
		return
	}
	evidence, err := triage.Freeze(alert)
	if err != nil {
		decisionResponseFailure(w, r, decision.ErrSource)
		return
	}
	record, err := a.DB.CreateDecisionResponse(r.Context(), u, r.PathValue("id"), keys[0], input, evidence, a.Signer)
	if err != nil {
		decisionResponseFailure(w, r, err)
		return
	}
	if a.Wakeup != nil {
		a.Wakeup.Notify(u.TenantID, input.SensorID)
	}
	httpapi.JSON(w, 202, record)
}
