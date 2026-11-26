package platform

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/gatewayblock"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/store"
)

func (a *API) registerGatewayBlocks(m *http.ServeMux) {
	m.HandleFunc("GET /api/v1/gateway-block/settings", a.Auth.Require(true, a.gatewayBlockSettings))
	m.HandleFunc("PUT /api/v1/gateway-block/settings", a.Auth.Require(true, a.saveGatewayBlockSettings))
	m.HandleFunc("GET /api/v1/gateway-block/policies", a.Auth.Require(true, a.gatewayBlockPolicies))
	m.HandleFunc("PUT /api/v1/gateway-block/policies/{id}", a.Auth.Require(true, a.saveGatewayBlockPolicy))
	m.HandleFunc("GET /api/v1/gateway-block/requests/{id}", a.Auth.Require(true, a.gatewayBlockRequest))
	m.HandleFunc("POST /api/v1/alerts/{id}/gateway-blocks", a.Auth.Require(true, a.createGatewayBlockReview))
}

func gatewayFailure(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, gatewayblock.ErrInput):
		httpapi.Fail(w, r, 400, "invalid_gateway_block", "请核对网关配置、策略修订和告警信息")
	case errors.Is(err, gatewayblock.ErrPermission):
		httpapi.Fail(w, r, 403, "gateway_block_forbidden", "当前账号没有受控网关阻断权限")
	case errors.Is(err, pgx.ErrNoRows):
		httpapi.Fail(w, r, 404, "not_found", "网关策略、告警或请求不可查询")
	case errors.Is(err, store.ErrConflict), errors.Is(err, store.ErrAlertIdentity), errors.Is(err, gatewayblock.ErrIneligible):
		httpapi.Fail(w, r, 409, "gateway_block_conflict", "授权、观测、研判或原提交已变化，请刷新后核对")
	case errors.Is(err, gatewayblock.ErrLimit):
		httpapi.Fail(w, r, 429, "gateway_block_limit", "网关策略或待处理请求已达到上限")
	default:
		httpapi.Fail(w, r, 503, "gateway_block_unavailable", "受控网关服务暂时不可用")
	}
}

func readGatewayJSON(w http.ResponseWriter, r *http.Request, out any, fields []string) bool {
	const limit = 16 * 1024
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	var raw json.RawMessage
	if r.URL.RawQuery != "" || httpapi.Decode(w, r, &raw) != nil || contract.JSONFields(string(raw), fields, limit) != nil {
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	return dec.Decode(out) == nil
}

func (a *API) gatewayReady(w http.ResponseWriter, r *http.Request, valid bool) bool {
	if !valid {
		gatewayFailure(w, r, gatewayblock.ErrInput)
		return false
	}
	if a.DB == nil {
		gatewayFailure(w, r, gatewayblock.ErrUnavailable)
		return false
	}
	return true
}

func (a *API) gatewayBlockSettings(w http.ResponseWriter, r *http.Request) {
	if !a.gatewayReady(w, r, r.URL.RawQuery == "") {
		return
	}
	result, err := a.DB.GatewayBlockSettings(r.Context(), httpapi.Principal(r))
	if err != nil {
		gatewayFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, result)
}

func (a *API) saveGatewayBlockSettings(w http.ResponseWriter, r *http.Request) {
	var change gatewayblock.SettingsChange
	if !a.gatewayReady(w, r, readGatewayJSON(w, r, &change, []string{"expected_revision", "enabled", "per_minute"}) && change.Valid()) {
		return
	}
	result, err := a.DB.SaveGatewayBlockSettings(r.Context(), httpapi.Principal(r), change, httpapi.RequestID(r))
	if err != nil {
		gatewayFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, result)
}

func (a *API) gatewayBlockPolicies(w http.ResponseWriter, r *http.Request) {
	cursor := r.URL.Query().Get("cursor")
	limit, ok := requestListLimit(w, r)
	if !ok {
		return
	}
	if !a.gatewayReady(w, r, incidentQuery(r, "cursor", "limit") && (cursor == "" || contract.ValidID(cursor))) {
		return
	}
	result, err := a.DB.GatewayBlockPolicies(r.Context(), httpapi.Principal(r), cursor, limit)
	if err != nil {
		gatewayFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, result)
}

func (a *API) saveGatewayBlockPolicy(w http.ResponseWriter, r *http.Request) {
	var change gatewayblock.PolicyChange
	fields := []string{"expected_revision", "definition", "name", "enabled", "trigger", "sensor_id", "registration_id",
		"rule_id", "rule_revision", "scope", "sources", "destinations", "lease_seconds", "valid_until"}
	if !a.gatewayReady(w, r, contract.ValidID(r.PathValue("id")) && readGatewayJSON(w, r, &change, fields)) {
		return
	}
	result, err := a.DB.SaveGatewayBlockPolicy(r.Context(), httpapi.Principal(r), r.PathValue("id"), change, httpapi.RequestID(r))
	if err != nil {
		gatewayFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, result)
}

func (a *API) gatewayBlockRequest(w http.ResponseWriter, r *http.Request) {
	if !a.gatewayReady(w, r, r.URL.RawQuery == "" && contract.ValidID(r.PathValue("id"))) {
		return
	}
	result, err := a.DB.GatewayBlockRequest(r.Context(), httpapi.Principal(r), r.PathValue("id"))
	if err != nil {
		gatewayFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, result)
}

func (a *API) createGatewayBlockReview(w http.ResponseWriter, r *http.Request) {
	var input gatewayblock.ReviewRequest
	key, event := r.Header.Get("Idempotency-Key"), r.PathValue("id")
	fields := []string{"policy_id", "policy_revision", "assessment_revision", "raw_sha256"}
	if !a.gatewayReady(w, r, gatewayblock.ValidDigest(event) && len(r.Header.Values("Idempotency-Key")) == 1 &&
		len(key) >= 8 && contract.ValidID(key) && readGatewayJSON(w, r, &input, fields) && input.Valid()) {
		return
	}
	if a.ES == nil || len(a.Signer) != ed25519.PrivateKeySize {
		gatewayFailure(w, r, gatewayblock.ErrUnavailable)
		return
	}
	user := httpapi.Principal(r)
	alert, err := a.ES.ReadGatewayAlert(r.Context(), user.TenantID, event, input.RawSHA256)
	if err != nil {
		gatewayFailure(w, r, err)
		return
	}
	result, err := a.DB.CreateGatewayBlockReview(r.Context(), user, input, key, alert)
	if err != nil {
		gatewayFailure(w, r, err)
		return
	}
	if result.State == "pending" && a.Wakeup != nil {
		a.Wakeup.Notify(user.TenantID, alert.SensorID)
	}
	httpapi.JSON(w, 202, result)
}
