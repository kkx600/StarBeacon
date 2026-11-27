package platform

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/playbook"
	"github.com/kkx600/StarBeacon/internal/store"
)

func (a *API) registerPlaybooks(m *http.ServeMux) {
	m.HandleFunc("GET /api/v1/playbooks", a.Auth.Require(true, a.playbooks))
	m.HandleFunc("POST /api/v1/playbooks", a.Auth.Require(true, a.savePlaybook))
	m.HandleFunc("POST /api/v1/playbooks/validate", a.Auth.Require(true, a.validatePlaybook))
	m.HandleFunc("GET /api/v1/playbooks/{id}", a.Auth.Require(true, a.playbook))
	m.HandleFunc("PUT /api/v1/playbooks/{id}", a.Auth.Require(true, a.savePlaybook))
	m.HandleFunc("POST /api/v1/playbooks/{id}/publish", a.Auth.Require(true, a.publishPlaybook))
	m.HandleFunc("POST /api/v1/playbooks/{id}/runs", a.Auth.Require(true, a.startPlaybook))
	m.HandleFunc("GET /api/v1/playbook-runs", a.Auth.Require(true, a.playbookRuns))
	m.HandleFunc("GET /api/v1/playbook-runs/{id}", a.Auth.Require(true, a.playbookRun))
	m.HandleFunc("POST /api/v1/playbook-runs/{id}/steps", a.Auth.Require(true, a.acknowledgePlaybook))
}

func playbookFailure(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, playbook.ErrInput):
		httpapi.Fail(w, r, 400, "invalid_playbook", "请核对编排名、步骤和修订")
	case errors.Is(err, playbook.ErrPermission):
		httpapi.Fail(w, r, 403, "playbook_forbidden", "当前账号不能操作此编排")
	case errors.Is(err, pgx.ErrNoRows):
		httpapi.Fail(w, r, 404, "not_found", "编排、告警或本人运行记录不存在或不可访问")
	case errors.Is(err, playbook.ErrSource), errors.Is(err, store.ErrAlertIdentity), errors.Is(err, store.ErrConflict):
		httpapi.Fail(w, r, 409, "playbook_conflict", "编排修订、绑定材料或当前步骤发生变化，请刷新核对")
	case errors.Is(err, playbook.ErrNotReady):
		httpapi.Fail(w, r, 409, "playbook_step_waiting", "当前步骤仍在等待原业务入口的结果或实际设备回执")
	case errors.Is(err, playbook.ErrLimit):
		httpapi.Fail(w, r, 429, "playbook_limit", err.Error())
	default:
		httpapi.Fail(w, r, 503, "playbook_unavailable", "编排所需的存储或告警服务不可用")
	}
}

var playbookDefinitionFields = []string{"name", "steps", "kind", "description", "minimum_severity", "model", "plugin", "gateway",
	"id", "revision", "minimum_confidence", "policy", "sensor_id", "registration_id", "connector_id", "config_sha256", "ttl_seconds"}

func decodePlaybook(w http.ResponseWriter, r *http.Request, target any, fields []string) bool {
	const maximum = 32768
	r.Body = http.MaxBytesReader(w, r.Body, maximum)
	var raw json.RawMessage
	if r.URL.RawQuery != "" || httpapi.Decode(w, r, &raw) != nil || contract.JSONFields(string(raw), fields, maximum) != nil {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target) == nil
}

func playbookRequestKey(r *http.Request) string {
	keys := r.Header.Values("Idempotency-Key")
	if len(keys) != 1 || len(keys[0]) < 8 || !contract.ValidID(keys[0]) {
		return ""
	}
	return keys[0]
}

func (a *API) playbookReady(w http.ResponseWriter, r *http.Request, valid bool) bool {
	if !valid {
		playbookFailure(w, r, playbook.ErrInput)
		return false
	}
	if a.DB == nil {
		playbookFailure(w, r, errors.New("编排数据服务未就绪"))
		return false
	}
	return true
}

func writePlaybook[T any](w http.ResponseWriter, r *http.Request, out T, err error, status int) {
	if err != nil {
		playbookFailure(w, r, err)
		return
	}
	httpapi.JSON(w, status, out)
}

func (a *API) playbooks(w http.ResponseWriter, r *http.Request) {
	limit, ok := requestListLimit(w, r)
	if !ok || !a.playbookReady(w, r, incidentQuery(r, "cursor", "limit")) {
		return
	}
	out, err := a.DB.Playbooks(r.Context(), httpapi.Principal(r), r.URL.Query().Get("cursor"), limit)
	writePlaybook(w, r, out, err, 200)
}

func (a *API) playbook(w http.ResponseWriter, r *http.Request) {
	if !a.playbookReady(w, r, r.URL.RawQuery == "" && contract.ValidID(r.PathValue("id"))) {
		return
	}
	out, err := a.DB.Playbook(r.Context(), httpapi.Principal(r), r.PathValue("id"))
	writePlaybook(w, r, out, err, 200)
}

func (a *API) savePlaybook(w http.ResponseWriter, r *http.Request) {
	var input playbook.Change
	allowed := append([]string{"definition", "expected_revision"}, playbookDefinitionFields...)
	key := playbookRequestKey(r)
	if !a.playbookReady(w, r, key != "" && decodePlaybook(w, r, &input, allowed) && input.Definition.ValidDraft()) {
		return
	}
	out, err := a.DB.SavePlaybook(r.Context(), httpapi.Principal(r), r.PathValue("id"), key, input)
	writePlaybook(w, r, out, err, 200)
}

func (a *API) validatePlaybook(w http.ResponseWriter, r *http.Request) {
	var input playbook.Definition
	if !a.playbookReady(w, r, decodePlaybook(w, r, &input, playbookDefinitionFields) && input.ValidDraft()) {
		return
	}
	issues, err := a.DB.ValidatePlaybook(r.Context(), httpapi.Principal(r), input)
	writePlaybook(w, r, map[string]any{"issues": issues}, err, 200)
}

func (a *API) publishPlaybook(w http.ResponseWriter, r *http.Request) {
	var input playbook.Revision
	id := r.PathValue("id")
	if !a.playbookReady(w, r, contract.ValidID(id) && decodePlaybook(w, r, &input, []string{"revision", "sha256"}) && input.Valid()) {
		return
	}
	item, issues, err := a.DB.PublishPlaybook(r.Context(), httpapi.Principal(r), id, input)
	if err == nil && len(issues) > 0 {
		httpapi.JSON(w, 409, map[string]any{"code": "playbook_invalid", "message": "编排步骤未通过发布校验", "request_id": httpapi.RequestID(r), "issues": issues})
		return
	}
	writePlaybook(w, r, item, err, 200)
}

func (a *API) startPlaybook(w http.ResponseWriter, r *http.Request) {
	var input playbook.Start
	id, key := r.PathValue("id"), playbookRequestKey(r)
	if !a.playbookReady(w, r, contract.ValidID(id) && key != "" && decodePlaybook(w, r, &input, []string{"revision", "sha256", "event_id", "raw_sha256"}) && input.Valid()) {
		return
	}
	if a.ES == nil {
		playbookFailure(w, r, errors.New("告警材料服务未就绪"))
		return
	}
	u := httpapi.Principal(r)
	alert, err := a.ES.ReadAlertEvidence(r.Context(), u.TenantID, input.EventID, input.RawSHA256)
	if err != nil {
		playbookFailure(w, r, err)
		return
	}
	out, err := a.DB.StartPlaybookRun(r.Context(), u, id, key, input, alert)
	writePlaybook(w, r, out, err, 201)
}

func (a *API) playbookRuns(w http.ResponseWriter, r *http.Request) {
	limit, ok := requestListLimit(w, r)
	if !ok || !a.playbookReady(w, r, incidentQuery(r, "cursor", "limit")) {
		return
	}
	out, err := a.DB.PlaybookRuns(r.Context(), httpapi.Principal(r), r.URL.Query().Get("cursor"), limit)
	writePlaybook(w, r, out, err, 200)
}

func (a *API) playbookRun(w http.ResponseWriter, r *http.Request) {
	if !a.playbookReady(w, r, r.URL.RawQuery == "" && contract.ValidID(r.PathValue("id"))) {
		return
	}
	out, err := a.DB.PlaybookRun(r.Context(), httpapi.Principal(r), r.PathValue("id"))
	writePlaybook(w, r, out, err, 200)
}

func (a *API) acknowledgePlaybook(w http.ResponseWriter, r *http.Request) {
	var input playbook.Acknowledge
	id := r.PathValue("id")
	if !a.playbookReady(w, r, contract.ValidID(id) && decodePlaybook(w, r, &input, []string{"step", "confirmed"}) && input.Confirmed) {
		return
	}
	out, err := a.DB.AcknowledgePlaybookStep(r.Context(), httpapi.Principal(r), id, input)
	writePlaybook(w, r, out, err, 200)
}
