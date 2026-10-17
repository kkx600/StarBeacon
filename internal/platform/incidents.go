package platform

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/incident"
	"github.com/kkx600/StarBeacon/internal/store"
)

func (a *API) registerIncidents(m *http.ServeMux) {
	m.HandleFunc("GET /api/v1/incidents", a.Auth.Require(true, a.incidents))
	m.HandleFunc("POST /api/v1/incidents", a.Auth.Require(true, a.createIncident))
	m.HandleFunc("GET /api/v1/incidents/assignees", a.Auth.Require(true, a.incidentAssignees))
	m.HandleFunc("GET /api/v1/incidents/{id}", a.Auth.Require(true, a.incident))
	m.HandleFunc("POST /api/v1/incidents/{id}", a.Auth.Require(true, a.changeIncident))
	m.HandleFunc("GET /api/v1/incidents/{id}/history", a.Auth.Require(true, a.incidentHistory))
	a.registerIncidentTasks(m)
}

func incidentFailure(w http.ResponseWriter, r *http.Request, err error) {
	var linked *store.IncidentLinked
	switch {
	case errors.Is(err, incident.ErrTaskInput):
		httpapi.Fail(w, r, 400, "invalid_incident_task", "请核对任务标题、说明、状态、负责人、截止时间和修订")
	case errors.Is(err, store.ErrIncidentTasksPending):
		httpapi.Fail(w, r, 409, "incident_tasks_pending", "事件仍有未完成的调查任务，请先完成或取消任务后结案")
	case errors.Is(err, store.ErrIncidentTaskClosed):
		httpapi.Fail(w, r, 409, "incident_task_readonly", "事件已结案，调查任务仅供查阅；需要继续调查时请先重开事件")
	case errors.Is(err, store.ErrIncidentTaskQuota):
		w.Header().Set("Retry-After", "60")
		httpapi.Fail(w, r, 429, "incident_task_quota", "调查任务或今日变更额度已用尽，请核对任务与留存范围")
	case errors.Is(err, incident.ErrInput):
		httpapi.Fail(w, r, 400, "invalid_incident", "事件参数无效，请核对标题、分类、状态、责任人、关联告警和结案材料")
	case errors.Is(err, pgx.ErrNoRows):
		httpapi.Fail(w, r, 404, "not_found", "事件、告警或分页续点不存在、已到保留期限或不可访问")
	case errors.Is(err, store.ErrIncidentExpired):
		httpapi.Fail(w, r, 410, "incident_expired", "记录已到保留期限，请刷新列表；原请求不能重新创建已到期的操作")
	case errors.Is(err, store.ErrIncidentOwner):
		httpapi.Fail(w, r, 409, "assignee_unavailable", "所选责任人已停用或不具备当前租户的调查权限，请重新选择")
	case errors.Is(err, store.ErrConflict):
		httpapi.Fail(w, r, 409, "incident_conflict", "事件修订或原请求已变化，请刷新后核对；相同请求键不能改变输入")
	case errors.Is(err, store.ErrAlertIdentity):
		httpapi.Fail(w, r, 409, "alert_identity_conflict", "关联告警来源不唯一或原始摘要已变化，事件尚未提交")
	case errors.As(err, &linked) && contract.ValidID(linked.ID):
		httpapi.JSON(w, 409, map[string]string{"code": "alert_already_linked", "message": "告警已关联事件，请核对既有调查，避免重复升级", "related_incident_id": linked.ID, "request_id": httpapi.RequestID(r)})
	case errors.Is(err, store.ErrIncidentQuota):
		w.Header().Set("Retry-After", "60")
		httpapi.Fail(w, r, 429, "incident_quota_exceeded", "事件记录或今日变更额度已用尽，请稍后重试或核对留存策略")
	default:
		httpapi.Fail(w, r, 503, "incident_unavailable", "事件服务暂不可用；保存结果需使用原请求核对后确认")
	}
}

func incidentQuery(r *http.Request, allowed ...string) bool {
	for key, values := range r.URL.Query() {
		found := false
		for _, candidate := range allowed {
			if key == candidate {
				found = true
			}
		}
		if !found || len(values) != 1 {
			return false
		}
	}
	return true
}
func decodeIncident(w http.ResponseWriter, r *http.Request, target any) bool {
	var raw json.RawMessage
	if !incidentQuery(r) || httpapi.Decode(w, r, &raw) != nil || contract.JSONFields(string(raw), []string{"spec", "alerts", "expected_revision", "note", "add_alerts", "title", "category", "severity", "status", "summary", "owner_id", "closure", "reason", "root_cause", "impact", "remediation", "verification", "evidence", "event_id", "raw_sha256"}, 65536) != nil {
		incidentFailure(w, r, incident.ErrInput)
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		incidentFailure(w, r, incident.ErrInput)
		return false
	}
	return true
}

func (a *API) incidents(w http.ResponseWriter, r *http.Request) {
	q := incident.Query{Status: r.URL.Query().Get("status"), Severity: r.URL.Query().Get("severity"), Before: r.URL.Query().Get("before")}
	if !incidentQuery(r, "status", "severity", "before") || q.Validate() != nil {
		incidentFailure(w, r, incident.ErrInput)
		return
	}
	if a.DB == nil {
		incidentFailure(w, r, errors.New("事件存储未配置"))
		return
	}
	page, err := a.DB.Incidents(r.Context(), httpapi.Principal(r), q)
	if err != nil {
		incidentFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, page)
}
func (a *API) incident(w http.ResponseWriter, r *http.Request) {
	if !incidentQuery(r) || !contract.ValidID(r.PathValue("id")) {
		incidentFailure(w, r, incident.ErrInput)
		return
	}
	if a.DB == nil {
		incidentFailure(w, r, errors.New("事件存储未配置"))
		return
	}
	record, err := a.DB.Incident(r.Context(), httpapi.Principal(r), r.PathValue("id"))
	if err != nil {
		incidentFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, record)
}
func (a *API) incidentAssignees(w http.ResponseWriter, r *http.Request) {
	if !incidentQuery(r) {
		incidentFailure(w, r, incident.ErrInput)
		return
	}
	if a.DB == nil {
		incidentFailure(w, r, errors.New("事件存储未配置"))
		return
	}
	rows, err := a.DB.IncidentAssignees(r.Context(), httpapi.Principal(r))
	if err != nil {
		incidentFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, map[string]any{"items": rows})
}
func (a *API) incidentHistory(w http.ResponseWriter, r *http.Request) {
	if !incidentQuery(r, "before") || !contract.ValidID(r.PathValue("id")) {
		incidentFailure(w, r, incident.ErrInput)
		return
	}
	if a.DB == nil {
		incidentFailure(w, r, errors.New("事件存储未配置"))
		return
	}
	rows, err := a.DB.IncidentHistory(r.Context(), httpapi.Principal(r), r.PathValue("id"), r.URL.Query().Get("before"))
	if err != nil {
		incidentFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, rows)
}

// 关联材料只保存身份、摘要、来源探针和实际时间；PG 不复制原始告警或报文正文。
func (a *API) freezeIncidentAlerts(ctx context.Context, tenant string, refs []incident.AlertRef) ([]incident.AlertEvidence, error) {
	frozen := []incident.AlertEvidence{}
	if incident.ValidateRefs(refs) != nil {
		return frozen, incident.ErrInput
	}
	if len(refs) > 0 && a.ES == nil {
		return frozen, errors.New("告警检索未配置")
	}
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	for _, ref := range refs {
		item, err := a.ES.ReadAlertEvidence(ctx, tenant, ref.EventID, ref.SHA256)
		if err != nil {
			return nil, err
		}
		if !contract.ValidID(item.SensorID) {
			return nil, store.ErrAlertIdentity
		}
		frozen = append(frozen, incident.AlertEvidence{AlertRef: ref, SensorID: item.SensorID, EventTime: item.Timestamp, ObservedAt: item.ObservedAt})
	}
	return frozen, nil
}
func (a *API) createIncident(w http.ResponseWriter, r *http.Request) {
	var input incident.Create
	if !decodeIncident(w, r, &input) {
		return
	}
	if input.Validate() != nil || !contract.ValidID(r.Header.Get("Idempotency-Key")) {
		incidentFailure(w, r, incident.ErrInput)
		return
	}
	if a.DB == nil {
		incidentFailure(w, r, errors.New("事件存储未配置"))
		return
	}
	u := httpapi.Principal(r)
	if existing, err := a.DB.IncidentReceipt(r.Context(), u, r.Header.Get("Idempotency-Key"), "create", store.IncidentCreateHash(input)); err == nil {
		httpapi.JSON(w, 200, existing)
		return
	} else if !errors.Is(err, pgx.ErrNoRows) {
		incidentFailure(w, r, err)
		return
	}
	frozen, err := a.freezeIncidentAlerts(r.Context(), u.TenantID, input.Alerts)
	if err != nil {
		incidentFailure(w, r, err)
		return
	}
	record, err := a.DB.CreateIncident(r.Context(), u, r.Header.Get("Idempotency-Key"), input, frozen, httpapi.RequestID(r))
	if err != nil {
		incidentFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, record)
}
func (a *API) changeIncident(w http.ResponseWriter, r *http.Request) {
	var input incident.Change
	if !decodeIncident(w, r, &input) {
		return
	}
	if !contract.ValidID(r.PathValue("id")) || input.Validate() != nil || !contract.ValidID(r.Header.Get("Idempotency-Key")) {
		incidentFailure(w, r, incident.ErrInput)
		return
	}
	if a.DB == nil {
		incidentFailure(w, r, errors.New("事件存储未配置"))
		return
	}
	u := httpapi.Principal(r)
	if existing, err := a.DB.IncidentReceipt(r.Context(), u, r.Header.Get("Idempotency-Key"), "change", store.IncidentChangeHash(r.PathValue("id"), input)); err == nil {
		httpapi.JSON(w, 200, existing)
		return
	} else if !errors.Is(err, pgx.ErrNoRows) {
		incidentFailure(w, r, err)
		return
	}
	frozen, err := a.freezeIncidentAlerts(r.Context(), u.TenantID, input.AddAlerts)
	if err != nil {
		incidentFailure(w, r, err)
		return
	}
	record, err := a.DB.ChangeIncident(r.Context(), u, r.PathValue("id"), r.Header.Get("Idempotency-Key"), input, frozen, httpapi.RequestID(r))
	if err != nil {
		incidentFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, record)
}
