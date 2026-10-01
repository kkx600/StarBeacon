package platform

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/store"
)

func (a *API) registerTasks(m *http.ServeMux) {
	m.HandleFunc("GET /api/v1/tasks", a.Auth.Require(true, a.tasks))
	m.HandleFunc("POST /api/v1/sensors/{id}/tasks", a.Auth.Require(true, a.createTask))
	m.HandleFunc("POST /api/v1/tasks/{id}/cancel", a.Auth.Require(true, a.cancelTask))
	m.HandleFunc("GET /api/v1/rule-packages", a.Auth.Require(true, a.rulePackages))
	m.HandleFunc("POST /api/v1/rule-packages", a.Auth.Require(true, a.saveRulePackage))
	m.HandleFunc("GET /api/v1/rule-packages/{id}/{revision}", a.Auth.Require(true, a.rulePackage))
}
func operationError(w http.ResponseWriter, r *http.Request, e error) {
	switch {
	case errors.Is(e, store.ErrConflict):
		httpapi.Fail(w, r, 409, "resource_conflict", "资源修订或在途任务冲突，请刷新后核对")
	case errors.Is(e, pgx.ErrNoRows):
		httpapi.Fail(w, r, 404, "not_found", "对象不存在或不可访问")
	default:
		httpapi.Fail(w, r, 503, "storage_unavailable", "暂时无法保存或读取对象")
	}
}
func (a *API) tasks(w http.ResponseWriter, r *http.Request) {
	v, e := a.DB.Tasks(r.Context(), httpapi.Principal(r).TenantID, r.URL.Query().Get("sensor_id"))
	if e != nil {
		operationError(w, r, e)
		return
	}
	httpapi.JSON(w, 200, map[string]any{"items": v})
}
func (a *API) createTask(w http.ResponseWriter, r *http.Request) {
	if len(a.Signer) == 0 {
		httpapi.Fail(w, r, 503, "signer_unavailable", "平台任务签名密钥未配置")
		return
	}
	key := r.Header.Get("Idempotency-Key")
	if len(key) < 8 || len(key) > 128 || strings.TrimSpace(key) != key {
		httpapi.Fail(w, r, 400, "idempotency_key_required", "需要提供 8–128 字符的幂等键")
		return
	}
	var input struct {
		Kind      string `json:"kind"`
		PackageID string `json:"package_id"`
		Revision  int64  `json:"revision"`
		SampleID  string `json:"sample_id"`
		RuleMode  string `json:"rule_mode"`
	}
	if e := httpapi.Decode(w, r, &input); e != nil {
		httpapi.Fail(w, r, 400, "invalid_request", "任务参数无效")
		return
	}
	if input.Kind != "rules.replay" && (input.SampleID != "" || input.RuleMode != "") {
		httpapi.Fail(w, r, 400, "invalid_request", "该任务不接受重放参数")
		return
	}
	u := httpapi.Principal(r)
	sensors, e := a.DB.Sensors(r.Context(), u.TenantID)
	if e != nil {
		operationError(w, r, e)
		return
	}
	var target *model.Sensor
	for i := range sensors {
		if sensors[i].ID == r.PathValue("id") && sensors[i].Active {
			target = &sensors[i]
			break
		}
	}
	if target == nil {
		operationError(w, r, pgx.ErrNoRows)
		return
	}
	var health model.HostHealth
	if json.Unmarshal(target.Health, &health) != nil || health.CommandSignerSHA256 != control.Digest(a.Signer.Public().(ed25519.PublicKey)) {
		httpapi.Fail(w, r, 409, "device_trust_mismatch", "设备尚未上报匹配的平台任务信任信息")
		return
	}
	supported := false
	for _, v := range health.TaskCapabilities {
		if v == input.Kind {
			supported = true
		}
	}
	if !supported {
		httpapi.Fail(w, r, 409, "capability_unavailable", "设备未提供该任务能力")
		return
	}
	payload := json.RawMessage(`{}`)
	switch input.Kind {
	case "rules.replay":
		if input.RuleMode == "registered" && !health.RegisteredRulesAvailable {
			httpapi.Fail(w, r, 409, "capability_unavailable", "设备未登记规则快照，请选择指定规则包修订")
			return
		}
		if a.Samples == nil {
			httpapi.Fail(w, r, 503, "sample_storage_unavailable", "平台样本存储未配置")
			return
		}
		sample, e := a.DB.Sample(r.Context(), u.TenantID, input.SampleID)
		if e != nil {
			operationError(w, r, e)
			return
		}
		p := control.Replay{SampleID: sample.ID, SampleSHA256: sample.SHA256, SampleSize: sample.Size, RuleMode: input.RuleMode}
		if input.RuleMode == "package" {
			rules, e := a.DB.RulePackage(r.Context(), u.TenantID, input.PackageID, input.Revision)
			if e != nil {
				operationError(w, r, e)
				return
			}
			p.Package = &control.RulePackage{PackageID: rules.ID, Revision: rules.Revision, EngineVersion: rules.EngineVersion, Text: rules.Text, SHA256: rules.SHA256}
		} else if input.RuleMode != "registered" || input.PackageID != "" || input.Revision != 0 {
			httpapi.Fail(w, r, 400, "invalid_request", "请选择登记规则快照或指定规则包修订")
			return
		}
		payload, e = control.ReplayPayload(p)
		if e != nil {
			httpapi.Fail(w, r, 400, "package_too_large", e.Error())
			return
		}
	case "diagnostics":
		if input.PackageID != "" || input.Revision != 0 {
			httpapi.Fail(w, r, 400, "invalid_request", "诊断任务不接受规则包参数")
			return
		}
	case "rules.validate", "rules.apply":
		p, e := a.DB.RulePackage(r.Context(), u.TenantID, input.PackageID, input.Revision)
		if e != nil {
			operationError(w, r, e)
			return
		}
		if input.Kind == "rules.apply" {
			httpapi.Fail(w, r, 409, "release_validation_required", "规则发布需要样本回放与完整包验收，装载检查不能单独授予发布资格")
			return
		}
		payload, e = control.RulePayload(control.RulePackage{PackageID: p.ID, Revision: p.Revision, EngineVersion: p.EngineVersion, Text: p.Text, SHA256: p.SHA256})
		if e != nil {
			httpapi.Fail(w, r, 400, "package_too_large", e.Error())
			return
		}
	default:
		httpapi.Fail(w, r, 400, "unsupported_task", "任务类型不受支持")
		return
	}
	id, e := a.DB.CreateTask(r.Context(), u, target.ID, input.Kind, key, payload, a.Signer)
	if e != nil {
		operationError(w, r, e)
		return
	}
	a.Wakeup.Notify(u.TenantID, target.ID)
	httpapi.JSON(w, 202, map[string]string{"id": id})
}
func (a *API) cancelTask(w http.ResponseWriter, r *http.Request) {
	if e := a.DB.CancelTask(r.Context(), httpapi.Principal(r), r.PathValue("id"), httpapi.RequestID(r)); e != nil {
		operationError(w, r, e)
		return
	}
	httpapi.JSON(w, 200, map[string]bool{"ok": true})
}
func (a *API) rulePackages(w http.ResponseWriter, r *http.Request) {
	items, e := a.DB.RulePackages(r.Context(), httpapi.Principal(r).TenantID)
	if e != nil {
		operationError(w, r, e)
		return
	}
	httpapi.JSON(w, 200, map[string]any{"items": items})
}
func (a *API) rulePackage(w http.ResponseWriter, r *http.Request) {
	revision, e := strconv.ParseInt(r.PathValue("revision"), 10, 64)
	if e != nil || revision < 1 {
		httpapi.Fail(w, r, 400, "invalid_revision", "规则修订号无效")
		return
	}
	v, e := a.DB.RulePackage(r.Context(), httpapi.Principal(r).TenantID, r.PathValue("id"), revision)
	if e != nil {
		operationError(w, r, e)
		return
	}
	httpapi.JSON(w, 200, v)
}
func (a *API) saveRulePackage(w http.ResponseWriter, r *http.Request) {
	var input struct {
		ID               string `json:"id"`
		Name             string `json:"name"`
		Text             string `json:"text"`
		ExpectedRevision int64  `json:"expected_revision"`
	}
	if e := httpapi.Decode(w, r, &input); e != nil {
		httpapi.Fail(w, r, 400, "invalid_request", "规则包参数无效")
		return
	}
	input.Name = strings.TrimSpace(input.Name)
	if input.ID == "" {
		input.ID = store.RandomID("rules_")
	}
	if !contract.ValidID(input.ID) || len([]rune(input.Name)) < 1 || len([]rune(input.Name)) > 128 || input.ExpectedRevision < 0 {
		httpapi.Fail(w, r, 400, "invalid_package", "规则包名称、身份或修订无效")
		return
	}
	if e := store.ValidateRules(input.Text); e != nil {
		httpapi.Fail(w, r, 400, "invalid_rules", e.Error())
		return
	}
	if _, e := control.RulePayload(control.RulePackage{PackageID: input.ID, Revision: input.ExpectedRevision + 1, EngineVersion: "8.0.7", Text: input.Text, SHA256: control.Digest([]byte(input.Text))}); e != nil {
		httpapi.Fail(w, r, 400, "package_too_large", e.Error())
		return
	}
	v, e := a.DB.SaveRulePackage(r.Context(), httpapi.Principal(r), input.ID, input.Name, input.Text, input.ExpectedRevision, httpapi.RequestID(r))
	if e != nil {
		operationError(w, r, e)
		return
	}
	httpapi.JSON(w, 201, v)
}
