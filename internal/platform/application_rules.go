package platform

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/application"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/store"
)

func (a *API) registerApplicationRules(m *http.ServeMux) {
	m.HandleFunc("GET /api/v1/application-rules", a.Auth.Require(false, a.applicationRules))
	m.HandleFunc("GET /api/v1/application-rules/snapshot", a.Auth.Require(false, a.applicationSnapshot))
	m.HandleFunc("POST /api/v1/sensors/{id}/application-rules", a.Auth.Require(true, a.deployApplicationRules))
	m.HandleFunc("GET /api/v1/application-rules/{id}/revisions/{revision}", a.Auth.Require(false, a.applicationRule))
	m.HandleFunc("POST /api/v1/application-rules", a.Auth.Require(true, a.saveApplicationRule))
	m.HandleFunc("POST /api/v1/application-rules/preview", a.Auth.Require(false, a.previewApplicationRule))
	m.HandleFunc("POST /api/v1/application-rules/test", a.Auth.Require(false, a.testApplicationRules))
}

// 严格拒绝重复键、大小写别名、跨层未声明字段和多余 JSON，避免验证与保存解释不一致。
func decodeApplication(w http.ResponseWriter, r *http.Request, target any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 32768)
	var raw json.RawMessage
	if err := httpapi.Decode(w, r, &raw); err != nil {
		return application.ErrInput
	}
	fields := []string{"id", "expected_revision", "name", "description", "active", "definition", "observation", "schema_version", "product_id", "product_name", "category_id", "protocols", "any", "all", "exclude", "field", "op", "value", "protocol", "http_host", "http_method", "http_path", "http_user_agent", "tls_sni", "tls_alpn", "dns_names", "expected_registration_id", "expected_state_sha256", "rules_sha256"}
	if contract.JSONFields(string(raw), fields, 32768) != nil {
		return application.ErrInput
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		return application.ErrInput
	}
	return nil
}

func applicationFailure(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, store.ErrApplicationState):
		httpapi.Fail(w, r, 409, "application_state_conflict", "探针不在线、信任信息或规则状态已变化，请刷新并核对后提交")
	case errors.Is(err, application.ErrInput):
		httpapi.Fail(w, r, 400, "invalid_application_rule", "请核对规则、材料字段、协议范围与修订；正向候选须包含实际可见的产品域名条件")
	case errors.Is(err, application.ErrQuota):
		httpapi.Fail(w, r, 429, "application_rule_quota", "应用识别规则或最近 24 小时变更数量已达上限")
	case errors.Is(err, application.ErrPermission):
		httpapi.Fail(w, r, 403, "application_rule_forbidden", "当前账号不再具有应用识别规则操作权限，请重新登录并核对权限")
	case errors.Is(err, store.ErrConflict):
		httpapi.Fail(w, r, 409, "application_rule_conflict", "规则修订或原提交输入已变化，请刷新后核对；不会覆盖其他提交")
	case errors.Is(err, pgx.ErrNoRows):
		httpapi.Fail(w, r, 404, "not_found", "应用识别规则修订不存在、已到期或不可访问")
	default:
		httpapi.Fail(w, r, 503, "application_rule_unavailable", "应用识别规则服务暂不可用；提交结果未确认时请核对原提交")
	}
}

func (a *API) applicationSnapshot(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		applicationFailure(w, r, application.ErrInput)
		return
	}
	if !a.applicationReady(w, r) {
		return
	}
	snapshot, err := a.DB.ApplicationSnapshot(r.Context(), httpapi.Principal(r))
	if err != nil {
		applicationFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, snapshot)
}

func (a *API) deployApplicationRules(w http.ResponseWriter, r *http.Request) {
	var input application.DeploymentInput
	if !contract.ValidID(r.PathValue("id")) || !contract.ValidID(r.Header.Get("Idempotency-Key")) || r.URL.RawQuery != "" || decodeApplication(w, r, &input) != nil || input.Validate() != nil {
		applicationFailure(w, r, application.ErrInput)
		return
	}
	if len(a.Signer) != ed25519.PrivateKeySize {
		httpapi.Fail(w, r, 503, "signer_unavailable", "平台任务签名密钥未配置")
		return
	}
	if !a.applicationReady(w, r) {
		return
	}
	id, err := a.DB.CreateApplicationDeployment(r.Context(), httpapi.Principal(r), r.PathValue("id"), r.Header.Get("Idempotency-Key"), input, a.Signer)
	if err != nil {
		applicationFailure(w, r, err)
		return
	}
	a.Wakeup.Notify(httpapi.Principal(r).TenantID, r.PathValue("id"))
	httpapi.JSON(w, 202, map[string]string{"id": id})
}

func (a *API) applicationReady(w http.ResponseWriter, r *http.Request) bool {
	if a.DB != nil {
		return true
	}
	applicationFailure(w, r, errors.New("应用识别规则存储不可用"))
	return false
}

func applicationListQuery(r *http.Request) (application.ListQuery, error) {
	q := application.ListQuery{Limit: 20}
	for key, values := range r.URL.Query() {
		if len(values) != 1 {
			return q, application.ErrInput
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
				return q, application.ErrInput
			}
		default:
			return q, application.ErrInput
		}
	}
	return q, q.Validate()
}

func (a *API) applicationRules(w http.ResponseWriter, r *http.Request) {
	q, err := applicationListQuery(r)
	if err != nil {
		applicationFailure(w, r, err)
		return
	}
	if !a.applicationReady(w, r) {
		return
	}
	result, err := a.DB.ApplicationRules(r.Context(), httpapi.Principal(r), q)
	if err != nil {
		applicationFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, result)
}

func (a *API) applicationRule(w http.ResponseWriter, r *http.Request) {
	revision, err := strconv.ParseInt(r.PathValue("revision"), 10, 64)
	if err != nil || strconv.FormatInt(revision, 10) != r.PathValue("revision") || revision < 1 || revision > application.MaxRevision || len(r.URL.Query()) > 0 {
		applicationFailure(w, r, application.ErrInput)
		return
	}
	if !a.applicationReady(w, r) {
		return
	}
	result, err := a.DB.ApplicationRule(r.Context(), httpapi.Principal(r), r.PathValue("id"), revision)
	if err != nil {
		applicationFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, result)
}

func (a *API) saveApplicationRule(w http.ResponseWriter, r *http.Request) {
	var c application.Change
	if decodeApplication(w, r, &c) != nil || c.Validate() != nil || !contract.ValidID(r.Header.Get("Idempotency-Key")) || len(r.URL.Query()) > 0 {
		applicationFailure(w, r, application.ErrInput)
		return
	}
	if !a.applicationReady(w, r) {
		return
	}
	result, err := a.DB.SaveApplicationRule(r.Context(), httpapi.Principal(r), r.Header.Get("Idempotency-Key"), c)
	if err != nil {
		applicationFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, result)
}

func (a *API) previewApplicationRule(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Definition  application.Definition  `json:"definition"`
		Observation application.Observation `json:"observation"`
	}
	if decodeApplication(w, r, &input) != nil || input.Definition.Validate() != nil || input.Observation.Validate() != nil || len(r.URL.Query()) > 0 {
		applicationFailure(w, r, application.ErrInput)
		return
	}
	if !a.applicationReady(w, r) {
		return
	}
	result, err := a.DB.TestApplicationRules(r.Context(), httpapi.Principal(r), input.Observation, &input.Definition)
	if err != nil {
		applicationFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, result)
}

func (a *API) testApplicationRules(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Observation application.Observation `json:"observation"`
	}
	if decodeApplication(w, r, &input) != nil || input.Observation.Validate() != nil || len(r.URL.Query()) > 0 {
		applicationFailure(w, r, application.ErrInput)
		return
	}
	if !a.applicationReady(w, r) {
		return
	}
	result, err := a.DB.TestApplicationRules(r.Context(), httpapi.Principal(r), input.Observation, nil)
	if err != nil {
		applicationFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, result)
}
