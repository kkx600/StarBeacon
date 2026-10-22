package platform

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/correlation"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/searchfilter"
	"github.com/kkx600/StarBeacon/internal/searchsnapshot"
	"github.com/kkx600/StarBeacon/internal/store"
)

func (a *API) registerCorrelation(m *http.ServeMux) {
	m.HandleFunc("GET /api/v1/correlation-rules", a.Auth.Require(false, a.correlationRules))
	m.HandleFunc("POST /api/v1/correlation-rules", a.Auth.Require(true, a.saveCorrelationRule))
	m.HandleFunc("GET /api/v1/correlation-rules/{id}/revisions/{revision}", a.Auth.Require(false, a.correlationRule))
	m.HandleFunc("POST /api/v1/correlation-rules/{id}/backtest", a.Auth.Require(true, a.backtestCorrelation))
}

func decodeCorrelation(w http.ResponseWriter, r *http.Request, target any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 32768)
	var raw json.RawMessage
	if httpapi.Decode(w, r, &raw) != nil || contract.JSONFields(string(raw), []string{"id", "expected_revision", "name", "description", "active", "definition", "schema_version", "dataset", "filter", "group_by", "metric", "distinct_field", "window_seconds", "threshold", "start", "end"}, 32768) != nil {
		return correlation.ErrInput
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		return correlation.ErrInput
	}
	return nil
}

func correlationFailure(w http.ResponseWriter, r *http.Request, err error) {
	var syntax *searchfilter.Error
	if errors.As(err, &syntax) {
		httpapi.JSON(w, 400, map[string]any{"code": "invalid_correlation_filter", "message": syntax.Error(), "line": syntax.Line, "column": syntax.Column, "request_id": httpapi.RequestID(r)})
		return
	}
	switch {
	case errors.Is(err, correlation.ErrInput):
		httpapi.Fail(w, r, 400, "invalid_correlation", "请核对规则字段、过滤语法、修订及不超过一小时的回测范围")
	case errors.Is(err, correlation.ErrPermission):
		httpapi.Fail(w, r, 403, "correlation_forbidden", "当前账号的关联规则权限已变化，请重新登录并核对权限")
	case errors.Is(err, model.ErrUnauthenticated):
		httpapi.Fail(w, r, 401, "session_expired", "会话或权限已变化，回测结果未交付")
	case errors.Is(err, correlation.ErrQuota):
		httpapi.Fail(w, r, 429, "correlation_rule_quota", "关联规则或最近 24 小时变更数量已达上限")
	case errors.Is(err, correlation.ErrLimit), errors.Is(err, searchsnapshot.ErrLimit):
		httpapi.Fail(w, r, 413, "correlation_limit", "规则、窗口分组或证据数量超过上限，请缩小回测范围或增加筛选条件")
	case errors.Is(err, store.ErrConflict):
		httpapi.Fail(w, r, 409, "correlation_conflict", "规则已停用、修订或原提交输入已变化，请刷新后核对")
	case errors.Is(err, pgx.ErrNoRows):
		httpapi.Fail(w, r, 404, "not_found", "关联规则修订不存在、已到期或不可访问")
	case errors.Is(err, errExportBusy):
		w.Header().Set("Retry-After", "5")
		httpapi.Fail(w, r, 429, "correlation_busy", "当前检索任务正在使用回测配额，请稍后重试")
	default:
		httpapi.Fail(w, r, 503, "correlation_unavailable", "关联回测服务暂不可用或来源未完整返回，未生成部分结果")
	}
}

func (a *API) correlationReady(w http.ResponseWriter, r *http.Request) bool {
	if a.DB != nil {
		return true
	}
	correlationFailure(w, r, errors.New("关联规则存储不可用"))
	return false
}

func (a *API) correlationRules(w http.ResponseWriter, r *http.Request) {
	q := correlation.Query{Limit: 20}
	for k, values := range r.URL.Query() {
		if len(values) != 1 {
			correlationFailure(w, r, correlation.ErrInput)
			return
		}
		switch k {
		case "cursor":
			q.Cursor = values[0]
		case "keyword":
			q.Keyword = values[0]
		case "active":
			q.Active = values[0]
		case "limit":
			n, err := strconv.Atoi(values[0])
			if err != nil || strconv.Itoa(n) != values[0] {
				correlationFailure(w, r, correlation.ErrInput)
				return
			}
			q.Limit = n
		default:
			correlationFailure(w, r, correlation.ErrInput)
			return
		}
	}
	if _, err := q.Position(httpapi.Principal(r).TenantID); err != nil {
		correlationFailure(w, r, err)
		return
	}
	if !a.correlationReady(w, r) {
		return
	}
	page, err := a.DB.CorrelationRules(r.Context(), httpapi.Principal(r), q)
	if err != nil {
		correlationFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, page)
}

func (a *API) correlationRule(w http.ResponseWriter, r *http.Request) {
	revision, err := strconv.ParseInt(r.PathValue("revision"), 10, 64)
	if err != nil || strconv.FormatInt(revision, 10) != r.PathValue("revision") || revision < 1 || revision > correlation.MaxRevision || !contract.ValidID(r.PathValue("id")) || r.URL.RawQuery != "" {
		correlationFailure(w, r, correlation.ErrInput)
		return
	}
	if !a.correlationReady(w, r) {
		return
	}
	item, err := a.DB.CorrelationRule(r.Context(), httpapi.Principal(r), r.PathValue("id"), revision)
	if err != nil {
		correlationFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, item)
}

func (a *API) saveCorrelationRule(w http.ResponseWriter, r *http.Request) {
	var input correlation.Change
	if r.URL.RawQuery != "" || !contract.ValidID(r.Header.Get("Idempotency-Key")) || decodeCorrelation(w, r, &input) != nil {
		correlationFailure(w, r, correlation.ErrInput)
		return
	}
	if err := input.Validate(); err != nil {
		correlationFailure(w, r, err)
		return
	}
	if !a.correlationReady(w, r) {
		return
	}
	item, err := a.DB.SaveCorrelationRule(r.Context(), httpapi.Principal(r), r.Header.Get("Idempotency-Key"), input)
	if err != nil {
		correlationFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, item)
}

func (a *API) backtestCorrelation(w http.ResponseWriter, r *http.Request) {
	var input correlation.Request
	id := r.PathValue("id")
	if !contract.ValidID(id) || r.URL.RawQuery != "" || decodeCorrelation(w, r, &input) != nil || input.Validate(time.Now()) != nil {
		correlationFailure(w, r, correlation.ErrInput)
		return
	}
	if !a.correlationReady(w, r) {
		return
	}
	if a.ES == nil {
		correlationFailure(w, r, errors.New("关联回测来源未配置"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 50*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	u := httpapi.Principal(r)
	rule, err := a.DB.CurrentCorrelationRule(ctx, u, id, input.ExpectedRevision)
	if err != nil {
		correlationFailure(w, r, err)
		return
	}
	release, err := a.exportSlot(ctx, u.TenantID)
	if err != nil {
		correlationFailure(w, r, err)
		return
	}
	defer release()
	cookie, err := r.Cookie(a.Auth.CookieName)
	if err != nil {
		correlationFailure(w, r, model.ErrUnauthenticated)
		return
	}
	authorize := func(ctx context.Context) error {
		current, err := a.Auth.Store.Session(ctx, cookie.Value)
		if err != nil {
			return model.ErrUnauthenticated
		}
		if current.ID != u.ID || current.TenantID != u.TenantID || current.Role != u.Role || current.CredentialRevision != u.CredentialRevision || current.CSRF != u.CSRF {
			return model.ErrUnauthenticated
		}
		now, err := a.DB.CurrentCorrelationRule(ctx, u, id, input.ExpectedRevision)
		if err != nil {
			return err
		}
		if now.DefinitionSHA256 != rule.DefinitionSHA256 {
			return store.ErrConflict
		}
		return nil
	}
	q := model.TrafficSearchRequest{SearchRequest: model.SearchRequest{Start: input.Start, End: input.End, Filter: rule.Definition.Filter}}
	facts, err := a.ES.SnapshotEvents(ctx, u.TenantID, "alerts", q, correlation.MaxFacts, authorize)
	if err != nil {
		correlationFailure(w, r, err)
		return
	}
	result, err := correlation.Evaluate(rule, input, facts, time.Now())
	if err == nil {
		err = authorize(ctx)
	}
	if err == nil {
		err = a.DB.RecordCorrelationBacktest(ctx, u, id, input.ExpectedRevision, httpapi.RequestID(r))
	}
	if err == nil {
		err = authorize(ctx)
	}
	if err != nil {
		correlationFailure(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	httpapi.JSON(w, 200, result)
}
