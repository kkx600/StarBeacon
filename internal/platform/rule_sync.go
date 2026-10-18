package platform

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"net/http"

	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/rulesync"
)

func (a *API) registerRuleSync(m *http.ServeMux) {
	m.HandleFunc("GET /api/v1/rule-sync-plans", a.Auth.Require(true, a.ruleSyncPlans))
	m.HandleFunc("POST /api/v1/rule-sync-plans", a.Auth.Require(true, a.saveRuleSyncPlan))
}

func ruleSyncFailure(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, rulesync.ErrInput):
		httpapi.Fail(w, r, 400, "invalid_rule_sync", err.Error())
	case errors.Is(err, rulesync.ErrQuota):
		httpapi.Fail(w, r, 429, "rule_sync_quota_exceeded", err.Error())
	default:
		operationError(w, r, err)
	}
}

func (a *API) ruleSyncPlans(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if len(q) > 1 || len(q["cursor"]) > 1 || len(q) == 1 && !q.Has("cursor") {
		ruleSyncFailure(w, r, rulesync.ErrInput)
		return
	}
	if a.DB == nil {
		httpapi.Fail(w, r, 503, "rule_sync_unavailable", "规则同步数据服务暂不可用")
		return
	}
	page, err := a.DB.RuleSyncPlans(r.Context(), httpapi.Principal(r), q.Get("cursor"))
	if err != nil {
		ruleSyncFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, page)
}

func (a *API) saveRuleSyncPlan(w http.ResponseWriter, r *http.Request) {
	var input rulesync.Change
	var raw bytes.Buffer
	r.Body = io.NopCloser(io.TeeReader(r.Body, &raw))
	if httpapi.Decode(w, r, &input) != nil || contract.JSONFields(raw.String(), []string{"id", "expected_revision", "spec", "name", "enabled", "sensor_id", "registration_id", "package_id", "package_revision", "positive_sample_id", "negative_sample_id", "interval_seconds"}, 8192) != nil || input.Validate() != nil {
		ruleSyncFailure(w, r, rulesync.ErrInput)
		return
	}
	if r.URL.RawQuery != "" {
		ruleSyncFailure(w, r, rulesync.ErrInput)
		return
	}
	if a.DB == nil || (input.Spec.Enabled && (len(a.Signer) != ed25519.PrivateKeySize || a.Samples == nil)) {
		httpapi.Fail(w, r, 503, "rule_sync_unavailable", "规则同步执行服务暂不可用，可保存停用计划")
		return
	}
	item, err := a.DB.SaveRuleSyncPlan(r.Context(), httpapi.Principal(r), input, httpapi.RequestID(r))
	if err != nil {
		ruleSyncFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, item)
}

func (a *API) SweepRuleSync(ctx context.Context, after string) (string, int, error) {
	if a.DB == nil || len(a.Signer) != ed25519.PrivateKeySize || a.Samples == nil {
		return after, 0, nil
	}
	tenants, err := a.DB.NotificationTenants(ctx, after)
	if err != nil {
		return after, 0, err
	}
	if len(tenants) == 0 {
		return "", 0, nil
	}
	count := 0
	var failures error
	for _, tenant := range tenants[:min(8, len(tenants))] {
		if ctx.Err() != nil {
			return after, count, errors.Join(failures, ctx.Err())
		}
		n, err := a.DB.SweepRuleRollouts(ctx, tenant)
		count += n
		failures = errors.Join(failures, err)
		n, err = a.DB.SweepRuleSync(ctx, tenant, a.Signer)
		count += n
		failures = errors.Join(failures, err)
		after = tenant
	}
	return after, count, failures
}
