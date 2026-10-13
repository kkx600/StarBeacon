package platform

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/decision"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/triage"
)

func (a *API) automaticTriages(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	for key := range query {
		if key != "before" {
			decisionFailure(w, r, decision.ErrInput)
			return
		}
	}
	revision, err := strconv.ParseInt(r.PathValue("revision"), 10, 64)
	if err != nil || strconv.FormatInt(revision, 10) != r.PathValue("revision") || revision < 1 || revision > decision.MaxRevision || !contract.ValidID(r.PathValue("id")) || query.Get("before") != "" && !contract.ValidID(query.Get("before")) || len(query) > 1 || query.Has("before") && len(query["before"]) != 1 {
		decisionFailure(w, r, decision.ErrInput)
		return
	}
	if !a.decisionReady(w, r) {
		return
	}
	page, err := a.DB.AutomaticTriages(r.Context(), httpapi.Principal(r), r.PathValue("id"), revision, query.Get("before"))
	if err != nil {
		decisionFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, page)
}

func (a *API) continuousDecision(w http.ResponseWriter, r *http.Request) {
	if !contract.ValidID(r.PathValue("id")) || r.URL.RawQuery != "" {
		decisionFailure(w, r, decision.ErrInput)
		return
	}
	if !a.decisionReady(w, r) {
		return
	}
	item, err := a.DB.ContinuousDecision(r.Context(), httpapi.Principal(r), r.PathValue("id"))
	if err != nil {
		decisionFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, map[string]any{"item": item})
}

// 每轮最多八个租户、每租户十六项；游标只越过已访问的租户，数据库幂等允许多实例安全重查。
func (a *API) SweepContinuousDecisions(ctx context.Context, after string) (string, int, error) {
	if a.DB == nil {
		return after, 0, errors.New("持续决策存储未就绪")
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
		submitted, err := a.SweepAutomaticTriages(ctx, tenant)
		count += submitted
		failures = errors.Join(failures, err)
		candidates, err := a.DB.ContinuousDecisionCandidates(ctx, tenant)
		if err != nil {
			failures = errors.Join(failures, err)
			after = tenant
			continue
		}
		for _, c := range candidates {
			if ctx.Err() != nil {
				return after, count, errors.Join(failures, ctx.Err())
			}
			if err := a.processContinuousDecision(ctx, c); err != nil {
				if !errors.Is(err, store.ErrConflict) && !errors.Is(err, decision.ErrPermission) && !errors.Is(err, pgx.ErrNoRows) {
					failures = errors.Join(failures, err)
				}
			} else {
				count++
			}
		}
		after = tenant
	}
	return after, count, failures
}

// 模型队列与凭据未就绪时不提交；ES 刷新宽限只延迟核对，不授权未核验的材料。
func (a *API) SweepAutomaticTriages(ctx context.Context, tenant string) (int, error) {
	if a.DB == nil {
		return 0, nil
	}
	inputs, err := a.DB.AutomaticTriageCandidates(ctx, tenant)
	if err != nil {
		return 0, err
	}
	if a.Jobs == nil || a.Vault == nil || a.ES == nil || a.JobsReady != nil && !a.JobsReady() {
		return 0, nil
	}
	count := 0
	var failures error
	for _, c := range inputs {
		alert, err := a.ES.ReadAlertEvidence(ctx, tenant, c.EventID, c.RawSHA256)
		if errors.Is(err, pgx.ErrNoRows) && time.Since(c.CreatedAt) < 30*time.Second {
			continue
		}
		if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, store.ErrAlertIdentity) {
			failures = errors.Join(failures, a.DB.SkipAutomaticTriage(ctx, c, "evidence_changed"))
			continue
		}
		if err != nil {
			failures = errors.Join(failures, err)
			continue
		}
		evidence, err := triage.Freeze(alert)
		if err != nil || evidence.SHA256 != c.EvidenceSHA256 {
			failures = errors.Join(failures, a.DB.SkipAutomaticTriage(ctx, c, "evidence_changed"))
			continue
		}
		_, err = a.DB.CreateAutomaticAlertTriage(ctx, c, evidence, a.Jobs, a.Vault)
		if errors.Is(err, store.ErrModelQuota) {
			failures = errors.Join(failures, a.DB.SkipAutomaticTriage(ctx, c, "model_quota"))
		} else if err == nil {
			count++
		} else if !errors.Is(err, store.ErrConflict) && !errors.Is(err, decision.ErrPermission) && !errors.Is(err, pgx.ErrNoRows) {
			failures = errors.Join(failures, err)
		}
	}
	return count, failures
}

func (a *API) processContinuousDecision(ctx context.Context, c store.DecisionCandidate) error {
	e, err := a.DB.CreateDecisionEvaluation(ctx, c.Principal, c.Key(), decision.EvaluationRequest{PolicyID: c.Policy.ID, ExpectedRevision: c.Policy.Revision, TriageID: c.TriageID})
	if err != nil {
		return err
	}
	var evidence triage.Evidence
	if c.Policy.Definition.Mode == "automatic" && e.Result.Status == "matched" {
		if a.ES == nil {
			return errors.New("持续决策告警核验服务未就绪")
		}
		alert, err := a.ES.ReadAlertEvidence(ctx, c.Principal.TenantID, e.Result.EventID, e.Result.RawSHA256)
		if err == nil {
			evidence, err = triage.Freeze(alert)
		}
		// 身份消失或不一致是确定性拒绝；依赖故障保留待核对状态，不能推定为允许执行。
		if err != nil && !errors.Is(err, store.ErrAlertIdentity) && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
	}
	r, err := a.DB.CompleteContinuousDecision(ctx, c, e.ID, evidence, a.Signer)
	if err == nil && r.TaskID != "" && a.Wakeup != nil {
		a.Wakeup.Notify(c.Principal.TenantID, r.Config.Automatic.SensorID)
	}
	return err
}
