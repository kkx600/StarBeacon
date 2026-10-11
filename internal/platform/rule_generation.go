package platform

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/replay"
	"github.com/kkx600/StarBeacon/internal/rulegen"
	"github.com/kkx600/StarBeacon/internal/store"
)

func (a *API) registerRuleGeneration(m *http.ServeMux) {
	capacity := make(chan struct{}, 2)
	m.HandleFunc("POST /api/v1/rule-generation/jobs", a.Auth.Require(true, func(w http.ResponseWriter, r *http.Request) {
		select {
		case capacity <- struct{}{}:
			defer func() { <-capacity }()
			a.createRuleGeneration(w, r)
		default:
			httpapi.Fail(w, r, 429, "generation_capacity_exceeded", "规则材料准备正在处理其他请求，请稍后重试")
		}
	}))
	m.HandleFunc("GET /api/v1/rule-generation/jobs", a.Auth.Require(true, a.ruleGenerations))
	m.HandleFunc("GET /api/v1/rule-generation/jobs/{id}", a.Auth.Require(true, a.ruleGeneration))
	m.HandleFunc("POST /api/v1/rule-generation/jobs/{id}/cancel", a.Auth.Require(true, a.cancelRuleGeneration))
	m.HandleFunc("POST /api/v1/rule-generation/jobs/{id}/adopt", a.Auth.Require(true, a.adoptRuleCandidate))
}

func generationFailure(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, rulegen.ErrInput):
		httpapi.Fail(w, r, 400, "invalid_generation", "请核对规则说明、材料来源、样本摘要、模型修订、候选数量与本次数据使用许可")
	case errors.Is(err, rulegen.ErrOutput):
		httpapi.Fail(w, r, 400, "invalid_rule_candidate", "规则候选格式、SID 或材料引用不符合要求")
	case errors.Is(err, rulegen.ErrSID):
		httpapi.Fail(w, r, 409, "rule_sid_exhausted", "租户规则 SID 保留区已用尽，不能复用已有标识")
	case errors.Is(err, store.ErrRuleSIDConflict):
		httpapi.Fail(w, r, 409, "rule_sid_conflict", "SID 已由其他规则包占用，或生成候选尚不允许保存")
	case errors.Is(err, pgx.ErrNoRows):
		httpapi.Fail(w, r, 404, "not_found", "规则生成作业、模型或样本不存在、已过期或不可访问")
	case errors.Is(err, store.ErrConflict):
		httpapi.Fail(w, r, 409, "generation_conflict", "输入、模型修订、样本或执行资格已变化；相同请求键不能改变输入")
	default:
		modelFailure(w, r, err)
	}
}

func (a *API) generationData(w http.ResponseWriter, r *http.Request) bool {
	if a.DB == nil {
		httpapi.Fail(w, r, 503, "generation_unavailable", "规则生成数据服务暂不可用")
		return false
	}
	return true
}

func (a *API) createRuleGeneration(w http.ResponseWriter, r *http.Request) {
	var input rulegen.Request
	if httpapi.Decode(w, r, &input) != nil || input.Validate() != nil {
		generationFailure(w, r, rulegen.ErrInput)
		return
	}
	if !a.generationData(w, r) {
		return
	}
	u := httpapi.Principal(r)
	key := r.Header.Get("Idempotency-Key")
	prior, err := a.DB.ExistingRuleGeneration(r.Context(), u, key, rulegen.InputHash(input))
	if err == nil {
		httpapi.JSON(w, 200, prior)
		return
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		generationFailure(w, r, err)
		return
	}
	if a.Jobs == nil || a.Vault == nil || (a.JobsReady != nil && !a.JobsReady()) {
		httpapi.Fail(w, r, 503, "generation_unavailable", "模型执行服务或凭据密钥暂不可用，规则生成尚未提交")
		return
	}
	ctx, stop := context.WithTimeout(r.Context(), 12*time.Second)
	defer stop()
	evidence, err := rulegen.Seal(rulegen.Evidence{Packets: []replay.PacketSnippet{}})
	if input.Source != "natural_language" {
		if a.Samples == nil {
			httpapi.Fail(w, r, 503, "sample_storage_unavailable", "平台样本存储未配置，规则生成尚未提交")
			return
		}
		sample, readErr := a.DB.Sample(ctx, u.TenantID, input.SampleID)
		if readErr != nil {
			generationFailure(w, r, readErr)
			return
		}
		if sample.SHA256 != input.SampleSHA256 {
			generationFailure(w, r, store.ErrConflict)
			return
		}
		if (input.Source == "http_raw") != (sample.Origin != nil && sample.Origin.Synthetic) {
			generationFailure(w, r, rulegen.ErrInput)
			return
		}
		evidence, err = rulegen.Material(ctx, a.Samples, u.TenantID, sample)
		if err != nil {
			httpapi.Fail(w, r, 422, "generation_material_invalid", "样本对象读取、摘要核验或有界解析失败，模型尚未调用")
			return
		}
	}
	if err != nil {
		generationFailure(w, r, err)
		return
	}
	job, err := a.DB.CreateRuleGeneration(ctx, u, input, key, evidence, a.Jobs, a.Vault, httpapi.RequestID(r))
	if err != nil {
		generationFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 202, job)
}

func (a *API) ruleGeneration(w http.ResponseWriter, r *http.Request) {
	if !a.generationData(w, r) {
		return
	}
	job, err := a.DB.RuleGeneration(r.Context(), httpapi.Principal(r), r.PathValue("id"))
	if err != nil {
		generationFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, job)
}

func (a *API) ruleGenerations(w http.ResponseWriter, r *http.Request) {
	if !a.generationData(w, r) {
		return
	}
	page, err := a.DB.RuleGenerations(r.Context(), httpapi.Principal(r), r.URL.Query().Get("before"))
	if err != nil {
		generationFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, map[string]any{"items": page.Items, "next_cursor": page.Next, "model_execution_available": a.Jobs != nil && a.Vault != nil && (a.JobsReady == nil || a.JobsReady())})
}

func (a *API) cancelRuleGeneration(w http.ResponseWriter, r *http.Request) {
	var input struct{}
	if httpapi.Decode(w, r, &input) != nil {
		generationFailure(w, r, rulegen.ErrInput)
		return
	}
	if !a.generationData(w, r) {
		return
	}
	job, err := a.DB.CancelRuleGeneration(r.Context(), httpapi.Principal(r), r.PathValue("id"), a.Jobs, httpapi.RequestID(r))
	if err != nil {
		generationFailure(w, r, err)
		return
	}
	httpapi.JSON(w, 200, job)
}

func (a *API) adoptRuleCandidate(w http.ResponseWriter, r *http.Request) {
	var input struct {
		SID uint32 `json:"sid"`
	}
	if httpapi.Decode(w, r, &input) != nil || input.SID < rulegen.MinSID || input.SID > rulegen.MaxSID {
		generationFailure(w, r, rulegen.ErrInput)
		return
	}
	if !a.generationData(w, r) {
		return
	}
	u := httpapi.Principal(r)
	job, err := a.DB.RuleGeneration(r.Context(), u, r.PathValue("id"))
	if err != nil {
		generationFailure(w, r, err)
		return
	}
	if job.State != "succeeded" {
		generationFailure(w, r, store.ErrConflict)
		return
	}
	for _, candidate := range job.Candidates {
		if candidate.SID != input.SID {
			continue
		}
		read := func() (store.RulePackage, error) {
			pkg, err := a.DB.RulePackage(r.Context(), u.TenantID, candidate.PackageID, 1)
			if err == nil && (pkg.SHA256 != candidate.SHA256 || pkg.GenerationID == nil || *pkg.GenerationID != job.ID || pkg.GenerationSID == nil || *pkg.GenerationSID != input.SID) {
				err = store.ErrConflict
			}
			return pkg, err
		}
		pkg, err := read()
		if errors.Is(err, pgx.ErrNoRows) {
			pkg, err = a.DB.SaveRulePackage(r.Context(), u, candidate.PackageID, candidate.Title, candidate.Rule, 0, httpapi.RequestID(r))
			if errors.Is(err, store.ErrConflict) {
				pkg, err = read()
			}
		}
		if err != nil {
			generationFailure(w, r, err)
			return
		}
		httpapi.JSON(w, 200, pkg)
		return
	}
	generationFailure(w, r, pgx.ErrNoRows)
}
