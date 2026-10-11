package jobs

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/llm"
	"github.com/kkx600/StarBeacon/internal/rulegen"
	"github.com/kkx600/StarBeacon/internal/secrets"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/riverqueue/river"
)

type RuleGenerationWorker struct {
	river.WorkerDefaults[rulegen.Args]
	DB     *store.Postgres
	Vault  *secrets.Vault
	Client llm.Client
}

func (w *RuleGenerationWorker) Work(ctx context.Context, job *river.Job[rulegen.Args]) error {
	lease, err := w.DB.StartRuleGeneration(ctx, job.Args, job.ID, w.Vault)
	if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, store.ErrConflict) {
		return river.JobCancel(errors.New("规则生成作业不存在或执行资格已变化"))
	}
	if err != nil {
		return errors.New("规则生成作业读取失败")
	}
	if !lease.Execute {
		return nil
	}
	result := w.Client.GenerateJSON(ctx, lease.Config, rulegen.Instructions, lease.Prompt, lease.Config.MaxOutputTokens, "starbeacon_rule_candidates", rulegen.OutputSchema())
	candidates := []rulegen.Candidate{}
	if result.State == "succeeded" {
		candidates, err = rulegen.DecodeOutput(result.Text, lease.Job.Evidence, lease.Job.SIDs)
		if err == nil {
			for _, candidate := range candidates {
				if store.ValidateRules(candidate.Rule) != nil {
					err = rulegen.ErrOutput
					break
				}
			}
		}
		if err != nil {
			result.State, result.Code = "failed", "invalid_generation_output"
			candidates = []rulegen.Candidate{}
		} else {
			candidates = rulegen.BindCandidates(lease.Job.ID, candidates)
		}
	} else if result.Code == "request_cancelled" {
		result.State = "cancelled"
	}
	finish, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer stop()
	if err := w.DB.FinishRuleGeneration(finish, job.Args.TenantID, lease, result, candidates); err != nil {
		return errors.New("规则生成结果保存失败，不自动重复模型调用")
	}
	return nil
}
