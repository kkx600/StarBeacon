package jobs

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/llm"
	"github.com/kkx600/StarBeacon/internal/plugingen"
	"github.com/kkx600/StarBeacon/internal/secrets"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/riverqueue/river"
)

type PluginGenerationWorker struct {
	river.WorkerDefaults[plugingen.Args]
	DB     *store.Postgres
	Vault  *secrets.Vault
	Client llm.Client
}

func (w *PluginGenerationWorker) Work(ctx context.Context, job *river.Job[plugingen.Args]) error {
	lease, err := w.DB.StartPluginGeneration(ctx, job.Args, job.ID, w.Vault)
	if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, store.ErrConflict) {
		return river.JobCancel(errors.New("插件生成作业不存在或资格已变化"))
	}
	if err != nil {
		return errors.New("插件生成作业读取失败")
	}
	if lease.Token == "" {
		return nil
	}
	result := w.Client.GenerateJSON(ctx, lease.Config, plugingen.Instructions, lease.Prompt, lease.Config.MaxOutputTokens,
		"starbeacon_response_plugin_draft", plugingen.OutputSchema())
	var draft *plugingen.Candidate
	if result.State == "succeeded" {
		draft, err = plugingen.DecodeOutput(result.Text, lease.Request)
		switch {
		case errors.Is(err, plugingen.ErrInsufficient):
			result.State, result.Code = "failed", "insufficient_documentation"
		case err != nil:
			result.State, result.Code = "failed", "invalid_plugin_generation_output"
		}
	} else if result.Code == "request_cancelled" {
		result.State = "cancelled"
	}
	finish, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer stop()
	if err := w.DB.FinishPluginGeneration(finish, job.Args, lease, result, draft); err != nil {
		return errors.New("插件生成结果保存失败，原请求保留为待核对")
	}
	return nil
}
