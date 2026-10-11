package jobs

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/llm"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/secrets"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/triage"
	"github.com/riverqueue/river"
)

type TriageSource interface {
	ReadAlertEvidence(context.Context, string, string, string) (model.Alert, error)
}

type AlertTriageWorker struct {
	river.WorkerDefaults[triage.Args]
	DB     *store.Postgres
	Vault  *secrets.Vault
	Client llm.Client
	Source TriageSource
}

func (w *AlertTriageWorker) Work(ctx context.Context, job *river.Job[triage.Args]) error {
	lease, err := w.DB.StartAlertTriage(ctx, job.Args, job.ID, w.Vault)
	if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, store.ErrConflict) {
		return river.JobCancel(errors.New("模型研判作业不存在或执行资格已变化"))
	}
	if err != nil {
		return errors.New("模型研判作业读取失败")
	}
	if !lease.Execute {
		return nil
	}
	result := llm.Result{State: "failed", Code: "alert_source_unavailable"}
	var answer *triage.Answer
	if w.Source != nil {
		check, stop := context.WithTimeout(ctx, 5*time.Second)
		alert, err := w.Source.ReadAlertEvidence(check, job.Args.TenantID, lease.Job.Request.EventID, lease.Job.Request.RawSHA256)
		stop()
		current, freezeErr := triage.Freeze(alert)
		// 排队期间原始告警过期、摘要或白名单事实变化时，不能继续发送冻结材料。
		if err == nil && freezeErr == nil && current.SHA256 == lease.Job.Evidence.SHA256 {
			result = w.Client.GenerateJSON(ctx, lease.Config, triage.Instructions, lease.Prompt, lease.Config.MaxOutputTokens, "starbeacon_alert_triage", triage.OutputSchema())
			if result.State == "succeeded" {
				decoded, err := triage.DecodeAnswer(result.Text, lease.Job.Evidence)
				if err != nil {
					result.State, result.Code = "failed", "invalid_triage_output"
				} else {
					answer = &decoded
				}
			} else if result.Code == "request_cancelled" {
				result.State = "cancelled"
			}
		}
	}
	if result.Code == "alert_source_unavailable" && ctx.Err() != nil {
		result.State, result.Code = "cancelled", "request_cancelled"
	}
	finish, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer stop()
	if err := w.DB.FinishAlertTriage(finish, job.Args.TenantID, lease, result, answer); err != nil {
		return errors.New("模型研判结果保存失败，不自动重复模型调用")
	}
	return nil
}
