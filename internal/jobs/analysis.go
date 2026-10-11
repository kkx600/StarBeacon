// Package jobs 使用 River 社区核心库调度持久业务作业；队列参数不携带证据或凭据。
package jobs

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/assistant"
	"github.com/kkx600/StarBeacon/internal/llm"
	"github.com/kkx600/StarBeacon/internal/outbound"
	"github.com/kkx600/StarBeacon/internal/secrets"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
)

type AnalysisWorker struct {
	river.WorkerDefaults[assistant.Args]
	DB     *store.Postgres
	Vault  *secrets.Vault
	Client llm.Client
}

func (w *AnalysisWorker) Work(ctx context.Context, job *river.Job[assistant.Args]) error {
	lease, err := w.DB.StartAnalysis(ctx, job.Args, job.ID, w.Vault)
	if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, store.ErrConflict) {
		return river.JobCancel(errors.New("分析作业不存在或执行资格已变化"))
	}
	if err != nil {
		return errors.New("分析作业读取失败")
	}
	if !lease.Execute {
		return nil
	}
	result := w.Client.Generate(ctx, lease.Config, assistant.Instructions, lease.Prompt, lease.Config.MaxOutputTokens)
	var answer *assistant.Answer
	if result.State == "succeeded" {
		value, err := assistant.DecodeAnswer(result.Text, lease.Job.Evidence)
		if err != nil {
			result.State, result.Code = "failed", "invalid_analysis_output"
		} else {
			answer = &value
		}
	} else if result.Code == "request_cancelled" {
		result.State = "cancelled"
	}
	// 取消已发送的请求无法证明供应商没有执行；仍保留未知状态与实际用量。
	finish, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer stop()
	if err := w.DB.FinishAnalysis(finish, job.Args.TenantID, lease, result, answer); err != nil {
		return errors.New("分析作业结果保存失败，不自动重复模型调用")
	}
	return nil
}

func NewAnalysis(db *store.Postgres, vault *secrets.Vault, policy outbound.Policy, snapshots ...ReportSnapshot) (*river.Client[pgx.Tx], error) {
	return NewAnalysisWithTriage(db, vault, policy, nil, snapshots...)
}

func NewAnalysisWithTriage(db *store.Postgres, vault *secrets.Vault, policy outbound.Policy, source TriageSource, snapshots ...ReportSnapshot) (*river.Client[pgx.Tx], error) {
	workers := river.NewWorkers()
	river.AddWorker(workers, &AnalysisWorker{DB: db, Vault: vault, Client: llm.Client{Policy: policy}})
	var snapshot ReportSnapshot
	if len(snapshots) > 0 {
		snapshot = snapshots[0]
	}
	river.AddWorker(workers, &ReportPlanWorker{DB: db, Vault: vault, Snapshot: snapshot})
	river.AddWorker(workers, &RuleGenerationWorker{DB: db, Vault: vault, Client: llm.Client{Policy: policy}})
	river.AddWorker(workers, &AlertTriageWorker{DB: db, Vault: vault, Client: llm.Client{Policy: policy}, Source: source})
	return river.NewClient(riverpgxv5.New(db.Pool), &river.Config{
		Schema: assistant.QueueSchema, Workers: workers,
		Queues:      map[string]river.QueueConfig{"assistant": {MaxWorkers: 3}, "reports": {MaxWorkers: 1}, "report_plans": {MaxWorkers: 1}, "rule_generation": {MaxWorkers: 1}, "alert_triage": {MaxWorkers: 1}},
		MaxAttempts: 1, JobTimeout: 140 * time.Second, RescueStuckJobsAfter: 3 * time.Minute, SoftStopTimeout: 5 * time.Second,
		// 运行账号不持有 REINDEX 权限；索引维护由受控运维命令承担。
		ReindexerIndexNames:         []string{},
		CompletedJobRetentionPeriod: 180 * 24 * time.Hour, CancelledJobRetentionPeriod: 180 * 24 * time.Hour, DiscardedJobRetentionPeriod: 180 * 24 * time.Hour,
	})
}
