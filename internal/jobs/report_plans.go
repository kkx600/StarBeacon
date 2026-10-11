package jobs

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/analytics"
	"github.com/kkx600/StarBeacon/internal/assistant"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/secrets"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/riverqueue/river"
)

type ReportSnapshot func(context.Context, model.Principal, analytics.Window) (analytics.Snapshot, error)

type ReportPlanWorker struct {
	river.WorkerDefaults[assistant.PlanArgs]
	DB       *store.Postgres
	Vault    *secrets.Vault
	Snapshot ReportSnapshot
}

func (w *ReportPlanWorker) Work(ctx context.Context, job *river.Job[assistant.PlanArgs]) error {
	queue := river.ClientFromContext[pgx.Tx](ctx)
	lease, err := w.DB.StartReportPlan(ctx, job.Args, job.ID, queue)
	if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, store.ErrConflict) || errors.Is(err, assistant.ErrInput) {
		return river.JobCancel(errors.New("报告计划执行资格已变化"))
	}
	if err != nil {
		return errors.New("报告计划读取失败")
	}
	if !lease.Execute {
		return nil
	}
	prepare := func() error {
		if w.Snapshot == nil {
			return errors.New("报告统计服务不可用")
		}
		work, cancel := context.WithTimeout(ctx, 25*time.Second)
		defer cancel()
		user := model.Principal{ID: lease.OwnerID, TenantID: lease.Args.TenantID, Role: "admin"}
		if err := w.DB.CheckReportPlanLease(work, lease); err != nil {
			return err
		}
		segments := []analytics.Snapshot{}
		for _, window := range assistant.Windows(lease.Request.Window) {
			value, err := w.Snapshot(work, user, window)
			if err != nil {
				return errors.New("报告统计未能完整返回")
			}
			segments = append(segments, value)
		}
		evidence, err := assistant.Freeze(lease.Request.Window, segments)
		if err != nil {
			return err
		}
		prompt := ""
		if lease.Request.ProviderID != "" {
			prompt, err = assistant.Prompt(evidence, lease.Request, nil)
			if err != nil {
				return err
			}
		}
		_, err = w.DB.CreateScheduledAnalysis(work, lease, evidence, prompt, queue, w.Vault)
		return err
	}
	err = prepare()
	if err == nil {
		return nil
	}
	terminal := errors.Is(err, pgx.ErrNoRows) || errors.Is(err, store.ErrConflict) || errors.Is(err, store.ErrModelQuota) || errors.Is(err, assistant.ErrInput) || errors.Is(err, secrets.ErrUnavailable)
	if terminal || job.Attempt >= job.MaxAttempts {
		code := "preparation_unavailable"
		if errors.Is(err, store.ErrModelQuota) {
			code = "model_quota_exceeded"
		} else if terminal {
			code = "plan_qualification_changed"
		}
		finish, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if err := w.DB.FailReportPlanRun(finish, lease, code, queue); err != nil {
			return errors.New("报告计划运行状态保存失败")
		}
		return river.JobCancel(errors.New("报告计划本周期未提交"))
	}
	// 此处仅重试统计准备；付费生成仍由独立一次性分析作业执行。
	return errors.New("报告统计准备失败")
}
