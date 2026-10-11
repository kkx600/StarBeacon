package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/assistant"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/secrets"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
)

var ErrPlanQuota = errors.New("报告计划数量已达到上限")

const planJSON = `jsonb_build_object('id',id,'revision',revision,'spec',spec,'next_at',next_at,'updated_at',updated_at)`
const planRunJSON = `jsonb_build_object('id',h.id,'plan_revision',h.plan_revision,'due_at',h.due_at,'effective_at',h.effective_at,'skipped_from',h.skipped_from,'skipped_until',h.skipped_until,'request',h.request,'state',h.state,'code',h.code,'analysis_id',COALESCE(h.analysis_id,''),'analysis_state',COALESCE(j.state,''),'created_at',h.created_at,'finished_at',h.finished_at,'expires_at',h.expires_at)`

func scanPlan(row pgx.Row) (assistant.Plan, error) {
	var plan assistant.Plan
	var raw []byte
	if err := row.Scan(&raw); err != nil {
		return plan, err
	}
	err := json.Unmarshal(raw, &plan)
	return plan, err
}

func activePlanOwner(ctx context.Context, tx pgx.Tx, tenant, owner string) error {
	var id string
	// 受限数据库函数只锁定当前事务租户的管理员资格，不授予在线账号用户表写权限。
	return tx.QueryRow(ctx, `SELECT public.lock_report_plan_owner($1) WHERE current_setting('starbeacon.tenant_id',true)=$2`, owner, tenant).Scan(&id)
}

func queuePlan(ctx context.Context, tx pgx.Tx, queue *river.Client[pgx.Tx], args assistant.PlanArgs) (int64, error) {
	if queue == nil || queue.Schema() != assistant.QueueSchema || args.Validate() != nil {
		return 0, assistant.ErrInput
	}
	result, err := queue.InsertTx(ctx, tx, args, &river.InsertOpts{Queue: "report_plans", MaxAttempts: 5, ScheduledAt: args.DueAt})
	if err != nil {
		return 0, err
	}
	return result.Job.ID, nil
}

func (p *Postgres) ReportPlans(ctx context.Context, user model.Principal) ([]assistant.Plan, error) {
	items := []assistant.Plan{}
	err := p.TenantTx(ctx, user.TenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+planJSON+` FROM report_plans WHERE tenant_id=$1 AND created_by=$2 ORDER BY updated_at DESC,id DESC LIMIT 32`, user.TenantID, user.ID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			item, err := scanPlan(rows)
			if err != nil {
				return err
			}
			items = append(items, item)
		}
		return rows.Err()
	})
	return items, err
}

// CAS 的同一输入重试回读当前修订；不同输入不能借用旧修订覆盖计划。
func (p *Postgres) SaveReportPlan(ctx context.Context, user model.Principal, change assistant.PlanChange, queue *river.Client[pgx.Tx], vault *secrets.Vault, requestID string) (assistant.Plan, error) {
	var result assistant.Plan
	if user.Role != "admin" || !contract.ValidID(change.ID) || change.ExpectedRevision < 0 || change.ExpectedRevision >= (1<<53)-1 || change.Spec.Validate() != nil || (change.Spec.Enabled && (queue == nil || queue.Schema() != assistant.QueueSchema)) {
		return result, assistant.ErrInput
	}
	raw, _ := json.Marshal(change.Spec)
	err := p.TenantTx(ctx, user.TenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, user.TenantID+"/models"); err != nil {
			return err
		}
		if err := activePlanOwner(ctx, tx, user.TenantID, user.ID); err != nil {
			return err
		}
		var revision int64
		var owner string
		var previous []byte
		var oldJob *int64
		err := tx.QueryRow(ctx, `SELECT revision,created_by,spec,river_job_id FROM report_plans WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, user.TenantID, change.ID).Scan(&revision, &owner, &previous, &oldJob)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if revision > 0 && owner != user.ID {
			return pgx.ErrNoRows
		}
		if revision == change.ExpectedRevision+1 {
			var spec assistant.PlanSpec
			if json.Unmarshal(previous, &spec) != nil || spec != change.Spec {
				return ErrConflict
			}
			result, err = scanPlan(tx.QueryRow(ctx, `SELECT `+planJSON+` FROM report_plans WHERE tenant_id=$1 AND id=$2 AND created_by=$3`, user.TenantID, change.ID, user.ID))
			return err
		}
		if revision != change.ExpectedRevision {
			return ErrConflict
		}
		var changes int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM operation_audits WHERE tenant_id=$1 AND action='reports.plan.save' AND created_at>=date_trunc('day',now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'`, user.TenantID).Scan(&changes); err != nil {
			return err
		}
		if changes >= 1000 {
			return ErrPlanQuota
		}
		if revision == 0 {
			var count int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM report_plans WHERE tenant_id=$1`, user.TenantID).Scan(&count); err != nil {
				return err
			}
			if count >= 32 {
				return ErrPlanQuota
			}
		}
		var provider, providerRevision any
		if change.Spec.ProviderID != "" {
			provider, providerRevision = change.Spec.ProviderID, change.Spec.ProviderRevision
			var exists bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM model_provider_versions WHERE tenant_id=$1 AND provider_id=$2 AND revision=$3)`, user.TenantID, provider, providerRevision).Scan(&exists); err != nil {
				return err
			}
			if !exists {
				return pgx.ErrNoRows
			}
			if change.Spec.Enabled {
				var current int64
				if err := tx.QueryRow(ctx, `SELECT revision FROM model_providers WHERE tenant_id=$1 AND id=$2 FOR SHARE`, user.TenantID, provider).Scan(&current); err != nil {
					return err
				}
				if current != change.Spec.ProviderRevision {
					return ErrConflict
				}
				config, err := modelConfig(ctx, tx, user.TenantID, change.Spec.ProviderID, current, vault)
				if err != nil {
					return err
				}
				if !config.Enabled {
					return ErrConflict
				}
			}
		}
		var nextAt, jobID any
		if oldJob != nil && queue != nil {
			if _, err := queue.JobCancelTx(ctx, tx, *oldJob); err != nil && !errors.Is(err, rivertype.ErrNotFound) {
				return err
			}
		}
		if change.Spec.Enabled {
			var now time.Time
			if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
				return err
			}
			due, err := change.Spec.Next(now)
			if err != nil {
				return err
			}
			queued, err := queuePlan(ctx, tx, queue, assistant.PlanArgs{TenantID: user.TenantID, PlanID: change.ID, Revision: revision + 1, DueAt: due})
			if err != nil {
				return err
			}
			nextAt, jobID = due, queued
		}
		if _, err := tx.Exec(ctx, `INSERT INTO report_plans(tenant_id,id,created_by,revision,spec,provider_id,provider_revision,next_at,river_job_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(tenant_id,id) DO UPDATE SET revision=EXCLUDED.revision,spec=EXCLUDED.spec,provider_id=EXCLUDED.provider_id,provider_revision=EXCLUDED.provider_revision,next_at=EXCLUDED.next_at,river_job_id=EXCLUDED.river_job_id,updated_at=clock_timestamp()`, user.TenantID, change.ID, user.ID, revision+1, raw, provider, providerRevision, nextAt, jobID); err != nil {
			return err
		}
		result, err = scanPlan(tx.QueryRow(ctx, `SELECT `+planJSON+` FROM report_plans WHERE tenant_id=$1 AND id=$2 AND created_by=$3`, user.TenantID, change.ID, user.ID))
		if err != nil {
			return err
		}
		return insertOperationAudit(ctx, tx, user, "reports.plan.save", change.ID, requestID)
	})
	return result, err
}

// 计划下一槽位和当前运行在同一事务持久化；恢复作业复用当前运行，不再推进一次。
func (p *Postgres) StartReportPlan(ctx context.Context, args assistant.PlanArgs, riverID int64, queue *river.Client[pgx.Tx]) (assistant.PlanLease, error) {
	lease := assistant.PlanLease{Args: args}
	if args.Validate() != nil || riverID < 1 || queue == nil || queue.Schema() != assistant.QueueSchema {
		return lease, assistant.ErrInput
	}
	err := p.TenantTx(ctx, args.TenantID, func(tx pgx.Tx) error {
		var owner string
		var revision int64
		var raw []byte
		var due *time.Time
		var expectedJob *int64
		if err := tx.QueryRow(ctx, `SELECT created_by,revision,spec,next_at,river_job_id FROM report_plans WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, args.TenantID, args.PlanID).Scan(&owner, &revision, &raw, &due, &expectedJob); err != nil {
			return err
		}
		var spec assistant.PlanSpec
		if json.Unmarshal(raw, &spec) != nil || spec.Validate() != nil || revision != args.Revision || !spec.Enabled {
			return ErrConflict
		}
		lease.OwnerID = owner
		var state string
		var deadline time.Time
		var runRiverID int64
		err := tx.QueryRow(ctx, `SELECT id,state,request,deadline,river_job_id FROM report_plan_runs WHERE tenant_id=$1 AND plan_id=$2 AND plan_revision=$3 AND due_at=$4 FOR UPDATE`, args.TenantID, args.PlanID, args.Revision, args.DueAt).Scan(&lease.RunID, &state, &raw, &deadline, &runRiverID)
		var now time.Time
		if errNow := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); errNow != nil {
			return errNow
		}
		if err == nil {
			if runRiverID != riverID {
				return ErrConflict
			}
			if state != "preparing" || !deadline.After(now) {
				return nil
			}
			if json.Unmarshal(raw, &lease.Request) != nil {
				return assistant.ErrInput
			}
			if err := activePlanOwner(ctx, tx, args.TenantID, owner); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return suspendUnqualifiedPlan(ctx, tx, lease, spec, expectedJob, riverID, queue)
				}
				return err
			}
			lease.Execute = true
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if due == nil || expectedJob == nil || *expectedJob != riverID || !due.Equal(args.DueAt) || args.DueAt.After(now) {
			return ErrConflict
		}
		effective, err := spec.Latest(now)
		if err != nil || effective.Before(args.DueAt) {
			return assistant.ErrInput
		}
		lease.Request, err = spec.RequestAt(effective)
		if err != nil {
			return err
		}
		lease.RunID = RandomID("planrun_")
		raw, _ = json.Marshal(lease.Request)
		var skippedFrom, skippedUntil, provider, providerRevision any
		if effective.After(args.DueAt) {
			skippedFrom, skippedUntil = args.DueAt, effective
		}
		if lease.Request.ProviderID != "" {
			provider, providerRevision = lease.Request.ProviderID, lease.Request.ProviderRevision
		}
		if _, err := tx.Exec(ctx, `INSERT INTO report_plan_runs(tenant_id,id,plan_id,created_by,plan_revision,due_at,effective_at,skipped_from,skipped_until,request,provider_id,provider_revision,state,river_job_id,deadline,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'preparing',$13,now()+interval '15 minutes',now()+make_interval(days=>COALESCE((SELECT days FROM retention_policies WHERE tenant_id=$1 AND category='reports'),180)))`, args.TenantID, lease.RunID, args.PlanID, owner, args.Revision, args.DueAt, effective, skippedFrom, skippedUntil, raw, provider, providerRevision, riverID); err != nil {
			return err
		}
		if err := activePlanOwner(ctx, tx, args.TenantID, owner); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return suspendUnqualifiedPlan(ctx, tx, lease, spec, expectedJob, riverID, queue)
			}
			return err
		}
		lease.Execute = true
		next, err := spec.Next(now)
		if err != nil {
			return err
		}
		queued, err := queuePlan(ctx, tx, queue, assistant.PlanArgs{TenantID: args.TenantID, PlanID: args.PlanID, Revision: args.Revision, DueAt: next})
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE report_plans SET next_at=$3,river_job_id=$4 WHERE tenant_id=$1 AND id=$2`, args.TenantID, args.PlanID, next, queued)
		return err
	})
	return lease, err
}

// 所有者失去执行资格后保留失败周期并停止未来任务，恢复账号不会恢复旧持续授权。
func suspendUnqualifiedPlan(ctx context.Context, tx pgx.Tx, lease assistant.PlanLease, spec assistant.PlanSpec, nextJob *int64, currentJob int64, queue *river.Client[pgx.Tx]) error {
	if nextJob != nil && *nextJob != currentJob {
		if _, err := queue.JobCancelTx(ctx, tx, *nextJob); err != nil && !errors.Is(err, rivertype.ErrNotFound) {
			return err
		}
	}
	tag, err := tx.Exec(ctx, `UPDATE report_plan_runs SET state='failed',code='plan_qualification_changed',finished_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND plan_id=$3 AND plan_revision=$4 AND created_by=$5 AND state='preparing'`, lease.Args.TenantID, lease.RunID, lease.Args.PlanID, lease.Args.Revision, lease.OwnerID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrConflict
	}
	spec.Enabled = false
	raw, _ := json.Marshal(spec)
	if _, err := tx.Exec(ctx, `UPDATE report_plans SET revision=LEAST(revision+1,9007199254740991),spec=$3,next_at=NULL,river_job_id=NULL,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND revision=$4`, lease.Args.TenantID, lease.Args.PlanID, raw, lease.Args.Revision); err != nil {
		return err
	}
	return insertOperationAudit(ctx, tx, model.Principal{ID: "system:report-plans", TenantID: lease.Args.TenantID}, "reports.plan.suspend", lease.Args.PlanID, lease.RunID)
}

func (p *Postgres) CheckReportPlanLease(ctx context.Context, lease assistant.PlanLease) error {
	user := model.Principal{ID: lease.OwnerID, TenantID: lease.Args.TenantID, Role: "admin"}
	return p.TenantTx(ctx, user.TenantID, func(tx pgx.Tx) error {
		return validateReportPlanLease(ctx, tx, user, &lease, lease.Request)
	})
}

func validateReportPlanLease(ctx context.Context, tx pgx.Tx, user model.Principal, lease *assistant.PlanLease, input assistant.Request) error {
	if lease.Args.Validate() != nil || !contract.ValidID(lease.RunID) || !lease.Execute || lease.OwnerID != user.ID || lease.Args.TenantID != user.TenantID || lease.Request != input {
		return assistant.ErrInput
	}
	var revision int64
	var raw []byte
	if err := tx.QueryRow(ctx, `SELECT revision,spec FROM report_plans WHERE tenant_id=$1 AND id=$2 AND created_by=$3 FOR UPDATE`, user.TenantID, lease.Args.PlanID, user.ID).Scan(&revision, &raw); err != nil {
		return err
	}
	var spec assistant.PlanSpec
	if json.Unmarshal(raw, &spec) != nil || !spec.Enabled || revision != lease.Args.Revision {
		return ErrConflict
	}
	if err := activePlanOwner(ctx, tx, user.TenantID, user.ID); err != nil {
		return err
	}
	var request []byte
	if err := tx.QueryRow(ctx, `SELECT request FROM report_plan_runs WHERE tenant_id=$1 AND id=$2 AND plan_id=$3 AND plan_revision=$4 AND created_by=$5 AND state='preparing' AND deadline>now() FOR UPDATE`, user.TenantID, lease.RunID, lease.Args.PlanID, lease.Args.Revision, user.ID).Scan(&request); err != nil {
		return err
	}
	var stored assistant.Request
	if json.Unmarshal(request, &stored) != nil || stored != input {
		return ErrConflict
	}
	return nil
}

func submitReportPlanRun(ctx context.Context, tx pgx.Tx, lease *assistant.PlanLease, analysisID string) error {
	if !contract.ValidID(analysisID) {
		return assistant.ErrInput
	}
	tag, err := tx.Exec(ctx, `UPDATE report_plan_runs SET state='submitted',code='report_submitted',analysis_id=$3,finished_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND state='preparing' AND deadline>now()`, lease.Args.TenantID, lease.RunID, analysisID)
	if err == nil && tag.RowsAffected() != 1 {
		return ErrConflict
	}
	return err
}

func (p *Postgres) FailReportPlanRun(ctx context.Context, lease assistant.PlanLease, code string, queues ...*river.Client[pgx.Tx]) error {
	if lease.Args.Validate() != nil || !contract.ValidID(lease.RunID) || (code != "preparation_unavailable" && code != "plan_qualification_changed" && code != "model_quota_exceeded") {
		return assistant.ErrInput
	}
	return p.TenantTx(ctx, lease.Args.TenantID, func(tx pgx.Tx) error {
		if code == "plan_qualification_changed" && len(queues) > 0 && queues[0] != nil {
			if queues[0].Schema() != assistant.QueueSchema || !contract.ValidID(lease.OwnerID) {
				return assistant.ErrInput
			}
			var raw []byte
			var nextJob *int64
			err := tx.QueryRow(ctx, `SELECT spec,river_job_id FROM report_plans WHERE tenant_id=$1 AND id=$2 AND revision=$3 AND created_by=$4 FOR UPDATE`, lease.Args.TenantID, lease.Args.PlanID, lease.Args.Revision, lease.OwnerID).Scan(&raw, &nextJob)
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
			if err == nil {
				var spec assistant.PlanSpec
				if json.Unmarshal(raw, &spec) != nil || spec.Validate() != nil {
					return assistant.ErrInput
				}
				if spec.Enabled {
					if err := activePlanOwner(ctx, tx, lease.Args.TenantID, lease.OwnerID); err != nil {
						if errors.Is(err, pgx.ErrNoRows) {
							return suspendUnqualifiedPlan(ctx, tx, lease, spec, nextJob, 0, queues[0])
						}
						return err
					}
				}
			}
		}
		_, err := tx.Exec(ctx, `UPDATE report_plan_runs SET state='failed',code=$3,finished_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND plan_id=$4 AND plan_revision=$5 AND state='preparing'`, lease.Args.TenantID, lease.RunID, code, lease.Args.PlanID, lease.Args.Revision)
		return err
	})
}

type PlanRunPage struct {
	Items []assistant.PlanRun `json:"items"`
	Next  string              `json:"next_cursor"`
}

func (p *Postgres) ReportPlanRuns(ctx context.Context, user model.Principal, id, before string) (PlanRunPage, error) {
	page := PlanRunPage{Items: []assistant.PlanRun{}}
	if !contract.ValidID(id) || (before != "" && !contract.ValidID(before)) {
		return page, assistant.ErrInput
	}
	err := p.TenantTx(ctx, user.TenantID, func(tx pgx.Tx) error {
		var plan string
		if err := tx.QueryRow(ctx, `SELECT id FROM report_plans WHERE tenant_id=$1 AND id=$2 AND created_by=$3`, user.TenantID, id, user.ID).Scan(&plan); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE report_plan_runs h SET state='failed',code='preparation_interrupted',finished_at=clock_timestamp() WHERE tenant_id=$1 AND plan_id=$2 AND created_by=$3 AND state='preparing' AND (deadline<=now() OR EXISTS(SELECT 1 FROM starbeacon_jobs.river_job r WHERE r.id=h.river_job_id AND r.state IN ('completed','cancelled','discarded')))`, user.TenantID, id, user.ID); err != nil {
			return err
		}
		if err := recoverAnalysis(ctx, tx, user.TenantID); err != nil {
			return err
		}
		boundary, cursor := time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC), "~"
		if before != "" {
			cursor = before
			if err := tx.QueryRow(ctx, `SELECT created_at FROM report_plan_runs WHERE tenant_id=$1 AND id=$2 AND plan_id=$3 AND created_by=$4 AND expires_at>now()`, user.TenantID, before, id, user.ID).Scan(&boundary); err != nil {
				return err
			}
		}
		rows, err := tx.Query(ctx, `SELECT `+planRunJSON+` FROM report_plan_runs h LEFT JOIN analysis_jobs j ON j.tenant_id=h.tenant_id AND j.id=h.analysis_id AND j.expires_at>now() WHERE h.tenant_id=$1 AND h.plan_id=$2 AND h.created_by=$3 AND h.expires_at>now() AND (h.created_at,h.id)<($4,$5) ORDER BY h.created_at DESC,h.id DESC LIMIT 21`, user.TenantID, id, user.ID, boundary, cursor)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var item assistant.PlanRun
			var raw []byte
			if err := rows.Scan(&raw); err != nil {
				return err
			}
			if err := json.Unmarshal(raw, &item); err != nil {
				return err
			}
			page.Items = append(page.Items, item)
		}
		if len(page.Items) > 20 {
			page.Items = page.Items[:20]
			page.Next = page.Items[len(page.Items)-1].ID
		}
		return rows.Err()
	})
	return page, err
}
