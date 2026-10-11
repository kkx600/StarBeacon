package store

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/analytics"
	"github.com/kkx600/StarBeacon/internal/assistant"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/llm"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/secrets"
	"github.com/riverqueue/river"
)

const analysisJSON = `jsonb_build_object('id',id,'revision',revision,'request',request,'state',state,'cancel_requested',cancel_requested,'template',template,'evidence',evidence,'answer',answer,'result',result,'created_at',created_at,'started_at',started_at,'finished_at',finished_at,'expires_at',expires_at)`

func scanAnalysis(row pgx.Row) (assistant.Job, error) {
	var job assistant.Job
	var raw []byte
	if err := row.Scan(&raw); err != nil {
		return job, err
	}
	err := json.Unmarshal(raw, &job)
	if err == nil && !validAnalysisWindow(job.Request.Window, job.Request.Kind) {
		err = errors.New("分析作业的统计窗口校验失败")
	}
	return job, err
}

func validAnalysisWindow(window analytics.Window, kind string) bool {
	if !slices.Contains([]string{"chat", "daily", "weekly", "monthly"}, kind) {
		return false
	}
	limit := 32 * 24 * time.Hour
	if kind == "chat" {
		limit = 31 * 24 * time.Hour
	}
	return !window.Start.IsZero() && !window.End.IsZero() && window.End.After(window.Start) && window.End.Sub(window.Start) <= limit
}

// recoverAnalysis 不重新排队已经可能计费的请求，迟到结果也不能覆盖未知终态。
func recoverAnalysis(ctx context.Context, tx pgx.Tx, tenant string) error {
	if _, err := tx.Exec(ctx, `UPDATE analysis_jobs SET state='uncertain',result='{"state":"uncertain","code":"provider_result_unknown","usage":null,"duration_ms":null}',finished_at=clock_timestamp() WHERE tenant_id=$1 AND state='running' AND deadline<=now()`, tenant); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `UPDATE analysis_jobs SET state='failed',result='{"state":"failed","code":"queue_wait_expired","usage":null,"duration_ms":null}',finished_at=clock_timestamp() WHERE tenant_id=$1 AND state='queued' AND deadline<=now()`, tenant)
	return err
}

func (p *Postgres) ExistingAnalysis(ctx context.Context, user model.Principal, key, inputHash string) (assistant.Job, error) {
	var job assistant.Job
	if !contract.ValidID(key) || len(inputHash) != 64 {
		return job, assistant.ErrInput
	}
	err := p.TenantTx(ctx, user.TenantID, func(tx pgx.Tx) error {
		if err := recoverAnalysis(ctx, tx, user.TenantID); err != nil {
			return err
		}
		var hash string
		if err := tx.QueryRow(ctx, `SELECT request_hash FROM analysis_jobs WHERE tenant_id=$1 AND created_by=$2 AND idempotency_key_hash=$3 AND expires_at>now()`, user.TenantID, user.ID, Hash(key)).Scan(&hash); err != nil {
			return err
		}
		if hash != inputHash {
			return ErrConflict
		}
		var err error
		job, err = scanAnalysis(tx.QueryRow(ctx, `SELECT `+analysisJSON+` FROM analysis_jobs WHERE tenant_id=$1 AND created_by=$2 AND idempotency_key_hash=$3 AND expires_at>now()`, user.TenantID, user.ID, Hash(key)))
		return err
	})
	return job, err
}

func (p *Postgres) AnalysisHistory(ctx context.Context, user model.Principal, thread string) ([]assistant.Turn, error) {
	items := []assistant.Turn{}
	if thread == "" {
		return items, nil
	}
	if !contract.ValidID(thread) {
		return nil, assistant.ErrInput
	}
	err := p.TenantTx(ctx, user.TenantID, func(tx pgx.Tx) error {
		var id string
		if err := tx.QueryRow(ctx, `SELECT id FROM analysis_threads WHERE tenant_id=$1 AND id=$2 AND created_by=$3 AND expires_at>now()`, user.TenantID, thread, user.ID).Scan(&id); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT request->>'question',COALESCE(answer->>'summary','') FROM analysis_jobs WHERE tenant_id=$1 AND thread_id=$2 AND created_by=$3 AND expires_at>now() AND state='succeeded' ORDER BY created_at DESC,id DESC LIMIT 8`, user.TenantID, thread, user.ID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var turn assistant.Turn
			if err := rows.Scan(&turn.Question, &turn.Summary); err != nil {
				return err
			}
			items = append(items, turn)
		}
		slices.Reverse(items)
		return rows.Err()
	})
	return items, err
}

func (p *Postgres) CreateAnalysis(ctx context.Context, user model.Principal, input assistant.Request, key string, evidence assistant.Evidence, prompt string, queue *river.Client[pgx.Tx], vault *secrets.Vault, requestID string) (assistant.Job, error) {
	return p.createAnalysis(ctx, user, input, key, evidence, prompt, queue, vault, requestID, nil)
}

func (p *Postgres) CreateScheduledAnalysis(ctx context.Context, lease assistant.PlanLease, evidence assistant.Evidence, prompt string, queue *river.Client[pgx.Tx], vault *secrets.Vault) (assistant.Job, error) {
	frozen, err := assistant.Freeze(lease.Request.Window, evidence.Segments)
	if err != nil || frozen.SHA256 != evidence.SHA256 || !frozen.Window.Start.Equal(evidence.Window.Start) || !frozen.Window.End.Equal(evidence.Window.End) {
		return assistant.Job{}, assistant.ErrInput
	}
	user := model.Principal{ID: lease.OwnerID, TenantID: lease.Args.TenantID, Role: "admin"}
	return p.createAnalysis(ctx, user, lease.Request, lease.RunID, evidence, prompt, queue, vault, lease.RunID, &lease)
}

func (p *Postgres) createAnalysis(ctx context.Context, user model.Principal, input assistant.Request, key string, evidence assistant.Evidence, prompt string, queue *river.Client[pgx.Tx], vault *secrets.Vault, requestID string, planned *assistant.PlanLease) (assistant.Job, error) {
	var job assistant.Job
	if !contract.ValidID(key) || len(prompt) > 24576 {
		return job, assistant.ErrInput
	}
	rawInput, err := json.Marshal(input)
	if err != nil {
		return job, err
	}
	inputHash := Hash(string(rawInput))
	err = p.TenantTx(ctx, user.TenantID, func(tx pgx.Tx) (err error) {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, user.TenantID+"/models"); err != nil {
			return err
		}
		if planned != nil {
			if err := validateReportPlanLease(ctx, tx, user, planned, input); err != nil {
				return err
			}
			// 报告入队和计划运行关联同事务提交，不留下重复生成或孤立的计费作业。
			defer func() {
				if err == nil {
					err = submitReportPlanRun(ctx, tx, planned, job.ID)
				}
			}()
		}
		if err := recoverAnalysis(ctx, tx, user.TenantID); err != nil {
			return err
		}
		var priorHash string
		err = tx.QueryRow(ctx, `SELECT request_hash FROM analysis_jobs WHERE tenant_id=$1 AND created_by=$2 AND idempotency_key_hash=$3 FOR UPDATE`, user.TenantID, user.ID, Hash(key)).Scan(&priorHash)
		if err == nil {
			if priorHash != inputHash {
				return ErrConflict
			}
			job, err = scanAnalysis(tx.QueryRow(ctx, `SELECT `+analysisJSON+` FROM analysis_jobs WHERE tenant_id=$1 AND created_by=$2 AND idempotency_key_hash=$3 AND expires_at>now()`, user.TenantID, user.ID, Hash(key)))
			return err
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		var config llm.Config
		if input.ProviderID != "" {
			if queue == nil || queue.Schema() != assistant.QueueSchema {
				return assistant.ErrInput
			}
			var current int64
			if err := tx.QueryRow(ctx, `SELECT revision FROM model_providers WHERE tenant_id=$1 AND id=$2 FOR SHARE`, user.TenantID, input.ProviderID).Scan(&current); err != nil {
				return err
			}
			if current != input.ProviderRevision {
				return ErrConflict
			}
			config, err = modelConfig(ctx, tx, user.TenantID, input.ProviderID, current, vault)
			if err != nil {
				return err
			}
			if !config.Enabled {
				return ErrConflict
			}
			if err := checkModelBudget(ctx, tx, user.TenantID, input.ProviderID, config.DailyRequests); err != nil {
				return err
			}
		}
		var submitted int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM analysis_jobs WHERE tenant_id=$1 AND created_at>=date_trunc('day',now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'`, user.TenantID).Scan(&submitted); err != nil {
			return err
		}
		if submitted >= 10000 {
			return ErrModelQuota
		}
		job = assistant.Job{ID: RandomID("analysis_"), Revision: 1, Request: input, State: "queued", Template: assistant.TemplateVersion, Evidence: evidence, Result: llm.Result{State: "queued", Code: "awaiting_execution"}}
		category := "reports"
		if input.Kind == "chat" {
			category = "models"
			if input.ThreadID == "" {
				job.Request.ThreadID = RandomID("thread_")
				title := []rune(input.Question)
				if len(title) > 80 {
					title = title[:80]
				}
				if _, err := tx.Exec(ctx, `INSERT INTO analysis_threads(tenant_id,id,created_by,title,expires_at) VALUES($1,$2,$3,$4,now()+make_interval(days=>COALESCE((SELECT days FROM retention_policies WHERE tenant_id=$1 AND category='models'),180)))`, user.TenantID, job.Request.ThreadID, user.ID, string(title)); err != nil {
					return err
				}
			} else {
				var thread string
				if err := tx.QueryRow(ctx, `SELECT id FROM analysis_threads WHERE tenant_id=$1 AND id=$2 AND created_by=$3 AND expires_at>now() FOR UPDATE`, user.TenantID, input.ThreadID, user.ID).Scan(&thread); err != nil {
					return err
				}
				var last, state string
				if err := tx.QueryRow(ctx, `SELECT id,state FROM analysis_jobs WHERE tenant_id=$1 AND thread_id=$2 AND created_by=$3 AND expires_at>now() ORDER BY created_at DESC,id DESC LIMIT 1`, user.TenantID, input.ThreadID, user.ID).Scan(&last, &state); err != nil {
					return err
				}
				if last != input.ParentID || state == "queued" || state == "running" {
					return ErrConflict
				}
				if _, err := tx.Exec(ctx, `UPDATE analysis_threads SET updated_at=clock_timestamp(),expires_at=now()+make_interval(days=>COALESCE((SELECT days FROM retention_policies WHERE tenant_id=$1 AND category='models'),180)) WHERE tenant_id=$1 AND id=$2`, user.TenantID, input.ThreadID); err != nil {
					return err
				}
			}
		} else if err := tx.QueryRow(ctx, `SELECT COALESCE(max(revision),0)+1 FROM analysis_jobs WHERE tenant_id=$1 AND kind=$2 AND period_start=$3 AND period_end=$4`, user.TenantID, input.Kind, input.Window.Start, input.Window.End).Scan(&job.Revision); err != nil {
			return err
		}
		if input.ProviderID == "" {
			job.State = "succeeded"
			job.Result = llm.Result{State: "succeeded", Code: "statistics_only"}
		}
		requestRaw, _ := json.Marshal(job.Request)
		evidenceRaw, _ := json.Marshal(evidence)
		resultRaw, _ := json.Marshal(job.Result)
		var provider any
		var revision any
		var thread any
		if input.ProviderID != "" {
			provider = input.ProviderID
			revision = input.ProviderRevision
		}
		if job.Request.ThreadID != "" {
			thread = job.Request.ThreadID
		}
		if err := tx.QueryRow(ctx, `INSERT INTO analysis_jobs(tenant_id,id,created_by,kind,thread_id,provider_id,provider_revision,revision,period_start,period_end,request,request_hash,idempotency_key_hash,template,evidence,prompt,prompt_hash,state,result,deadline,finished_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,now()+interval '5 minutes',CASE WHEN $18='succeeded' THEN clock_timestamp() ELSE NULL END,now()+make_interval(days=>COALESCE((SELECT days FROM retention_policies WHERE tenant_id=$1 AND category=$20),180))) RETURNING created_at,finished_at,expires_at`, user.TenantID, job.ID, user.ID, input.Kind, thread, provider, revision, job.Revision, input.Window.Start, input.Window.End, requestRaw, inputHash, Hash(key), job.Template, evidenceRaw, prompt, Hash(prompt), job.State, resultRaw, category).Scan(&job.CreatedAt, &job.FinishedAt, &job.ExpiresAt); err != nil {
			return err
		}
		if input.ProviderID != "" {
			queueName := "reports"
			if input.Kind == "chat" {
				queueName = "assistant"
			}
			queued, err := queue.InsertTx(ctx, tx, assistant.Args{TenantID: user.TenantID, JobID: job.ID}, &river.InsertOpts{Queue: queueName, MaxAttempts: 1})
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE analysis_jobs SET river_job_id=$3 WHERE tenant_id=$1 AND id=$2`, user.TenantID, job.ID, queued.Job.ID); err != nil {
				return err
			}
		}
		return insertOperationAudit(ctx, tx, user, "analysis.create", job.ID, requestID)
	})
	return job, err
}

// checkModelBudget 对连接验证与业务作业使用同一 UTC 日额度和跨实例并发门控。
func checkModelBudget(ctx context.Context, tx pgx.Tx, tenant, provider string, daily int) error {
	if _, err := tx.Exec(ctx, `UPDATE model_capability_checks SET state='uncertain',result='{"state":"uncertain","code":"provider_result_unknown"}',finished_at=clock_timestamp() WHERE tenant_id=$1 AND state='running' AND deadline<=now()`, tenant); err != nil {
		return err
	}
	if err := recoverAnalysis(ctx, tx, tenant); err != nil {
		return err
	}
	if err := recoverRuleGeneration(ctx, tx, tenant); err != nil {
		return err
	}
	if err := recoverAlertTriage(ctx, tx, tenant); err != nil {
		return err
	}
	var count, active, tenantActive int
	if err := tx.QueryRow(ctx, `SELECT count(*) FILTER(WHERE provider_id=$2 AND created_at>=date_trunc('day',now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'),count(*) FILTER(WHERE provider_id=$2 AND active),count(*) FILTER(WHERE active) FROM (SELECT provider_id,created_at,(state='running' AND deadline>now()) AS active FROM model_capability_checks WHERE tenant_id=$1 UNION ALL SELECT provider_id,created_at,(state IN ('queued','running')) AS active FROM analysis_jobs WHERE tenant_id=$1 AND provider_id IS NOT NULL UNION ALL SELECT provider_id,created_at,(state IN ('queued','running')) AS active FROM rule_generation_jobs WHERE tenant_id=$1 UNION ALL SELECT provider_id,created_at,(state IN ('queued','running')) AS active FROM alert_triage_jobs WHERE tenant_id=$1) calls`, tenant, provider).Scan(&count, &active, &tenantActive); err != nil {
		return err
	}
	if count >= daily || active >= 1 || tenantActive >= 4 {
		return ErrModelQuota
	}
	return nil
}

func (p *Postgres) AnalysisJob(ctx context.Context, user model.Principal, id string) (assistant.Job, error) {
	var job assistant.Job
	if !contract.ValidID(id) {
		return job, pgx.ErrNoRows
	}
	err := p.TenantTx(ctx, user.TenantID, func(tx pgx.Tx) error {
		if err := recoverAnalysis(ctx, tx, user.TenantID); err != nil {
			return err
		}
		var err error
		job, err = scanAnalysis(tx.QueryRow(ctx, `SELECT `+analysisJSON+` FROM analysis_jobs WHERE tenant_id=$1 AND id=$2 AND created_by=$3 AND expires_at>now()`, user.TenantID, id, user.ID))
		return err
	})
	return job, err
}

type AnalysisSummary struct {
	ID              string           `json:"id"`
	Kind            string           `json:"kind"`
	ThreadID        string           `json:"thread_id"`
	Title           string           `json:"title"`
	State           string           `json:"state"`
	Revision        int64            `json:"revision"`
	Window          analytics.Window `json:"window"`
	CreatedAt       time.Time        `json:"created_at"`
	CancelRequested bool             `json:"cancel_requested"`
}
type AnalysisPage struct {
	Items []AnalysisSummary `json:"items"`
	Next  string            `json:"next_cursor"`
}

func (p *Postgres) AnalysisJobs(ctx context.Context, user model.Principal, group, before string, limit int) (AnalysisPage, error) {
	page := AnalysisPage{Items: []AnalysisSummary{}}
	if !slices.Contains([]string{"reports", "chat"}, group) || limit < 1 || limit > 50 || (before != "" && !contract.ValidID(before)) {
		return page, assistant.ErrInput
	}
	err := p.TenantTx(ctx, user.TenantID, func(tx pgx.Tx) error {
		if err := recoverAnalysis(ctx, tx, user.TenantID); err != nil {
			return err
		}
		boundary := time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)
		cursor := "~"
		if before != "" {
			cursor = before
			if err := tx.QueryRow(ctx, `SELECT created_at FROM analysis_jobs WHERE tenant_id=$1 AND id=$2 AND created_by=$3 AND expires_at>now()`, user.TenantID, before, user.ID).Scan(&boundary); err != nil {
				return err
			}
		}
		rows, err := tx.Query(ctx, `SELECT id,kind,COALESCE(thread_id,''),CASE WHEN kind='chat' THEN left(request->>'question',80) ELSE request->>'period' END,state,revision,request->'window',created_at,cancel_requested FROM analysis_jobs WHERE tenant_id=$1 AND created_by=$2 AND expires_at>now() AND ((kind='chat')=($3='chat')) AND (created_at,id)<($4,$5) ORDER BY created_at DESC,id DESC LIMIT $6`, user.TenantID, user.ID, group, boundary, cursor, limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var item AnalysisSummary
			var window []byte
			if err := rows.Scan(&item.ID, &item.Kind, &item.ThreadID, &item.Title, &item.State, &item.Revision, &window, &item.CreatedAt, &item.CancelRequested); err != nil {
				return err
			}
			if err := json.Unmarshal(window, &item.Window); err != nil {
				return err
			}
			if !validAnalysisWindow(item.Window, item.Kind) {
				return errors.New("分析作业列表的统计窗口校验失败")
			}
			page.Items = append(page.Items, item)
		}
		if len(page.Items) > limit {
			page.Items = page.Items[:limit]
			page.Next = page.Items[len(page.Items)-1].ID
		}
		return rows.Err()
	})
	return page, err
}

type AnalysisLease struct {
	Job     assistant.Job
	Config  llm.Config
	Prompt  string
	Token   string
	Execute bool
}

func (p *Postgres) StartAnalysis(ctx context.Context, args assistant.Args, riverID int64, vault *secrets.Vault) (AnalysisLease, error) {
	var lease AnalysisLease
	if !contract.ValidID(args.TenantID) || !contract.ValidID(args.JobID) || riverID < 1 {
		return lease, assistant.ErrInput
	}
	err := p.TenantTx(ctx, args.TenantID, func(tx pgx.Tx) error {
		if err := recoverAnalysis(ctx, tx, args.TenantID); err != nil {
			return err
		}
		var raw []byte
		var state, prompt, promptHash, owner string
		var recordedID int64
		var requested bool
		if err := tx.QueryRow(ctx, `SELECT `+analysisJSON+`,state,prompt,prompt_hash,river_job_id,cancel_requested,created_by FROM analysis_jobs WHERE tenant_id=$1 AND id=$2 AND expires_at>now() FOR UPDATE`, args.TenantID, args.JobID).Scan(&raw, &state, &prompt, &promptHash, &recordedID, &requested, &owner); err != nil {
			return err
		}
		if recordedID != riverID {
			return ErrConflict
		}
		if state != "queued" || requested {
			return nil
		}
		if err := json.Unmarshal(raw, &lease.Job); err != nil {
			return err
		}
		var valid bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users u JOIN tenants t ON t.id=u.tenant_id WHERE u.tenant_id=$1 AND u.id=$2 AND u.role='admin' AND u.active AND t.active)`, args.TenantID, owner).Scan(&valid); err != nil {
			return err
		}
		code := ""
		if !valid {
			code = "authorization_revoked"
		}
		var revision int64
		if err := tx.QueryRow(ctx, `SELECT revision FROM model_providers WHERE tenant_id=$1 AND id=$2`, args.TenantID, lease.Job.Request.ProviderID).Scan(&revision); err != nil {
			return err
		}
		if revision != lease.Job.Request.ProviderRevision {
			code = "provider_revision_changed"
		}
		if code == "" {
			var err error
			lease.Config, err = modelConfig(ctx, tx, args.TenantID, lease.Job.Request.ProviderID, revision, vault)
			if errors.Is(err, secrets.ErrUnavailable) || errors.Is(err, pgx.ErrNoRows) {
				// 出站调用尚未发生；凭据不可用须保存明确终态，不能留下无法执行的排队记录。
				code = "provider_config_unavailable"
			} else if err != nil {
				return err
			}
			if code == "" && !lease.Config.Enabled {
				code = "provider_disabled"
			}
		}
		if Hash(prompt) != promptHash || lease.Job.Template != assistant.TemplateVersion || prompt == "" || !validAnalysisWindow(lease.Job.Request.Window, lease.Job.Request.Kind) {
			code = "analysis_input_invalid"
		}
		if code != "" {
			result, _ := json.Marshal(llm.Result{State: "failed", Code: code})
			_, err := tx.Exec(ctx, `UPDATE analysis_jobs SET state='failed',result=$3,finished_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2`, args.TenantID, args.JobID, result)
			return err
		}
		lease.Prompt, lease.Token, lease.Execute = prompt, Token(), true
		lease.Job.State = "running"
		return tx.QueryRow(ctx, `UPDATE analysis_jobs SET state='running',lease_token=$3,deadline=now()+make_interval(secs=>$4),started_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 RETURNING started_at`, args.TenantID, args.JobID, lease.Token, lease.Config.TimeoutSeconds+15).Scan(&lease.Job.StartedAt)
	})
	return lease, err
}

func (p *Postgres) FinishAnalysis(ctx context.Context, tenant string, lease AnalysisLease, result llm.Result, answer *assistant.Answer) error {
	if !slices.Contains([]string{"succeeded", "failed", "refused", "incomplete", "uncertain", "cancelled"}, result.State) || !lease.Execute || lease.Token == "" {
		return ErrConflict
	}
	result.Text = ""
	if result.State != "succeeded" {
		answer = nil
	}
	raw, err := json.Marshal(result)
	if err != nil {
		return err
	}
	answerRaw, err := json.Marshal(answer)
	if err != nil {
		return err
	}
	return p.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE analysis_jobs SET state=$4,result=$5,answer=$6,finished_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND state='running' AND lease_token=$3 AND deadline>now()`, tenant, lease.Job.ID, lease.Token, result.State, raw, answerRaw)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrConflict
		}
		return nil
	})
}

func (p *Postgres) CancelAnalysis(ctx context.Context, user model.Principal, id string, queue *river.Client[pgx.Tx], request string) (assistant.Job, error) {
	var job assistant.Job
	if !contract.ValidID(id) {
		return job, pgx.ErrNoRows
	}
	err := p.TenantTx(ctx, user.TenantID, func(tx pgx.Tx) error {
		var riverID *int64
		var state string
		if err := tx.QueryRow(ctx, `SELECT state,river_job_id FROM analysis_jobs WHERE tenant_id=$1 AND id=$2 AND created_by=$3 AND expires_at>now() FOR UPDATE`, user.TenantID, id, user.ID).Scan(&state, &riverID); err != nil {
			return err
		}
		if state == "queued" || state == "running" {
			if riverID == nil || queue == nil {
				return ErrConflict
			}
			if _, err := queue.JobCancelTx(ctx, tx, *riverID); err != nil {
				return err
			}
			if state == "queued" {
				if _, err := tx.Exec(ctx, `UPDATE analysis_jobs SET state='cancelled',cancel_requested=true,result='{"state":"cancelled","code":"cancelled_before_execution","usage":null,"duration_ms":null}',finished_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2`, user.TenantID, id); err != nil {
					return err
				}
			} else {
				if _, err := tx.Exec(ctx, `UPDATE analysis_jobs SET cancel_requested=true WHERE tenant_id=$1 AND id=$2`, user.TenantID, id); err != nil {
					return err
				}
			}
			if err := insertOperationAudit(ctx, tx, user, "analysis.cancel", id, request); err != nil {
				return err
			}
		}
		var err error
		job, err = scanAnalysis(tx.QueryRow(ctx, `SELECT `+analysisJSON+` FROM analysis_jobs WHERE tenant_id=$1 AND id=$2 AND created_by=$3`, user.TenantID, id, user.ID))
		return err
	})
	return job, err
}

func AnalysisInputHash(input assistant.Request) string {
	raw, _ := json.Marshal(input)
	return Hash(string(raw))
}

type AnalysisThread struct {
	ID        string    `json:"id"`
	Title     string    `json:"title"`
	UpdatedAt time.Time `json:"updated_at"`
	LastJobID string    `json:"last_job_id"`
	State     string    `json:"state"`
}
type AnalysisThreadsPage struct {
	Items []AnalysisThread `json:"items"`
	Next  string           `json:"next_cursor"`
}
type AnalysisConversation struct {
	ID    string          `json:"id"`
	Title string          `json:"title"`
	Jobs  []assistant.Job `json:"jobs"`
	Next  string          `json:"next_cursor"`
}

func (p *Postgres) AnalysisThreads(ctx context.Context, user model.Principal, before string) (AnalysisThreadsPage, error) {
	page := AnalysisThreadsPage{Items: []AnalysisThread{}}
	if before != "" && !contract.ValidID(before) {
		return page, assistant.ErrInput
	}
	err := p.TenantTx(ctx, user.TenantID, func(tx pgx.Tx) error {
		if err := recoverAnalysis(ctx, tx, user.TenantID); err != nil {
			return err
		}
		boundary := time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)
		cursor := "~"
		if before != "" {
			cursor = before
			if err := tx.QueryRow(ctx, `SELECT updated_at FROM analysis_threads WHERE tenant_id=$1 AND id=$2 AND created_by=$3 AND expires_at>now()`, user.TenantID, before, user.ID).Scan(&boundary); err != nil {
				return err
			}
		}
		rows, err := tx.Query(ctx, `SELECT t.id,t.title,t.updated_at,j.id,j.state FROM analysis_threads t JOIN LATERAL(SELECT id,state FROM analysis_jobs WHERE tenant_id=t.tenant_id AND thread_id=t.id AND created_by=t.created_by AND expires_at>now() ORDER BY created_at DESC,id DESC LIMIT 1) j ON true WHERE t.tenant_id=$1 AND t.created_by=$2 AND t.expires_at>now() AND (t.updated_at,t.id)<($3,$4) ORDER BY t.updated_at DESC,t.id DESC LIMIT 21`, user.TenantID, user.ID, boundary, cursor)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var item AnalysisThread
			if err := rows.Scan(&item.ID, &item.Title, &item.UpdatedAt, &item.LastJobID, &item.State); err != nil {
				return err
			}
			page.Items = append(page.Items, item)
		}
		if len(page.Items) > 20 {
			page.Items = page.Items[:20]
			page.Next = page.Items[19].ID
		}
		return rows.Err()
	})
	return page, err
}

func (p *Postgres) AnalysisConversation(ctx context.Context, user model.Principal, id, before string) (AnalysisConversation, error) {
	result := AnalysisConversation{ID: id, Jobs: []assistant.Job{}}
	if !contract.ValidID(id) || (before != "" && !contract.ValidID(before)) {
		return result, assistant.ErrInput
	}
	err := p.TenantTx(ctx, user.TenantID, func(tx pgx.Tx) error {
		if err := recoverAnalysis(ctx, tx, user.TenantID); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT title FROM analysis_threads WHERE tenant_id=$1 AND id=$2 AND created_by=$3 AND expires_at>now()`, user.TenantID, id, user.ID).Scan(&result.Title); err != nil {
			return err
		}
		boundary := time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)
		cursor := "~"
		if before != "" {
			cursor = before
			if err := tx.QueryRow(ctx, `SELECT created_at FROM analysis_jobs WHERE tenant_id=$1 AND id=$2 AND thread_id=$3 AND created_by=$4 AND expires_at>now()`, user.TenantID, before, id, user.ID).Scan(&boundary); err != nil {
				return err
			}
		}
		rows, err := tx.Query(ctx, `SELECT `+analysisJSON+` FROM analysis_jobs WHERE tenant_id=$1 AND thread_id=$2 AND created_by=$3 AND expires_at>now() AND (created_at,id)<($4,$5) ORDER BY created_at DESC,id DESC LIMIT 11`, user.TenantID, id, user.ID, boundary, cursor)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			job, err := scanAnalysis(rows)
			if err != nil {
				return err
			}
			result.Jobs = append(result.Jobs, job)
		}
		if len(result.Jobs) > 10 {
			result.Jobs = result.Jobs[:10]
			result.Next = result.Jobs[9].ID
		}
		slices.Reverse(result.Jobs)
		return rows.Err()
	})
	return result, err
}
