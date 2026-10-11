package store

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/assessment"
	"github.com/kkx600/StarBeacon/internal/assistant"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/llm"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/secrets"
	"github.com/kkx600/StarBeacon/internal/triage"
	"github.com/riverqueue/river"
)

const triageJSON = `jsonb_build_object('id',id,'request',request,'state',state,'cancel_requested',cancel_requested,'template',template,'evidence',evidence,'answer',answer,'result',result,'confidence_kind','self_reported','created_at',created_at,'started_at',started_at,'finished_at',finished_at,'expires_at',expires_at)`

func scanTriage(row pgx.Row) (triage.Job, error) {
	var job triage.Job
	var raw []byte
	if err := row.Scan(&raw); err != nil {
		return job, err
	}
	err := json.Unmarshal(raw, &job)
	return job, err
}

func recoverAlertTriage(ctx context.Context, tx pgx.Tx, tenant string) error {
	if _, err := tx.Exec(ctx, `UPDATE alert_triage_jobs SET state='uncertain',result='{"state":"uncertain","code":"provider_result_unknown","usage":null,"duration_ms":null}',finished_at=clock_timestamp() WHERE tenant_id=$1 AND state='running' AND deadline<=now()`, tenant); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `UPDATE alert_triage_jobs SET state='failed',result='{"state":"failed","code":"queue_wait_expired","usage":null,"duration_ms":null}',finished_at=clock_timestamp() WHERE tenant_id=$1 AND state='queued' AND deadline<=now()`, tenant)
	return err
}

func (p *Postgres) ExistingAlertTriage(ctx context.Context, u model.Principal, key, hash string) (triage.Job, error) {
	var job triage.Job
	if !contract.ValidID(key) || !contract.ValidID(u.ID) || u.Role != "admin" || !assessment.ValidDigest(hash) {
		return job, triage.ErrInput
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := recoverAlertTriage(ctx, tx, u.TenantID); err != nil {
			return err
		}
		var prior string
		if err := tx.QueryRow(ctx, `SELECT request_hash FROM alert_triage_jobs WHERE tenant_id=$1 AND created_by=$2 AND idempotency_key_hash=$3 AND expires_at>now()`, u.TenantID, u.ID, Hash(key)).Scan(&prior); err != nil {
			return err
		}
		if prior != hash {
			return ErrConflict
		}
		var err error
		job, err = scanTriage(tx.QueryRow(ctx, `SELECT `+triageJSON+` FROM alert_triage_jobs WHERE tenant_id=$1 AND created_by=$2 AND idempotency_key_hash=$3 AND expires_at>now()`, u.TenantID, u.ID, Hash(key)))
		return err
	})
	return job, err
}

func (p *Postgres) CreateAlertTriage(ctx context.Context, u model.Principal, input triage.Request, key string, evidence triage.Evidence, queue *river.Client[pgx.Tx], vault *secrets.Vault, requestID string) (triage.Job, error) {
	var job triage.Job
	prompt, err := triage.Prompt(input, evidence)
	if err != nil || u.Role != "admin" || !contract.ValidID(u.ID) || !contract.ValidID(key) || queue == nil || queue.Schema() != assistant.QueueSchema {
		return job, triage.ErrInput
	}
	rawInput, _ := json.Marshal(input)
	rawEvidence, _ := json.Marshal(evidence)
	err = p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, u.TenantID+"/models"); err != nil {
			return err
		}
		if err := recoverAlertTriage(ctx, tx, u.TenantID); err != nil {
			return err
		}
		var prior string
		err := tx.QueryRow(ctx, `SELECT request_hash FROM alert_triage_jobs WHERE tenant_id=$1 AND created_by=$2 AND idempotency_key_hash=$3 FOR UPDATE`, u.TenantID, u.ID, Hash(key)).Scan(&prior)
		if err == nil {
			if prior != triage.InputHash(input) {
				return ErrConflict
			}
			job, err = scanTriage(tx.QueryRow(ctx, `SELECT `+triageJSON+` FROM alert_triage_jobs WHERE tenant_id=$1 AND created_by=$2 AND idempotency_key_hash=$3 AND expires_at>now()`, u.TenantID, u.ID, Hash(key)))
			return err
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if err := activePlanOwner(ctx, tx, u.TenantID, u.ID); err != nil {
			return err
		}
		var revision int64
		if err := tx.QueryRow(ctx, `SELECT revision FROM model_providers WHERE tenant_id=$1 AND id=$2 FOR SHARE`, u.TenantID, input.ProviderID).Scan(&revision); err != nil {
			return err
		}
		if revision != input.ProviderRevision {
			return ErrConflict
		}
		config, err := modelConfig(ctx, tx, u.TenantID, input.ProviderID, revision, vault)
		if err != nil {
			return err
		}
		if !config.Enabled {
			return ErrConflict
		}
		if err := checkModelBudget(ctx, tx, u.TenantID, input.ProviderID, config.DailyRequests); err != nil {
			return err
		}
		var count int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM alert_triage_jobs WHERE tenant_id=$1 AND created_at>=date_trunc('day',now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'`, u.TenantID).Scan(&count); err != nil {
			return err
		}
		if count >= 1000 {
			return ErrModelQuota
		}
		job = triage.Job{ID: RandomID("triage_"), Request: input, State: "queued", Template: triage.TemplateVersion, Evidence: evidence, Result: llm.Result{State: "queued", Code: "awaiting_execution"}, ConfidenceKind: "self_reported"}
		rawResult, _ := json.Marshal(job.Result)
		if err := tx.QueryRow(ctx, `INSERT INTO alert_triage_jobs(tenant_id,id,created_by,event_id,raw_sha256,provider_id,provider_revision,request,request_hash,idempotency_key_hash,template,evidence,prompt,prompt_hash,state,result,deadline,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,'queued',$15,now()+interval '15 minutes',now()+make_interval(days=>COALESCE((SELECT days FROM retention_policies WHERE tenant_id=$1 AND category='models'),180))) RETURNING created_at,expires_at`, u.TenantID, job.ID, u.ID, input.EventID, input.RawSHA256, input.ProviderID, revision, rawInput, triage.InputHash(input), Hash(key), job.Template, rawEvidence, prompt, Hash(prompt), rawResult).Scan(&job.CreatedAt, &job.ExpiresAt); err != nil {
			return err
		}
		queued, err := queue.InsertTx(ctx, tx, triage.Args{TenantID: u.TenantID, JobID: job.ID}, &river.InsertOpts{Queue: "alert_triage", MaxAttempts: 1})
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE alert_triage_jobs SET river_job_id=$3 WHERE tenant_id=$1 AND id=$2`, u.TenantID, job.ID, queued.Job.ID); err != nil {
			return err
		}
		return insertOperationAudit(ctx, tx, u, "alerts.triage.create", job.ID, requestID)
	})
	return job, err
}

func (p *Postgres) AlertTriage(ctx context.Context, u model.Principal, id string) (triage.Job, error) {
	var job triage.Job
	if !contract.ValidID(id) || !contract.ValidID(u.ID) || u.Role != "admin" {
		return job, triage.ErrInput
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := recoverAlertTriage(ctx, tx, u.TenantID); err != nil {
			return err
		}
		var err error
		job, err = scanTriage(tx.QueryRow(ctx, `SELECT `+triageJSON+` FROM alert_triage_jobs WHERE tenant_id=$1 AND id=$2 AND created_by=$3 AND expires_at>now()`, u.TenantID, id, u.ID))
		return err
	})
	return job, err
}

type TriageSummary struct {
	ID         string    `json:"id"`
	State      string    `json:"state"`
	ProviderID string    `json:"provider_id"`
	CreatedAt  time.Time `json:"created_at"`
}

type TriagePage struct {
	Items     []TriageSummary `json:"items"`
	Next      string          `json:"next_cursor"`
	Available bool            `json:"model_execution_available"`
}

func (p *Postgres) AlertTriages(ctx context.Context, u model.Principal, event, digest, before string) (TriagePage, error) {
	page := TriagePage{Items: []TriageSummary{}}
	if !contract.ValidID(event) || !assessment.ValidDigest(digest) || !contract.ValidID(u.ID) || u.Role != "admin" || (before != "" && !contract.ValidID(before)) {
		return page, triage.ErrInput
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := recoverAlertTriage(ctx, tx, u.TenantID); err != nil {
			return err
		}
		at, cursor := time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC), "~"
		if before != "" {
			cursor = before
			if err := tx.QueryRow(ctx, `SELECT created_at FROM alert_triage_jobs WHERE tenant_id=$1 AND id=$2 AND created_by=$3 AND event_id=$4 AND raw_sha256=$5 AND expires_at>now()`, u.TenantID, before, u.ID, event, digest).Scan(&at); err != nil {
				return err
			}
		}
		rows, err := tx.Query(ctx, `SELECT id,state,provider_id,created_at FROM alert_triage_jobs WHERE tenant_id=$1 AND created_by=$2 AND event_id=$3 AND raw_sha256=$4 AND expires_at>now() AND (created_at,id)<($5,$6) ORDER BY created_at DESC,id DESC LIMIT 21`, u.TenantID, u.ID, event, digest, at, cursor)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var item TriageSummary
			if err := rows.Scan(&item.ID, &item.State, &item.ProviderID, &item.CreatedAt); err != nil {
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

type TriageLease struct {
	Job     triage.Job
	Config  llm.Config
	Prompt  string
	Token   string
	Execute bool
}

func (p *Postgres) StartAlertTriage(ctx context.Context, args triage.Args, riverID int64, vault *secrets.Vault) (TriageLease, error) {
	var lease TriageLease
	if !contract.ValidID(args.TenantID) || !contract.ValidID(args.JobID) || riverID < 1 {
		return lease, triage.ErrInput
	}
	err := p.TenantTx(ctx, args.TenantID, func(tx pgx.Tx) error {
		if err := recoverAlertTriage(ctx, tx, args.TenantID); err != nil {
			return err
		}
		var raw []byte
		var prompt, promptHash, owner string
		var recorded int64
		if err := tx.QueryRow(ctx, `SELECT `+triageJSON+`,prompt,prompt_hash,created_by,river_job_id FROM alert_triage_jobs WHERE tenant_id=$1 AND id=$2 AND expires_at>now() FOR UPDATE`, args.TenantID, args.JobID).Scan(&raw, &prompt, &promptHash, &owner, &recorded); err != nil {
			return err
		}
		if recorded != riverID {
			return ErrConflict
		}
		if err := json.Unmarshal(raw, &lease.Job); err != nil {
			return err
		}
		if lease.Job.State != "queued" || lease.Job.CancelRequested {
			return nil
		}
		code := ""
		if err := activePlanOwner(ctx, tx, args.TenantID, owner); errors.Is(err, pgx.ErrNoRows) {
			code = "authorization_revoked"
		} else if err != nil {
			return err
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
				code = "provider_config_unavailable"
			} else if err != nil {
				return err
			}
			if code == "" && !lease.Config.Enabled {
				code = "provider_disabled"
			}
		}
		expected, err := triage.Prompt(lease.Job.Request, lease.Job.Evidence)
		if err != nil || expected != prompt || Hash(prompt) != promptHash || lease.Job.Template != triage.TemplateVersion {
			code = "triage_input_invalid"
		}
		if code != "" {
			rawResult, _ := json.Marshal(llm.Result{State: "failed", Code: code})
			_, err := tx.Exec(ctx, `UPDATE alert_triage_jobs SET state='failed',result=$3,finished_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2`, args.TenantID, args.JobID, rawResult)
			return err
		}
		lease.Prompt, lease.Token, lease.Execute = prompt, Token(), true
		lease.Job.State = "running"
		lease.Job.Result = llm.Result{State: "running", Code: "request_in_progress"}
		rawResult, _ := json.Marshal(lease.Job.Result)
		return tx.QueryRow(ctx, `UPDATE alert_triage_jobs SET state='running',lease_token=$3,deadline=now()+make_interval(secs=>$4),started_at=clock_timestamp(),result=$5 WHERE tenant_id=$1 AND id=$2 RETURNING started_at`, args.TenantID, args.JobID, lease.Token, lease.Config.TimeoutSeconds+15, rawResult).Scan(&lease.Job.StartedAt)
	})
	return lease, err
}

func (p *Postgres) FinishAlertTriage(ctx context.Context, tenant string, lease TriageLease, result llm.Result, answer *triage.Answer) error {
	if !slices.Contains([]string{"succeeded", "failed", "refused", "incomplete", "uncertain", "cancelled"}, result.State) || !lease.Execute || lease.Token == "" {
		return ErrConflict
	}
	if result.State == "succeeded" {
		if answer == nil {
			return triage.ErrOutput
		}
		raw, _ := json.Marshal(answer)
		if _, err := triage.DecodeAnswer(string(raw), lease.Job.Evidence); err != nil {
			return err
		}
	} else {
		answer = nil
	}
	result.Text = ""
	rawResult, _ := json.Marshal(result)
	rawAnswer, _ := json.Marshal(answer)
	return p.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE alert_triage_jobs SET state=$4,result=$5,answer=$6,finished_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND state='running' AND lease_token=$3 AND deadline>now()`, tenant, lease.Job.ID, lease.Token, result.State, rawResult, rawAnswer)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrConflict
		}
		return nil
	})
}

func (p *Postgres) CancelAlertTriage(ctx context.Context, u model.Principal, id string, queue *river.Client[pgx.Tx], requestID string) (triage.Job, error) {
	var job triage.Job
	if !contract.ValidID(id) || !contract.ValidID(u.ID) || u.Role != "admin" {
		return job, triage.ErrInput
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		var state string
		var riverID *int64
		if err := tx.QueryRow(ctx, `SELECT state,river_job_id FROM alert_triage_jobs WHERE tenant_id=$1 AND id=$2 AND created_by=$3 AND expires_at>now() FOR UPDATE`, u.TenantID, id, u.ID).Scan(&state, &riverID); err != nil {
			return err
		}
		if state == "queued" || state == "running" {
			if queue == nil || riverID == nil {
				return ErrConflict
			}
			if _, err := queue.JobCancelTx(ctx, tx, *riverID); err != nil {
				return err
			}
			if state == "queued" {
				if _, err := tx.Exec(ctx, `UPDATE alert_triage_jobs SET state='cancelled',cancel_requested=true,result='{"state":"cancelled","code":"cancelled_before_execution","usage":null,"duration_ms":null}',finished_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2`, u.TenantID, id); err != nil {
					return err
				}
			} else if _, err := tx.Exec(ctx, `UPDATE alert_triage_jobs SET cancel_requested=true WHERE tenant_id=$1 AND id=$2`, u.TenantID, id); err != nil {
				return err
			}
			if err := insertOperationAudit(ctx, tx, u, "alerts.triage.cancel", id, requestID); err != nil {
				return err
			}
		}
		var err error
		job, err = scanTriage(tx.QueryRow(ctx, `SELECT `+triageJSON+` FROM alert_triage_jobs WHERE tenant_id=$1 AND id=$2 AND created_by=$3`, u.TenantID, id, u.ID))
		return err
	})
	return job, err
}
