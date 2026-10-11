package store

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/assistant"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/llm"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/replay"
	"github.com/kkx600/StarBeacon/internal/rulegen"
	"github.com/kkx600/StarBeacon/internal/secrets"
	"github.com/riverqueue/river"
)

const generationJSON = `jsonb_build_object('id',id,'request',request,'state',state,'cancel_requested',cancel_requested,'template',template,'evidence',evidence,'sids',assigned_sids,'candidates',candidates,'result',result,'created_at',created_at,'started_at',started_at,'finished_at',finished_at,'expires_at',expires_at)`

func scanGeneration(row pgx.Row) (rulegen.Job, error) {
	var job rulegen.Job
	var raw []byte
	if err := row.Scan(&raw); err != nil {
		return job, err
	}
	err := json.Unmarshal(raw, &job)
	return job, err
}

// 已可能发送的模型请求恢复为未知状态，不能通过任务救援再次计费。
func recoverRuleGeneration(ctx context.Context, tx pgx.Tx, tenant string) error {
	if _, err := tx.Exec(ctx, `UPDATE rule_generation_jobs SET state='uncertain',result='{"state":"uncertain","code":"provider_result_unknown","usage":null,"duration_ms":null}',finished_at=clock_timestamp() WHERE tenant_id=$1 AND state='running' AND deadline<=now()`, tenant); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `UPDATE rule_generation_jobs SET state='failed',result='{"state":"failed","code":"queue_wait_expired","usage":null,"duration_ms":null}',finished_at=clock_timestamp() WHERE tenant_id=$1 AND state='queued' AND deadline<=now()`, tenant)
	return err
}

func (p *Postgres) ExistingRuleGeneration(ctx context.Context, u model.Principal, key, hash string) (rulegen.Job, error) {
	var job rulegen.Job
	if !contract.ValidID(key) || !rulegen.ValidSHA(hash) {
		return job, rulegen.ErrInput
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := recoverRuleGeneration(ctx, tx, u.TenantID); err != nil {
			return err
		}
		var prior string
		if err := tx.QueryRow(ctx, `SELECT request_hash FROM rule_generation_jobs WHERE tenant_id=$1 AND created_by=$2 AND idempotency_key_hash=$3 AND expires_at>now()`, u.TenantID, u.ID, Hash(key)).Scan(&prior); err != nil {
			return err
		}
		if prior != hash {
			return ErrConflict
		}
		var err error
		job, err = scanGeneration(tx.QueryRow(ctx, `SELECT `+generationJSON+` FROM rule_generation_jobs WHERE tenant_id=$1 AND created_by=$2 AND idempotency_key_hash=$3 AND expires_at>now()`, u.TenantID, u.ID, Hash(key)))
		return err
	})
	return job, err
}

func allocateGenerationSIDs(ctx context.Context, tx pgx.Tx, tenant, job string, count int) ([]uint32, error) {
	if _, err := tx.Exec(ctx, `INSERT INTO rule_sid_state(tenant_id) VALUES($1) ON CONFLICT DO NOTHING`, tenant); err != nil {
		return nil, err
	}
	var cursor uint32
	if err := tx.QueryRow(ctx, `SELECT next_sid FROM rule_sid_state WHERE tenant_id=$1 FOR UPDATE`, tenant).Scan(&cursor); err != nil {
		return nil, err
	}
	sids := []uint32{}
	for len(sids) < count {
		if cursor > rulegen.MaxSID {
			return nil, rulegen.ErrSID
		}
		var registered uint32
		err := tx.QueryRow(ctx, `INSERT INTO rule_sid_registry(tenant_id,sid,package_id,generation_id) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING RETURNING sid`, tenant, cursor, rulegen.PackageID(job, cursor), job).Scan(&registered)
		if errors.Is(err, pgx.ErrNoRows) {
			// 按索引顺序跳过连续占用区，不对每个已占用 SID 执行一次数据库往返。
			err = tx.QueryRow(ctx, `SELECT r.sid+1 FROM rule_sid_registry r WHERE r.tenant_id=$1 AND r.sid>=$2 AND r.sid<$3 AND NOT EXISTS(SELECT 1 FROM rule_sid_registry n WHERE n.tenant_id=$1 AND n.sid=r.sid+1) ORDER BY r.sid LIMIT 1`, tenant, cursor, rulegen.MaxSID).Scan(&cursor)
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, rulegen.ErrSID
			}
			if err != nil {
				return nil, err
			}
			continue
		}
		if err != nil {
			return nil, err
		}
		sids = append(sids, registered)
		cursor++
	}
	_, err := tx.Exec(ctx, `UPDATE rule_sid_state SET next_sid=$2 WHERE tenant_id=$1`, tenant, cursor)
	return sids, err
}

func (p *Postgres) CreateRuleGeneration(ctx context.Context, u model.Principal, input rulegen.Request, key string, evidence rulegen.Evidence, queue *river.Client[pgx.Tx], vault *secrets.Vault, requestID string) (rulegen.Job, error) {
	var job rulegen.Job
	if input.Validate() != nil || u.Role != "admin" || !contract.ValidID(key) || queue == nil || queue.Schema() != assistant.QueueSchema {
		return job, rulegen.ErrInput
	}
	sealed, err := rulegen.Seal(evidence)
	if err != nil || sealed.SHA256 != evidence.SHA256 {
		return job, rulegen.ErrInput
	}
	rawInput, _ := json.Marshal(input)
	err = p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, u.TenantID+"/models"); err != nil {
			return err
		}
		if err := recoverRuleGeneration(ctx, tx, u.TenantID); err != nil {
			return err
		}
		var prior string
		err := tx.QueryRow(ctx, `SELECT request_hash FROM rule_generation_jobs WHERE tenant_id=$1 AND created_by=$2 AND idempotency_key_hash=$3 FOR UPDATE`, u.TenantID, u.ID, Hash(key)).Scan(&prior)
		if err == nil {
			if prior != rulegen.InputHash(input) {
				return ErrConflict
			}
			job, err = scanGeneration(tx.QueryRow(ctx, `SELECT `+generationJSON+` FROM rule_generation_jobs WHERE tenant_id=$1 AND created_by=$2 AND idempotency_key_hash=$3 AND expires_at>now()`, u.TenantID, u.ID, Hash(key)))
			return err
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if err := activePlanOwner(ctx, tx, u.TenantID, u.ID); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrConflict
			}
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
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM rule_generation_jobs WHERE tenant_id=$1 AND created_at>=date_trunc('day',now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'`, u.TenantID).Scan(&count); err != nil {
			return err
		}
		if count >= 1000 {
			return ErrModelQuota
		}
		if input.SampleID != "" {
			sample, err := scanSample(tx.QueryRow(ctx, `SELECT id,name,size,sha256,format,created_at,expires_at,origin FROM replay_samples WHERE tenant_id=$1 AND id=$2 AND state='ready' AND expires_at>now() FOR SHARE`, u.TenantID, input.SampleID))
			if err != nil {
				return err
			}
			if evidence.Sample == nil || sample.SHA256 != input.SampleSHA256 || sample.SHA256 != evidence.Sample.SHA256 || sample.Size != evidence.Sample.Size || !replay.SameOrigin(sample.Origin, evidence.Sample.Origin) {
				return ErrConflict
			}
		}
		job.ID = RandomID("gen_")
		job.SIDs, err = allocateGenerationSIDs(ctx, tx, u.TenantID, job.ID, input.CandidateCount)
		if err != nil {
			return err
		}
		prompt, err := rulegen.Prompt(input, evidence, job.SIDs)
		if err != nil {
			return err
		}
		job.Request, job.Evidence, job.Template, job.State, job.Candidates = input, evidence, rulegen.TemplateVersion, "queued", []rulegen.Candidate{}
		job.Result = llm.Result{State: "queued", Code: "awaiting_execution"}
		rawEvidence, _ := json.Marshal(evidence)
		rawSIDs, _ := json.Marshal(job.SIDs)
		rawResult, _ := json.Marshal(job.Result)
		if err := tx.QueryRow(ctx, `INSERT INTO rule_generation_jobs(tenant_id,id,created_by,provider_id,provider_revision,sample_id,sample_sha256,request,request_hash,idempotency_key_hash,template,evidence,assigned_sids,prompt,prompt_hash,state,result,deadline,expires_at) VALUES($1,$2,$3,$4,$5,NULLIF($6,''),NULLIF($7,''),$8,$9,$10,$11,$12,$13,$14,$15,'queued',$16,now()+interval '15 minutes',now()+make_interval(days=>COALESCE((SELECT days FROM retention_policies WHERE tenant_id=$1 AND category='models'),180))) RETURNING created_at,expires_at`, u.TenantID, job.ID, u.ID, input.ProviderID, revision, input.SampleID, input.SampleSHA256, rawInput, rulegen.InputHash(input), Hash(key), job.Template, rawEvidence, rawSIDs, prompt, Hash(prompt), rawResult).Scan(&job.CreatedAt, &job.ExpiresAt); err != nil {
			return err
		}
		queued, err := queue.InsertTx(ctx, tx, rulegen.Args{TenantID: u.TenantID, JobID: job.ID}, &river.InsertOpts{Queue: "rule_generation", MaxAttempts: 1})
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE rule_generation_jobs SET river_job_id=$3 WHERE tenant_id=$1 AND id=$2`, u.TenantID, job.ID, queued.Job.ID); err != nil {
			return err
		}
		return insertOperationAudit(ctx, tx, u, "rule.generation.create", job.ID, requestID)
	})
	return job, err
}

func (p *Postgres) RuleGeneration(ctx context.Context, u model.Principal, id string) (rulegen.Job, error) {
	var job rulegen.Job
	if !contract.ValidID(id) {
		return job, pgx.ErrNoRows
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := recoverRuleGeneration(ctx, tx, u.TenantID); err != nil {
			return err
		}
		var err error
		job, err = scanGeneration(tx.QueryRow(ctx, `SELECT `+generationJSON+` FROM rule_generation_jobs WHERE tenant_id=$1 AND id=$2 AND created_by=$3 AND expires_at>now()`, u.TenantID, id, u.ID))
		return err
	})
	return job, err
}

type GenerationSummary struct {
	ID              string    `json:"id"`
	Title           string    `json:"title"`
	Source          string    `json:"source"`
	State           string    `json:"state"`
	ProviderID      string    `json:"provider_id"`
	CreatedAt       time.Time `json:"created_at"`
	CancelRequested bool      `json:"cancel_requested"`
}
type GenerationPage struct {
	Items []GenerationSummary `json:"items"`
	Next  string              `json:"next_cursor"`
}

func (p *Postgres) RuleGenerations(ctx context.Context, u model.Principal, before string) (GenerationPage, error) {
	page := GenerationPage{Items: []GenerationSummary{}}
	if before != "" && !contract.ValidID(before) {
		return page, rulegen.ErrInput
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := recoverRuleGeneration(ctx, tx, u.TenantID); err != nil {
			return err
		}
		at := time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)
		cursor := "~"
		if before != "" {
			cursor = before
			if err := tx.QueryRow(ctx, `SELECT created_at FROM rule_generation_jobs WHERE tenant_id=$1 AND id=$2 AND created_by=$3 AND expires_at>now()`, u.TenantID, before, u.ID).Scan(&at); err != nil {
				return err
			}
		}
		rows, err := tx.Query(ctx, `SELECT id,left(request->>'description',80),request->>'source',state,provider_id,created_at,cancel_requested FROM rule_generation_jobs WHERE tenant_id=$1 AND created_by=$2 AND expires_at>now() AND (created_at,id)<($3,$4) ORDER BY created_at DESC,id DESC LIMIT 21`, u.TenantID, u.ID, at, cursor)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var v GenerationSummary
			if err := rows.Scan(&v.ID, &v.Title, &v.Source, &v.State, &v.ProviderID, &v.CreatedAt, &v.CancelRequested); err != nil {
				return err
			}
			page.Items = append(page.Items, v)
		}
		if len(page.Items) > 20 {
			page.Items = page.Items[:20]
			page.Next = page.Items[19].ID
		}
		return rows.Err()
	})
	return page, err
}

type GenerationLease struct {
	Job     rulegen.Job
	Config  llm.Config
	Prompt  string
	Token   string
	Execute bool
}

func (p *Postgres) StartRuleGeneration(ctx context.Context, args rulegen.Args, riverID int64, vault *secrets.Vault) (GenerationLease, error) {
	var lease GenerationLease
	if !contract.ValidID(args.TenantID) || !contract.ValidID(args.JobID) || riverID < 1 {
		return lease, rulegen.ErrInput
	}
	err := p.TenantTx(ctx, args.TenantID, func(tx pgx.Tx) error {
		if err := recoverRuleGeneration(ctx, tx, args.TenantID); err != nil {
			return err
		}
		var raw []byte
		var prompt, promptHash, owner string
		var recorded int64
		if err := tx.QueryRow(ctx, `SELECT `+generationJSON+`,prompt,prompt_hash,created_by,river_job_id FROM rule_generation_jobs WHERE tenant_id=$1 AND id=$2 AND expires_at>now() FOR UPDATE`, args.TenantID, args.JobID).Scan(&raw, &prompt, &promptHash, &owner, &recorded); err != nil {
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
		if lease.Job.Request.SampleID != "" {
			var valid bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM replay_samples WHERE tenant_id=$1 AND id=$2 AND state='ready' AND sha256=$3 AND expires_at>now())`, args.TenantID, lease.Job.Request.SampleID, lease.Job.Request.SampleSHA256).Scan(&valid); err != nil {
				return err
			}
			if !valid {
				code = "sample_unavailable"
			}
		}
		expected, err := rulegen.Prompt(lease.Job.Request, lease.Job.Evidence, lease.Job.SIDs)
		if err != nil || expected != prompt || Hash(prompt) != promptHash || lease.Job.Template != rulegen.TemplateVersion {
			code = "generation_input_invalid"
		}
		if code != "" {
			result, _ := json.Marshal(llm.Result{State: "failed", Code: code})
			_, err := tx.Exec(ctx, `UPDATE rule_generation_jobs SET state='failed',result=$3,finished_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2`, args.TenantID, args.JobID, result)
			return err
		}
		lease.Prompt, lease.Token, lease.Execute = prompt, Token(), true
		lease.Job.State = "running"
		lease.Job.Result = llm.Result{State: "running", Code: "request_in_progress"}
		rawResult, _ := json.Marshal(lease.Job.Result)
		return tx.QueryRow(ctx, `UPDATE rule_generation_jobs SET state='running',lease_token=$3,deadline=now()+make_interval(secs=>$4),started_at=clock_timestamp(),result=$5 WHERE tenant_id=$1 AND id=$2 RETURNING started_at`, args.TenantID, args.JobID, lease.Token, lease.Config.TimeoutSeconds+15, rawResult).Scan(&lease.Job.StartedAt)
	})
	return lease, err
}

func (p *Postgres) FinishRuleGeneration(ctx context.Context, tenant string, lease GenerationLease, result llm.Result, candidates []rulegen.Candidate) error {
	if !slices.Contains([]string{"succeeded", "failed", "refused", "incomplete", "uncertain", "cancelled"}, result.State) || !lease.Execute || lease.Token == "" {
		return ErrConflict
	}
	if result.State == "succeeded" {
		if rulegen.ValidateCandidates(candidates, lease.Job.Evidence, lease.Job.SIDs) != nil {
			return rulegen.ErrOutput
		}
		for _, c := range candidates {
			if c.PackageID != rulegen.PackageID(lease.Job.ID, c.SID) || ValidateRules(c.Rule) != nil {
				return rulegen.ErrOutput
			}
		}
	} else {
		candidates = []rulegen.Candidate{}
	}
	result.Text = ""
	rawResult, _ := json.Marshal(result)
	rawCandidates, _ := json.Marshal(candidates)
	return p.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE rule_generation_jobs SET state=$4,result=$5,candidates=$6,finished_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND state='running' AND lease_token=$3 AND deadline>now()`, tenant, lease.Job.ID, lease.Token, result.State, rawResult, rawCandidates)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrConflict
		}
		return nil
	})
}

func (p *Postgres) CancelRuleGeneration(ctx context.Context, u model.Principal, id string, queue *river.Client[pgx.Tx], request string) (rulegen.Job, error) {
	var job rulegen.Job
	if !contract.ValidID(id) {
		return job, pgx.ErrNoRows
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		var state string
		var riverID *int64
		if err := tx.QueryRow(ctx, `SELECT state,river_job_id FROM rule_generation_jobs WHERE tenant_id=$1 AND id=$2 AND created_by=$3 AND expires_at>now() FOR UPDATE`, u.TenantID, id, u.ID).Scan(&state, &riverID); err != nil {
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
				if _, err := tx.Exec(ctx, `UPDATE rule_generation_jobs SET state='cancelled',cancel_requested=true,result='{"state":"cancelled","code":"cancelled_before_execution","usage":null,"duration_ms":null}',finished_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2`, u.TenantID, id); err != nil {
					return err
				}
			} else {
				if _, err := tx.Exec(ctx, `UPDATE rule_generation_jobs SET cancel_requested=true WHERE tenant_id=$1 AND id=$2`, u.TenantID, id); err != nil {
					return err
				}
			}
			if err := insertOperationAudit(ctx, tx, u, "rule.generation.cancel", id, request); err != nil {
				return err
			}
		}
		var err error
		job, err = scanGeneration(tx.QueryRow(ctx, `SELECT `+generationJSON+` FROM rule_generation_jobs WHERE tenant_id=$1 AND id=$2 AND created_by=$3`, u.TenantID, id, u.ID))
		return err
	})
	return job, err
}
