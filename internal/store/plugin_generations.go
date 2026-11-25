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
	"github.com/kkx600/StarBeacon/internal/plugingen"
	responseapi "github.com/kkx600/StarBeacon/internal/response"
	"github.com/kkx600/StarBeacon/internal/secrets"
	"github.com/riverqueue/river"
)

const pluginGenerationSummary = `jsonb_build_object('id',id,'provider_id',provider_id,'provider_revision',provider_revision,
 'model',model_name,'device_type',input->>'device_type','abilities',input->'abilities','documentation_sha256',document_sha256,
 'prompt_version',prompt_version,'state',state,'result',result,'created_at',created_at,'finished_at',finished_at)`
const pluginGenerationDetail = pluginGenerationSummary + ` || jsonb_build_object('candidate',candidate)`

func scanPluginGeneration(row pgx.Row) (plugingen.Job, error) {
	var job plugingen.Job
	var raw []byte
	if err := row.Scan(&raw); err != nil {
		return job, err
	}
	err := json.Unmarshal(raw, &job)
	return job, err
}

func recoverPluginGenerations(ctx context.Context, tx pgx.Tx, tenant string) error {
	_, err := tx.Exec(ctx, `UPDATE response_plugin_generations SET
		state=CASE WHEN state='running' THEN 'uncertain' ELSE 'failed' END,
		result=CASE WHEN state='running' THEN '{"state":"uncertain","code":"provider_result_unknown","usage":null,"duration_ms":null}'::jsonb
			ELSE '{"state":"failed","code":"queue_wait_expired","usage":null,"duration_ms":null}'::jsonb END,
		input=input-'documentation',finished_at=clock_timestamp()
		WHERE tenant_id=$1 AND state IN ('queued','running') AND deadline<=now()`, tenant)
	return err
}

func (p *Postgres) CreatePluginGeneration(ctx context.Context, u model.Principal, input plugingen.Request, key string, queue *river.Client[pgx.Tx], vault *secrets.Vault, requestID string) (plugingen.Job, bool, error) {
	var job plugingen.Job
	if _, err := input.Prompt(); err != nil {
		return job, false, err
	}
	if len(key) < 8 || !contract.ValidID(key) {
		return job, false, plugingen.ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	raw, _ := json.Marshal(input)
	hash, document, created := Hash(string(raw)), plugingen.DocumentSHA256(input.Documentation), false
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := configurationActor(ctx, tx, u, true, responseapi.ErrPermission); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, u.TenantID+"/models"); err != nil {
			return err
		}
		var prior, id string
		err := tx.QueryRow(ctx, `SELECT id,request_sha256 FROM response_plugin_generations
			WHERE tenant_id=$1 AND created_by=$2 AND idempotency_hash=$3`, u.TenantID, u.ID, Hash(key)).Scan(&id, &prior)
		if err == nil {
			if prior != hash {
				return ErrConflict
			}
			if err := recoverPluginGenerations(ctx, tx, u.TenantID); err != nil {
				return err
			}
			job, err = scanPluginGeneration(tx.QueryRow(ctx, `SELECT `+pluginGenerationDetail+` FROM response_plugin_generations
				WHERE tenant_id=$1 AND id=$2 AND expires_at>now()`, u.TenantID, id))
			return err
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if queue == nil || queue.Schema() != assistant.QueueSchema || vault == nil {
			return secrets.ErrUnavailable
		}
		var revision int64
		err = tx.QueryRow(ctx, `SELECT revision FROM model_providers WHERE tenant_id=$1 AND id=$2 FOR SHARE`, u.TenantID, input.ProviderID).Scan(&revision)
		if err != nil {
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
		id = RandomID("plugin_gen_")
		written, err := queue.InsertTx(ctx, tx, plugingen.Args{TenantID: u.TenantID, JobID: id}, &river.InsertOpts{Queue: plugingen.Queue, MaxAttempts: 1})
		if err != nil {
			return err
		}
		job, err = scanPluginGeneration(tx.QueryRow(ctx, `INSERT INTO response_plugin_generations
			(tenant_id,id,created_by,provider_id,provider_revision,model_name,input,request_sha256,document_sha256,idempotency_hash,prompt_version,
			 state,result,river_job_id,deadline,expires_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'queued','{"state":"queued","code":"awaiting_execution","usage":null,"duration_ms":null}',
			 $12,now()+interval '15 minutes',now()+make_interval(days=>COALESCE((SELECT days FROM retention_policies WHERE tenant_id=$1 AND category='models'),180)))
			RETURNING `+pluginGenerationDetail, u.TenantID, id, u.ID, input.ProviderID, revision, config.Model, raw, hash, document, Hash(key), plugingen.PromptVersion, written.Job.ID))
		if err != nil {
			return err
		}
		created = true
		return insertOperationAudit(ctx, tx, u, "response.plugin.generation.create", job.ID, requestID)
	})
	return job, created && err == nil, err
}

func (p *Postgres) PluginGeneration(ctx context.Context, u model.Principal, id string) (plugingen.Job, error) {
	var job plugingen.Job
	if !contract.ValidID(id) {
		return job, plugingen.ErrInput
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := recoverPluginGenerations(ctx, tx, u.TenantID); err != nil {
			return err
		}
		var err error
		job, err = scanPluginGeneration(tx.QueryRow(ctx, `SELECT `+pluginGenerationDetail+` FROM response_plugin_generations
			WHERE tenant_id=$1 AND created_by=$2 AND id=$3 AND expires_at>now()`, u.TenantID, u.ID, id))
		return err
	})
	return job, err
}

func (p *Postgres) PluginGenerations(ctx context.Context, u model.Principal, before string, limit int) (plugingen.Page, error) {
	page := plugingen.Page{Items: []plugingen.Job{}}
	if limit < 1 || limit > 100 || before != "" && !contract.ValidID(before) {
		return page, plugingen.ErrInput
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := recoverPluginGenerations(ctx, tx, u.TenantID); err != nil {
			return err
		}
		var at *time.Time
		if before != "" {
			if err := tx.QueryRow(ctx, `SELECT created_at FROM response_plugin_generations WHERE tenant_id=$1 AND created_by=$2 AND id=$3 AND expires_at>now()`,
				u.TenantID, u.ID, before).Scan(&at); err != nil {
				return err
			}
		}
		rows, err := tx.Query(ctx, `SELECT `+pluginGenerationSummary+` FROM response_plugin_generations
			WHERE tenant_id=$1 AND created_by=$2 AND expires_at>now() AND ($3::timestamptz IS NULL OR (created_at,id)<($3,$4))
			ORDER BY created_at DESC,id DESC LIMIT $5`, u.TenantID, u.ID, at, before, limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			item, err := scanPluginGeneration(rows)
			if err != nil {
				return err
			}
			page.Items = append(page.Items, item)
		}
		if len(page.Items) > limit {
			page.Items = page.Items[:limit]
			page.NextCursor = page.Items[len(page.Items)-1].ID
		}
		return rows.Err()
	})
	return page, err
}

type PluginGenerationLease struct {
	Request plugingen.Request
	Config  llm.Config
	Prompt  string
	Token   string
}

func (p *Postgres) StartPluginGeneration(ctx context.Context, args plugingen.Args, riverID int64, vault *secrets.Vault) (PluginGenerationLease, error) {
	var lease PluginGenerationLease
	if !contract.ValidID(args.TenantID) || !contract.ValidID(args.JobID) || riverID < 1 {
		return lease, plugingen.ErrInput
	}
	err := p.TenantTx(ctx, args.TenantID, func(tx pgx.Tx) error {
		if err := recoverPluginGenerations(ctx, tx, args.TenantID); err != nil {
			return err
		}
		var owner, state, provider, hash, docSHA, template string
		var input []byte
		var recorded, version int64
		if err := tx.QueryRow(ctx, `SELECT created_by,state,provider_id,provider_revision,input,request_sha256,document_sha256,prompt_version,river_job_id
			FROM response_plugin_generations WHERE tenant_id=$1 AND id=$2 AND expires_at>now() FOR UPDATE`, args.TenantID, args.JobID).
			Scan(&owner, &state, &provider, &version, &input, &hash, &docSHA, &template, &recorded); err != nil {
			return err
		}
		if recorded != riverID {
			return ErrConflict
		}
		if state != "queued" {
			return nil
		}
		code, err := preparePluginGeneration(ctx, tx, args.TenantID, owner, provider, version, vault, &lease)
		if err != nil {
			return err
		}
		if code == "" {
			if json.Unmarshal(input, &lease.Request) != nil {
				code = "generation_input_invalid"
			} else {
				normalized, _ := json.Marshal(lease.Request)
				prompt, err := lease.Request.Prompt()
				if err != nil || hash != Hash(string(normalized)) || docSHA != plugingen.DocumentSHA256(lease.Request.Documentation) ||
					lease.Request.ProviderID != provider || lease.Request.ProviderRevision != version || template != plugingen.PromptVersion {
					code = "generation_input_invalid"
				} else {
					lease.Prompt = prompt
				}
			}
		}
		if code != "" {
			result, _ := json.Marshal(llm.Result{State: "failed", Code: code})
			_, err := tx.Exec(ctx, `UPDATE response_plugin_generations
				SET state='failed',result=$3,input=input-'documentation',finished_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2`,
				args.TenantID, args.JobID, result)
			return err
		}
		lease.Token = Token()
		_, err = tx.Exec(ctx, `UPDATE response_plugin_generations SET state='running',lease_token=$3,input=input-'documentation',
			deadline=now()+make_interval(secs=>$4),result='{"state":"running","code":"request_in_progress","usage":null,"duration_ms":null}'
			WHERE tenant_id=$1 AND id=$2`, args.TenantID, args.JobID, lease.Token, lease.Config.TimeoutSeconds+15)
		return err
	})
	return lease, err
}

func preparePluginGeneration(ctx context.Context, tx pgx.Tx, tenant, owner, provider string, version int64, vault *secrets.Vault, lease *PluginGenerationLease) (string, error) {
	if err := activePlanOwner(ctx, tx, tenant, owner); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "authorization_revoked", nil
		}
		return "", err
	}
	var head int64
	if err := tx.QueryRow(ctx, `SELECT revision FROM model_providers WHERE tenant_id=$1 AND id=$2 FOR SHARE`, tenant, provider).Scan(&head); err != nil {
		return "", err
	}
	if head != version {
		return "provider_revision_changed", nil
	}
	config, err := modelConfig(ctx, tx, tenant, provider, version, vault)
	if errors.Is(err, secrets.ErrUnavailable) || errors.Is(err, pgx.ErrNoRows) {
		return "provider_config_unavailable", nil
	}
	if err == nil && !config.Enabled {
		return "provider_disabled", nil
	}
	lease.Config = config
	return "", err
}

func (p *Postgres) FinishPluginGeneration(ctx context.Context, args plugingen.Args, lease PluginGenerationLease, result llm.Result, candidate *plugingen.Candidate) error {
	if lease.Token == "" || !slices.Contains([]string{"succeeded", "failed", "refused", "incomplete", "uncertain", "cancelled"}, result.State) {
		return ErrConflict
	}
	var rawCandidate []byte
	if result.State == "succeeded" {
		if candidate == nil || candidate.Validate(lease.Request) != nil {
			return plugingen.ErrOutput
		}
		rawCandidate, _ = json.Marshal(candidate)
	}
	result.Text = ""
	rawResult, _ := json.Marshal(result)
	return p.TenantTx(ctx, args.TenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE response_plugin_generations SET state=$4,result=$5,candidate=$6,finished_at=clock_timestamp()
			WHERE tenant_id=$1 AND id=$2 AND lease_token=$3 AND state='running' AND deadline>now()`,
			args.TenantID, args.JobID, lease.Token, result.State, rawResult, rawCandidate)
		if err == nil && tag.RowsAffected() != 1 {
			return ErrConflict
		}
		return err
	})
}
