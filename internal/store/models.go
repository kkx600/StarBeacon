package store

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/llm"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/outbound"
	"github.com/kkx600/StarBeacon/internal/secrets"
)

var ErrModelQuota = errors.New("模型验证请求额度不足")

type ModelChange struct {
	ID               string     `json:"id"`
	ExpectedRevision int64      `json:"expected_revision"`
	Config           llm.Config `json:"config"`
	ReplaceKey       bool       `json:"replace_key"`
}

func modelConfig(ctx context.Context, tx pgx.Tx, tenant, id string, revision int64, vault *secrets.Vault) (llm.Config, error) {
	var config llm.Config
	var encrypted string
	if err := tx.QueryRow(ctx, `SELECT ciphertext FROM model_provider_versions WHERE tenant_id=$1 AND provider_id=$2 AND revision=$3`, tenant, id, revision).Scan(&encrypted); err != nil {
		return config, err
	}
	raw, err := vault.Open(tenant, "model", id, revision, encrypted)
	if err != nil {
		return config, err
	}
	if json.Unmarshal(raw, &config) != nil {
		return config, secrets.ErrUnavailable
	}
	return config, nil
}

func (p *Postgres) ModelProviders(ctx context.Context, tenant string) ([]llm.Provider, error) {
	providers := []llm.Provider{}
	err := p.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		// 失联请求只标记结果未知，不重新发起可能已经收费的调用。
		if _, err := tx.Exec(ctx, `UPDATE model_capability_checks SET state='uncertain',result='{"state":"uncertain","code":"provider_result_unknown"}',finished_at=clock_timestamp() WHERE tenant_id=$1 AND state='running' AND deadline<now()`, tenant); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT p.id,p.revision,p.public,p.updated_at,(SELECT jsonb_build_object('id',c.id,'provider_revision',c.provider_revision,'state',c.state,'result',c.result,'created_at',c.created_at,'finished_at',c.finished_at) FROM model_capability_checks c WHERE c.tenant_id=p.tenant_id AND c.provider_id=p.id AND c.expires_at>now() ORDER BY c.created_at DESC,c.id DESC LIMIT 1) FROM model_providers p WHERE p.tenant_id=$1 ORDER BY p.id LIMIT 50`, tenant)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var provider llm.Provider
			var public, check []byte
			var id string
			var revision int64
			var updated time.Time
			if err := rows.Scan(&id, &revision, &public, &updated, &check); err != nil {
				return err
			}
			if err := json.Unmarshal(public, &provider); err != nil {
				return err
			}
			provider.ID, provider.Revision, provider.UpdatedAt = id, revision, updated
			if len(check) > 0 {
				if err := json.Unmarshal(check, &provider.Check); err != nil {
					return err
				}
			}
			providers = append(providers, provider)
		}
		return rows.Err()
	})
	return providers, err
}

func (p *Postgres) SaveModelProvider(ctx context.Context, user model.Principal, change ModelChange, vault *secrets.Vault, policy outbound.Policy, request string) (llm.Provider, error) {
	var result llm.Provider
	if !contract.ValidID(change.ID) || change.ExpectedRevision < 0 {
		return result, ErrConflict
	}
	err := p.TenantTx(ctx, user.TenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, user.TenantID+"/models"); err != nil {
			return err
		}
		var revision int64
		err := tx.QueryRow(ctx, `SELECT revision FROM model_providers WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, user.TenantID, change.ID).Scan(&revision)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if change.ExpectedRevision != revision {
			return ErrConflict
		}
		if revision == 0 {
			var count int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM model_providers WHERE tenant_id=$1`, user.TenantID).Scan(&count); err != nil {
				return err
			}
			if count >= 50 {
				return ErrModelQuota
			}
		} else if !change.ReplaceKey {
			if change.Config.APIKey != "" {
				return llm.ErrConfig
			}
			prior, err := modelConfig(ctx, tx, user.TenantID, change.ID, revision, vault)
			if err != nil {
				return err
			}
			// 旧凭据仅能保留在同一连接目标与协议，避免把旧 key 发往新地址。
			if prior.BaseURL != change.Config.BaseURL || prior.Kind != change.Config.Kind {
				return llm.ErrConfig
			}
			change.Config.APIKey = prior.APIKey
		}
		if err := change.Config.Validate(policy); err != nil {
			return err
		}
		raw, err := llm.Encode(change.Config)
		if err != nil {
			return err
		}
		encrypted, err := vault.Seal(user.TenantID, "model", change.ID, revision+1, raw)
		if err != nil {
			return err
		}
		result = change.Config.Public()
		result.ID, result.Revision = change.ID, revision+1
		public, err := json.Marshal(result)
		if err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO model_providers(tenant_id,id,revision,public) VALUES($1,$2,$3,$4) ON CONFLICT(tenant_id,id) DO UPDATE SET revision=EXCLUDED.revision,public=EXCLUDED.public,updated_at=clock_timestamp() RETURNING updated_at`, user.TenantID, result.ID, result.Revision, public).Scan(&result.UpdatedAt); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO model_provider_versions(tenant_id,provider_id,revision,ciphertext,expires_at) VALUES($1,$2,$3,$4,now()+make_interval(days=>COALESCE((SELECT days FROM retention_policies WHERE tenant_id=$1 AND category='models'),180)))`, user.TenantID, result.ID, result.Revision, encrypted); err != nil {
			return err
		}
		return insertOperationAudit(ctx, tx, user, "models.provider.save", change.ID, request)
	})
	return result, err
}

type ModelCheckLease struct {
	llm.Check
	ProviderID string
	Config     llm.Config
	Execute    bool
}

func (p *Postgres) StartModelCheck(ctx context.Context, user model.Principal, id, key string, revision int64, vault *secrets.Vault, request string) (ModelCheckLease, error) {
	var lease ModelCheckLease
	if !contract.ValidID(id) || !contract.ValidID(key) || revision < 1 {
		return lease, ErrConflict
	}
	err := p.TenantTx(ctx, user.TenantID, func(tx pgx.Tx) error {
		// 同租户验证共享预算锁；不同实例不能同时越过租户并发上限。
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, user.TenantID+"/models"); err != nil {
			return err
		}
		var current int64
		if err := tx.QueryRow(ctx, `SELECT revision FROM model_providers WHERE tenant_id=$1 AND id=$2 FOR SHARE`, user.TenantID, id).Scan(&current); err != nil {
			return err
		}
		if current != revision {
			return ErrConflict
		}
		lease.ProviderID = id
		if _, err := tx.Exec(ctx, `UPDATE model_capability_checks SET state='uncertain',result='{"state":"uncertain","code":"provider_result_unknown"}',finished_at=clock_timestamp() WHERE tenant_id=$1 AND provider_id=$2 AND state='running' AND deadline<=now()`, user.TenantID, id); err != nil {
			return err
		}
		var existing []byte
		err := tx.QueryRow(ctx, `SELECT jsonb_build_object('id',id,'provider_revision',provider_revision,'state',state,'result',result,'created_at',created_at,'finished_at',finished_at) FROM model_capability_checks WHERE tenant_id=$1 AND provider_id=$2 AND created_by=$3 AND idempotency_key_hash=$4 AND expires_at>now()`, user.TenantID, id, user.ID, Hash(key)).Scan(&existing)
		if err == nil {
			if err := json.Unmarshal(existing, &lease.Check); err != nil {
				return err
			}
			if lease.ProviderRevision != revision {
				return ErrConflict
			}
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		config, err := modelConfig(ctx, tx, user.TenantID, id, revision, vault)
		if err != nil {
			return err
		}
		if !config.Enabled {
			return ErrConflict
		}
		if err := checkModelBudget(ctx, tx, user.TenantID, id, config.DailyRequests); err != nil {
			return err
		}
		lease.Config, lease.Execute = config, true
		lease.Check = llm.Check{ID: RandomID("mcheck_"), ProviderRevision: revision, State: "running"}
		if err := tx.QueryRow(ctx, `INSERT INTO model_capability_checks(tenant_id,id,provider_id,provider_revision,created_by,idempotency_key_hash,state,deadline,expires_at) VALUES($1,$2,$3,$4,$5,$6,'running',now()+interval '20 seconds',now()+make_interval(days=>COALESCE((SELECT days FROM retention_policies WHERE tenant_id=$1 AND category='models'),180))) RETURNING created_at`, user.TenantID, lease.ID, id, revision, user.ID, Hash(key)).Scan(&lease.CreatedAt); err != nil {
			return err
		}
		return insertOperationAudit(ctx, tx, user, "models.provider.test", id+"/"+lease.ID, request)
	})
	return lease, err
}

func (p *Postgres) FinishModelCheck(ctx context.Context, tenant string, lease ModelCheckLease, result llm.Result) (llm.Check, error) {
	check := lease.Check
	if !slices.Contains([]string{"succeeded", "failed", "refused", "incomplete", "uncertain"}, result.State) {
		return check, ErrConflict
	}
	// 连通性验证不保留生成正文，不能以此结果宣称通过安全领域评测。
	result.Text = ""
	raw, err := json.Marshal(result)
	if err != nil {
		return check, err
	}
	err = p.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `UPDATE model_capability_checks SET state=$4,result=$5,finished_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND provider_revision=$3 AND state='running' RETURNING finished_at`, tenant, lease.ID, lease.ProviderRevision, result.State, raw).Scan(&check.FinishedAt)
	})
	check.State, check.Result = result.State, result
	return check, err
}
