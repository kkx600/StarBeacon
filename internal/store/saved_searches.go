package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/savedsearch"
)

const savedSearchColumns = `tenant_id,id,generation_id,owner_id,revision,name,description,visibility,active,definition,created_at,updated_at,expires_at`

func savedSearchUser(ctx context.Context, tx pgx.Tx, u model.Principal) error {
	if !contract.ValidID(u.ID) || !contract.ValidID(u.TenantID) || (u.Role != "admin" && u.Role != "viewer") {
		return savedsearch.ErrPermission
	}
	// 与账号停用、密码恢复及降权互斥；查询配置不能借用已经撤回的权限。
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared(hashtextextended($1,0))`, u.TenantID+"/users"); err != nil {
		return err
	}
	var active, tenantActive bool
	var role string
	var revision int64
	if err := tx.QueryRow(ctx, `SELECT u.active,u.role,u.revision,t.active FROM users u JOIN tenants t ON t.id=u.tenant_id WHERE u.tenant_id=$1 AND u.id=$2`, u.TenantID, u.ID).Scan(&active, &role, &revision, &tenantActive); err != nil {
		return err
	}
	if !active || !tenantActive || role != u.Role || u.CredentialRevision > 0 && revision != u.CredentialRevision {
		return pgx.ErrNoRows
	}
	return nil
}

func ValidateSavedDefinition(d savedsearch.Definition) error {
	q, err := d.Query(time.Now().UTC())
	if err != nil {
		return err
	}
	if d.Dataset == "alerts" {
		err = ValidateSearch(&q.SearchRequest)
	} else {
		err = ValidateTrafficSearch(&q)
	}
	if err != nil {
		return savedsearch.ErrInput
	}
	return nil
}

func readSavedSearch(row interface{ Scan(...any) error }) (savedsearch.Record, error) {
	var record savedsearch.Record
	var raw json.RawMessage
	err := row.Scan(&record.TenantID, &record.ID, &record.GenerationID, &record.OwnerID, &record.Revision, &record.Name, &record.Description, &record.Visibility, &record.Active, &raw, &record.CreatedAt, &record.UpdatedAt, &record.ExpiresAt)
	if err != nil {
		return record, err
	}
	if json.Unmarshal(raw, &record.Definition) != nil || record.Validate() != nil {
		return record, errors.New("保存查询记录不完整")
	}
	return record, nil
}

func (p *Postgres) SavedSearches(ctx context.Context, u model.Principal, q savedsearch.ListQuery) (savedsearch.Page, error) {
	page := savedsearch.Page{Items: []savedsearch.Record{}}
	if q.Validate() != nil {
		return page, savedsearch.ErrInput
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := savedSearchUser(ctx, tx, u); err != nil {
			return err
		}
		pattern := "%" + strings.NewReplacer("!", "!!", "%", "!%", "_", "!_").Replace(q.Keyword) + "%"
		rows, err := tx.Query(ctx, `SELECT `+savedSearchColumns+` FROM saved_searches WHERE tenant_id=$1 AND id>$2 AND (owner_id=$3 OR visibility='team') AND ($4='' OR dataset=$4) AND ($5='' OR visibility=$5) AND ($6='' OR active=($6='true')) AND (expires_at IS NULL OR expires_at>now()) AND name ILIKE $7 ESCAPE '!' ORDER BY id LIMIT $8`, u.TenantID, q.Cursor, u.ID, q.Dataset, q.Visibility, q.Active, pattern, q.Limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			record, err := readSavedSearch(rows)
			if err != nil {
				return err
			}
			page.Items = append(page.Items, record)
		}
		return rows.Err()
	})
	if len(page.Items) > q.Limit {
		page.NextCursor = page.Items[q.Limit-1].ID
		page.Items = page.Items[:q.Limit]
	}
	return page, err
}

func (p *Postgres) SavedSearch(ctx context.Context, u model.Principal, id string) (savedsearch.Record, error) {
	var result savedsearch.Record
	if !contract.ValidID(id) {
		return result, pgx.ErrNoRows
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := savedSearchUser(ctx, tx, u); err != nil {
			return err
		}
		var err error
		result, err = readSavedSearch(tx.QueryRow(ctx, `SELECT `+savedSearchColumns+` FROM saved_searches WHERE tenant_id=$1 AND id=$2 AND (owner_id=$3 OR visibility='team') AND (expires_at IS NULL OR expires_at>now())`, u.TenantID, id, u.ID))
		return err
	})
	return result, err
}

func (p *Postgres) SaveSavedSearch(ctx context.Context, u model.Principal, key string, c savedsearch.Change) (savedsearch.Record, error) {
	var result savedsearch.Record
	if err := c.Validate(); err != nil {
		return result, err
	}
	if !contract.ValidID(key) {
		return result, savedsearch.ErrInput
	}
	if err := ValidateSavedDefinition(c.Definition); err != nil {
		return result, err
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, u.TenantID+"/saved-searches"); err != nil {
			return err
		}
		if err := savedSearchUser(ctx, tx, u); err != nil {
			return err
		}
		if c.Visibility == "team" && u.Role != "admin" {
			return savedsearch.ErrPermission
		}
		var previousHash string
		var raw json.RawMessage
		var expires time.Time
		err := tx.QueryRow(ctx, `SELECT input_hash,record,expires_at FROM saved_search_changes WHERE tenant_id=$1 AND created_by=$2 AND key_hash=$3`, u.TenantID, u.ID, Hash(key)).Scan(&previousHash, &raw, &expires)
		if err == nil {
			if previousHash != savedsearch.InputHash(c) || !expires.After(time.Now()) {
				return ErrConflict
			}
			if json.Unmarshal(raw, &result) != nil || result.Validate() != nil {
				return errors.New("保存查询原提交回执不完整")
			}
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		current, err := readSavedSearch(tx.QueryRow(ctx, `SELECT `+savedSearchColumns+` FROM saved_searches WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, u.TenantID, c.ID))
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if errors.Is(err, pgx.ErrNoRows) && c.ExpectedRevision > 0 {
			return pgx.ErrNoRows
		}
		if err == nil && current.OwnerID != u.ID {
			// 私有对象与不可访问对象使用同一结果；团队对象只允许原所有者修改。
			if current.Visibility == "team" {
				return savedsearch.ErrPermission
			}
			return pgx.ErrNoRows
		}
		if current.Revision != c.ExpectedRevision || current.GenerationID != c.ExpectedGenerationID {
			return ErrConflict
		}
		if current.Visibility == "team" && u.Role != "admin" {
			return savedsearch.ErrPermission
		}
		if current.ExpiresAt != nil && !current.ExpiresAt.After(time.Now()) {
			return pgx.ErrNoRows
		}
		if current.Revision > 0 {
			prior := savedsearch.Change{ID: current.ID, ExpectedRevision: c.ExpectedRevision, ExpectedGenerationID: c.ExpectedGenerationID, Name: current.Name, Description: current.Description, Visibility: current.Visibility, Active: &current.Active, Definition: current.Definition}
			if savedsearch.InputHash(prior) == savedsearch.InputHash(c) {
				return savedsearch.ErrInput
			}
		} else {
			var owned, total int
			if err := tx.QueryRow(ctx, `SELECT count(*) FILTER(WHERE owner_id=$2),count(*) FROM saved_searches WHERE tenant_id=$1`, u.TenantID, u.ID).Scan(&owned, &total); err != nil {
				return err
			}
			if owned >= savedsearch.MaxPerOwner || total >= savedsearch.MaxPerTenant {
				return savedsearch.ErrQuota
			}
			current.GenerationID = RandomID("querygen_")
		}
		var count int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM saved_search_changes WHERE tenant_id=$1 AND created_at>now()-interval '24 hours'`, u.TenantID).Scan(&count); err != nil {
			return err
		}
		if count >= savedsearch.MaxDailyChanges {
			return savedsearch.ErrQuota
		}
		definition, err := json.Marshal(c.Definition)
		if err != nil {
			return err
		}
		result, err = readSavedSearch(tx.QueryRow(ctx, `INSERT INTO saved_searches(tenant_id,id,generation_id,owner_id,revision,name,description,visibility,dataset,active,definition,expires_at) VALUES($1,$2,$3,$4,1,$5,$6,$7,$8,$9,$10,CASE WHEN $9 THEN NULL ELSE now()+make_interval(days=>COALESCE((SELECT days FROM retention_policies WHERE tenant_id=$1 AND category='operations'),180)) END) ON CONFLICT(tenant_id,id) DO UPDATE SET revision=saved_searches.revision+1,name=EXCLUDED.name,description=EXCLUDED.description,visibility=EXCLUDED.visibility,dataset=EXCLUDED.dataset,active=EXCLUDED.active,definition=EXCLUDED.definition,updated_at=now(),expires_at=EXCLUDED.expires_at RETURNING `+savedSearchColumns, u.TenantID, c.ID, current.GenerationID, u.ID, c.Name, c.Description, c.Visibility, c.Definition.Dataset, *c.Active, definition))
		if err != nil {
			return err
		}
		if err := insertOperationAudit(ctx, tx, u, "search.saved.save", c.ID, model.RequestMetadataFrom(ctx).RequestID); err != nil {
			return err
		}
		raw, err = json.Marshal(result)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO saved_search_changes(tenant_id,created_by,key_hash,query_id,generation_id,revision,input_hash,record,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,now()+make_interval(days=>COALESCE((SELECT days FROM retention_policies WHERE tenant_id=$1 AND category='operations'),180)))`, u.TenantID, u.ID, Hash(key), c.ID, result.GenerationID, result.Revision, savedsearch.InputHash(c), raw)
		return err
	})
	if err == nil {
		bound := savedsearch.Change{ID: result.ID, ExpectedRevision: result.Revision - 1, ExpectedGenerationID: c.ExpectedGenerationID, Name: result.Name, Description: result.Description, Visibility: result.Visibility, Active: &result.Active, Definition: result.Definition}
		if result.TenantID != u.TenantID || result.OwnerID != u.ID || result.Revision != c.ExpectedRevision+1 || c.ExpectedRevision > 0 && result.GenerationID != c.ExpectedGenerationID || savedsearch.InputHash(bound) != savedsearch.InputHash(c) {
			err = errors.New("保存查询回执与原输入不一致")
		}
	}
	return result, err
}

func (p *Postgres) ResolveSavedSearch(ctx context.Context, u model.Principal, id, generation, dataset string, revision int64) (savedsearch.Resolution, error) {
	var result savedsearch.Resolution
	if !contract.ValidID(generation) || revision < 1 || revision > savedsearch.MaxRevision || (dataset != "alerts" && dataset != "context") {
		return result, savedsearch.ErrInput
	}
	record, err := p.SavedSearch(ctx, u, id)
	if err != nil {
		return result, err
	}
	if record.GenerationID != generation || record.Revision != revision || record.Definition.Dataset != dataset {
		return result, ErrConflict
	}
	if !record.Active {
		return result, savedsearch.ErrInactive
	}
	q, err := record.Definition.Query(time.Now().UTC())
	if err != nil {
		return result, err
	}
	var raw json.RawMessage
	if dataset == "alerts" {
		if err := ValidateSearch(&q.SearchRequest); err != nil {
			return result, savedsearch.ErrInput
		}
		// 保留保存条件的原文；原检索入口负责规范化 IP，前端无需另行实现地址解析器。
		q.SourceIP, q.DestinationIP = record.Definition.Terms.SourceIP, record.Definition.Terms.DestinationIP
		raw, err = json.Marshal(q.SearchRequest)
	} else {
		if err := ValidateTrafficSearch(&q); err != nil {
			return result, savedsearch.ErrInput
		}
		q.SourceIP, q.DestinationIP = record.Definition.Terms.SourceIP, record.Definition.Terms.DestinationIP
		raw, err = json.Marshal(q)
	}
	result = savedsearch.Resolution{TenantID: record.TenantID, ID: record.ID, GenerationID: record.GenerationID, Revision: record.Revision, Definition: record.Definition, Query: raw}
	return result, err
}
