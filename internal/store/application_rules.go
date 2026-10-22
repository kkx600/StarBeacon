package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/application"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/model"
)

const applicationRuleColumns = `v.tenant_id,v.rule_id,v.revision,v.name,v.description,v.active,v.definition,v.definition_sha256,v.created_by,v.created_at,v.expires_at`

func applicationRuleUser(ctx context.Context, tx pgx.Tx, u model.Principal, write bool) error {
	return configurationActor(ctx, tx, u, write, application.ErrPermission)
}

func readApplicationRule(row interface{ Scan(...any) error }) (application.Record, error) {
	var record application.Record
	var definition json.RawMessage
	if err := row.Scan(&record.TenantID, &record.ID, &record.Revision, &record.Name, &record.Description, &record.Active, &definition, &record.DefinitionSHA256, &record.CreatedBy, &record.CreatedAt, &record.ExpiresAt); err != nil {
		return record, err
	}
	if json.Unmarshal(definition, &record.Definition) != nil || record.Validate() != nil {
		return record, errors.New("应用识别规则修订不完整")
	}
	return record, nil
}

func (p *Postgres) ApplicationRules(ctx context.Context, u model.Principal, q application.ListQuery) (application.Page, error) {
	page := application.Page{Items: []application.Record{}}
	if q.Validate() != nil {
		return page, application.ErrInput
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := applicationRuleUser(ctx, tx, u, false); err != nil {
			return err
		}
		pattern := "%" + strings.NewReplacer("!", "!!", "%", "!%", "_", "!_").Replace(q.Keyword) + "%"
		rows, err := tx.Query(ctx, `SELECT `+applicationRuleColumns+` FROM application_rules h JOIN application_rule_revisions v ON v.tenant_id=h.tenant_id AND v.rule_id=h.id AND v.revision=h.revision WHERE h.tenant_id=$1 AND h.id>$2 AND h.name ILIKE $3 ESCAPE '!' AND ($4='' OR h.active=($4='true')) ORDER BY h.id LIMIT $5`, u.TenantID, q.Cursor, pattern, q.Active, q.Limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			record, err := readApplicationRule(rows)
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

func (p *Postgres) ApplicationRule(ctx context.Context, u model.Principal, id string, revision int64) (application.Record, error) {
	var result application.Record
	if !contract.ValidID(id) || revision < 1 || revision > application.MaxRevision {
		return result, application.ErrInput
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := applicationRuleUser(ctx, tx, u, false); err != nil {
			return err
		}
		var err error
		result, err = readApplicationRule(tx.QueryRow(ctx, `SELECT `+applicationRuleColumns+` FROM application_rule_revisions v WHERE v.tenant_id=$1 AND v.rule_id=$2 AND v.revision=$3 AND (v.expires_at>now() OR EXISTS(SELECT 1 FROM application_rules h WHERE h.tenant_id=v.tenant_id AND h.id=v.rule_id AND h.revision=v.revision))`, u.TenantID, id, revision))
		return err
	})
	return result, err
}

func (p *Postgres) SaveApplicationRule(ctx context.Context, u model.Principal, key string, c application.Change) (application.Record, error) {
	var result application.Record
	if c.Validate() != nil || !contract.ValidID(key) {
		return result, application.ErrInput
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout='2s'; SET LOCAL statement_timeout='5s'`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, u.TenantID+"/application-rules"); err != nil {
			return err
		}
		if err := applicationRuleUser(ctx, tx, u, true); err != nil {
			return err
		}
		var inputHash string
		err := tx.QueryRow(ctx, `SELECT input_hash FROM application_rule_revisions WHERE tenant_id=$1 AND created_by=$2 AND key_hash=$3`, u.TenantID, u.ID, Hash(key)).Scan(&inputHash)
		if err == nil {
			if inputHash != application.Digest(c) {
				return ErrConflict
			}
			result, err = readApplicationRule(tx.QueryRow(ctx, `SELECT `+applicationRuleColumns+` FROM application_rule_revisions v WHERE v.tenant_id=$1 AND v.created_by=$2 AND v.key_hash=$3`, u.TenantID, u.ID, Hash(key)))
			if err == nil && !result.ExpiresAt.After(time.Now()) {
				return ErrConflict
			}
			return err
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		var current application.Record
		current, err = readApplicationRule(tx.QueryRow(ctx, `SELECT `+applicationRuleColumns+` FROM application_rules h JOIN application_rule_revisions v ON v.tenant_id=h.tenant_id AND v.rule_id=h.id AND v.revision=h.revision WHERE h.tenant_id=$1 AND h.id=$2 FOR UPDATE OF h`, u.TenantID, c.ID))
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if errors.Is(err, pgx.ErrNoRows) && c.ExpectedRevision > 0 {
			return pgx.ErrNoRows
		}
		if current.Revision != c.ExpectedRevision {
			return ErrConflict
		}
		if current.Revision > 0 && current.Name == c.Name && current.Description == c.Description && current.Active == *c.Active && current.DefinitionSHA256 == application.Digest(c.Definition) {
			return application.ErrInput
		}
		var count int
		if current.Revision == 0 {
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM application_rules WHERE tenant_id=$1`, u.TenantID).Scan(&count); err != nil {
				return err
			}
			if count >= application.MaxRules {
				return application.ErrQuota
			}
		}
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM application_rule_revisions WHERE tenant_id=$1 AND created_at>now()-interval '24 hours'`, u.TenantID).Scan(&count); err != nil {
			return err
		}
		if count >= application.MaxDailyChanges {
			return application.ErrQuota
		}
		raw, err := json.Marshal(c.Definition)
		if err != nil {
			return err
		}
		result, err = readApplicationRule(tx.QueryRow(ctx, `INSERT INTO application_rule_revisions AS v(tenant_id,rule_id,revision,name,description,active,definition,definition_sha256,created_by,key_hash,input_hash,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,now()+make_interval(days=>COALESCE((SELECT days FROM retention_policies WHERE tenant_id=$1 AND category='operations'),180))) RETURNING `+applicationRuleColumns, u.TenantID, c.ID, c.ExpectedRevision+1, c.Name, c.Description, *c.Active, raw, application.Digest(c.Definition), u.ID, Hash(key), application.Digest(c)))
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO application_rules(tenant_id,id,revision,name,active) VALUES($1,$2,$3,$4,$5) ON CONFLICT(tenant_id,id) DO UPDATE SET revision=EXCLUDED.revision,name=EXCLUDED.name,active=EXCLUDED.active`, u.TenantID, c.ID, result.Revision, c.Name, *c.Active); err != nil {
			return err
		}
		return insertOperationAudit(ctx, tx, u, "application.rule.save", c.ID, model.RequestMetadataFrom(ctx).RequestID)
	})
	if err == nil && (result.TenantID != u.TenantID || result.CreatedBy != u.ID || result.ID != c.ID || result.Revision != c.ExpectedRevision+1 || result.Name != c.Name || result.Description != c.Description || result.Active != *c.Active || result.DefinitionSHA256 != application.Digest(c.Definition)) {
		err = errors.New("应用识别规则原提交回执与输入不一致")
	}
	return result, err
}

// 输入验证不修改事件、归因、计数或探针规则包。审计只记录操作和规则标识，不复制验证材料。
func (p *Postgres) TestApplicationRules(ctx context.Context, u model.Principal, observation application.Observation, candidate *application.Definition) (application.Result, error) {
	var result application.Result
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := applicationRuleUser(ctx, tx, u, false); err != nil {
			return err
		}
		versions := []application.Version{}
		action := "application.rule.test"
		object := "application_rules"
		if candidate != nil {
			versions = append(versions, application.Version{ID: "candidate_rule", Revision: 1, Definition: *candidate})
			action = "application.rule.preview"
			object = "candidate_rule"
		} else {
			rows, err := tx.Query(ctx, `SELECT `+applicationRuleColumns+` FROM application_rules h JOIN application_rule_revisions v ON v.tenant_id=h.tenant_id AND v.rule_id=h.id AND v.revision=h.revision WHERE h.tenant_id=$1 AND h.active ORDER BY h.id LIMIT $2`, u.TenantID, application.MaxRules+1)
			if err != nil {
				return err
			}
			for rows.Next() {
				record, err := readApplicationRule(rows)
				if err != nil {
					rows.Close()
					return err
				}
				versions = append(versions, application.Version{ID: record.ID, Revision: record.Revision, Definition: record.Definition})
			}
			err = rows.Err()
			rows.Close()
			if err != nil {
				return err
			}
		}
		var err error
		result, err = application.Evaluate(versions, observation, time.Now().UTC())
		if err != nil {
			return err
		}
		return insertOperationAudit(ctx, tx, u, action, object, model.RequestMetadataFrom(ctx).RequestID)
	})
	return result, err
}
