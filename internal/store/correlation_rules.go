package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/correlation"
	"github.com/kkx600/StarBeacon/internal/model"
)

const correlationRuleColumns = `v.tenant_id,v.rule_id,v.revision,v.name,v.description,v.active,v.definition,v.definition_sha256,v.created_by,v.created_at,v.expires_at`

func correlationRuleUser(ctx context.Context, tx pgx.Tx, u model.Principal, write bool) error {
	return configurationActor(ctx, tx, u, write, correlation.ErrPermission)
}

func readCorrelationRule(row interface{ Scan(...any) error }) (correlation.Record, error) {
	return scanCorrelationRule(row, false)
}

func readCorrelationHead(row interface{ Scan(...any) error }) (correlation.Record, error) {
	return scanCorrelationRule(row, true)
}

func scanCorrelationRule(row interface{ Scan(...any) error }, head bool) (correlation.Record, error) {
	var record correlation.Record
	var definition json.RawMessage
	var name string
	var active bool
	fields := []any{&record.TenantID, &record.ID, &record.Revision, &record.Name, &record.Description, &record.Active, &definition, &record.DefinitionSHA256, &record.CreatedBy, &record.CreatedAt, &record.ExpiresAt}
	if head {
		fields = append(fields, &name, &active)
	}
	if err := row.Scan(fields...); err != nil {
		return record, err
	}
	if json.Unmarshal(definition, &record.Definition) != nil || record.Validate() != nil || head && (name != record.Name || active != record.Active) {
		return record, errors.New("关联规则修订不完整")
	}
	return record, nil
}

func (p *Postgres) CorrelationRules(ctx context.Context, u model.Principal, q correlation.Query) (correlation.Page, error) {
	page := correlation.Page{Items: []correlation.Record{}}
	if q.Validate() != nil {
		return page, correlation.ErrInput
	}
	after, err := q.Position(u.TenantID)
	if err != nil {
		return page, err
	}
	err = p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := correlationRuleUser(ctx, tx, u, false); err != nil {
			return err
		}
		pattern := "%" + strings.NewReplacer("!", "!!", "%", "!%", "_", "!_").Replace(q.Keyword) + "%"
		rows, err := tx.Query(ctx, `SELECT `+correlationRuleColumns+`,h.name,h.active FROM correlation_rules h JOIN correlation_rule_revisions v ON v.tenant_id=h.tenant_id AND v.rule_id=h.id AND v.revision=h.revision WHERE h.tenant_id=$1 AND h.id>$2 AND h.name ILIKE $3 ESCAPE '!' AND ($4='' OR h.active=($4='true')) ORDER BY h.id LIMIT $5`, u.TenantID, after, pattern, q.Active, q.Limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			record, err := readCorrelationHead(rows)
			if err != nil {
				return err
			}
			page.Items = append(page.Items, record)
		}
		return rows.Err()
	})
	if len(page.Items) > q.Limit {
		page.NextCursor = q.Next(u.TenantID, page.Items[q.Limit-1].ID)
		page.Items = page.Items[:q.Limit]
	}
	return page, err
}

func (p *Postgres) CorrelationRule(ctx context.Context, u model.Principal, id string, revision int64) (correlation.Record, error) {
	var result correlation.Record
	if !contract.ValidID(id) || revision < 1 || revision > correlation.MaxRevision {
		return result, correlation.ErrInput
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := correlationRuleUser(ctx, tx, u, false); err != nil {
			return err
		}
		var err error
		result, err = readCorrelationRule(tx.QueryRow(ctx, `SELECT `+correlationRuleColumns+` FROM correlation_rule_revisions v WHERE v.tenant_id=$1 AND v.rule_id=$2 AND v.revision=$3 AND (v.expires_at>now() OR EXISTS(SELECT 1 FROM correlation_rules h WHERE h.tenant_id=v.tenant_id AND h.id=v.rule_id AND h.revision=v.revision))`, u.TenantID, id, revision))
		return err
	})
	return result, err
}

func (p *Postgres) SaveCorrelationRule(ctx context.Context, u model.Principal, key string, c correlation.Change) (correlation.Record, error) {
	var result correlation.Record
	if c.Validate() != nil || !contract.ValidID(key) {
		return result, correlation.ErrInput
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout='2s'; SET LOCAL statement_timeout='5s'`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, u.TenantID+"/correlation-rules"); err != nil {
			return err
		}
		if err := correlationRuleUser(ctx, tx, u, true); err != nil {
			return err
		}
		var inputHash string
		err := tx.QueryRow(ctx, `SELECT input_hash FROM correlation_rule_revisions WHERE tenant_id=$1 AND created_by=$2 AND key_hash=$3`, u.TenantID, u.ID, Hash(key)).Scan(&inputHash)
		if err == nil {
			if inputHash != correlation.Digest(c) {
				return ErrConflict
			}
			result, err = readCorrelationRule(tx.QueryRow(ctx, `SELECT `+correlationRuleColumns+` FROM correlation_rule_revisions v WHERE v.tenant_id=$1 AND v.created_by=$2 AND v.key_hash=$3`, u.TenantID, u.ID, Hash(key)))
			if err == nil && !result.ExpiresAt.After(time.Now()) {
				return ErrConflict
			}
			return err
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		var current correlation.Record
		current, err = readCorrelationHead(tx.QueryRow(ctx, `SELECT `+correlationRuleColumns+`,h.name,h.active FROM correlation_rules h JOIN correlation_rule_revisions v ON v.tenant_id=h.tenant_id AND v.rule_id=h.id AND v.revision=h.revision WHERE h.tenant_id=$1 AND h.id=$2 FOR UPDATE OF h`, u.TenantID, c.ID))
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if errors.Is(err, pgx.ErrNoRows) && c.ExpectedRevision > 0 {
			return pgx.ErrNoRows
		}
		if current.Revision != c.ExpectedRevision {
			return ErrConflict
		}
		if current.Revision > 0 && current.Name == c.Name && current.Description == c.Description && current.Active == *c.Active && current.DefinitionSHA256 == correlation.Digest(c.Definition) {
			return correlation.ErrInput
		}
		var count int
		if current.Revision == 0 {
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM correlation_rules WHERE tenant_id=$1`, u.TenantID).Scan(&count); err != nil {
				return err
			}
			if count >= correlation.MaxRules {
				return correlation.ErrQuota
			}
		}
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM correlation_rule_revisions WHERE tenant_id=$1 AND created_at>now()-interval '24 hours'`, u.TenantID).Scan(&count); err != nil {
			return err
		}
		if count >= correlation.MaxDailyChanges {
			return correlation.ErrQuota
		}
		raw, err := json.Marshal(c.Definition)
		if err != nil {
			return err
		}
		result, err = readCorrelationRule(tx.QueryRow(ctx, `INSERT INTO correlation_rule_revisions AS v(tenant_id,rule_id,revision,name,description,active,definition,definition_sha256,created_by,key_hash,input_hash,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,now()+make_interval(days=>COALESCE((SELECT days FROM retention_policies WHERE tenant_id=$1 AND category='operations'),180))) RETURNING `+correlationRuleColumns, u.TenantID, c.ID, c.ExpectedRevision+1, c.Name, c.Description, *c.Active, raw, correlation.Digest(c.Definition), u.ID, Hash(key), correlation.Digest(c)))
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO correlation_rules(tenant_id,id,revision,name,active) VALUES($1,$2,$3,$4,$5) ON CONFLICT(tenant_id,id) DO UPDATE SET revision=EXCLUDED.revision,name=EXCLUDED.name,active=EXCLUDED.active`, u.TenantID, c.ID, result.Revision, c.Name, *c.Active); err != nil {
			return err
		}
		return insertOperationAudit(ctx, tx, u, "correlation.rule.save", c.ID, model.RequestMetadataFrom(ctx).RequestID)
	})
	if err == nil && (result.TenantID != u.TenantID || result.CreatedBy != u.ID || result.ID != c.ID || result.Revision != c.ExpectedRevision+1 || result.Name != c.Name || result.Description != c.Description || result.Active != *c.Active || result.DefinitionSHA256 != correlation.Digest(c.Definition)) {
		err = errors.New("关联规则原提交回执与输入不一致")
	}
	return result, err
}

// 回测只允许当前可用修订；历史修订仍可查看，但不能绕过停用或替换后的配置。
func (p *Postgres) CurrentCorrelationRule(ctx context.Context, u model.Principal, id string, expected int64) (correlation.Record, error) {
	var result correlation.Record
	if !contract.ValidID(id) || expected < 1 || expected > correlation.MaxRevision {
		return result, correlation.ErrInput
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := correlationRuleUser(ctx, tx, u, true); err != nil {
			return err
		}
		var err error
		result, err = readCorrelationHead(tx.QueryRow(ctx, `SELECT `+correlationRuleColumns+`,h.name,h.active FROM correlation_rules h JOIN correlation_rule_revisions v ON v.tenant_id=h.tenant_id AND v.rule_id=h.id AND v.revision=h.revision WHERE h.tenant_id=$1 AND h.id=$2`, u.TenantID, id))
		if err == nil && (result.Revision != expected || !result.Active) {
			return ErrConflict
		}
		return err
	})
	return result, err
}

func (p *Postgres) RecordCorrelationBacktest(ctx context.Context, u model.Principal, id string, expected int64, request string) error {
	if !contract.ValidID(id) || !contract.ValidID(request) || expected < 1 || expected > correlation.MaxRevision {
		return correlation.ErrInput
	}
	return p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		// 与配置变更使用同一把锁，不能在停用已经提交后继续批准结果交付。
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared(hashtextextended($1,0))`, u.TenantID+"/correlation-rules"); err != nil {
			return err
		}
		if err := correlationRuleUser(ctx, tx, u, true); err != nil {
			return err
		}
		var revision int64
		var active bool
		if err := tx.QueryRow(ctx, `SELECT revision,active FROM correlation_rules WHERE tenant_id=$1 AND id=$2`, u.TenantID, id).Scan(&revision, &active); err != nil {
			return err
		}
		if revision != expected || !active {
			return ErrConflict
		}
		return insertOperationAudit(ctx, tx, u, "correlation.backtest.read", id, request)
	})
}
