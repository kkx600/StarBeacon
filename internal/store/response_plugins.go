package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/model"
	responseapi "github.com/kkx600/StarBeacon/internal/response"
)

const responsePluginColumns = `v.plugin_id,v.version,v.name,v.device,v.template,v.template_sha256,v.created_by,v.created_at`

func scanResponsePlugin(row interface{ Scan(...any) error }, head bool) (responseapi.PluginVersion, error) {
	var item responseapi.PluginVersion
	var raw json.RawMessage
	var current int
	fields := []any{&item.ID, &item.Version, &item.Name, &item.Device, &raw, &item.TemplateSHA256, &item.CreatedBy, &item.CreatedAt}
	if !head {
		fields = append(fields, &current)
	}
	if err := row.Scan(fields...); err != nil {
		return item, err
	}
	item.Kind, item.State = "template", "draft"
	if !head && current != item.Version {
		item.State = "superseded"
	}
	if json.Unmarshal(raw, &item.Template) != nil || item.Validate() != nil {
		return responseapi.PluginVersion{}, errors.New("联动插件版本与摘要不一致")
	}
	return item, nil
}

func responsePluginVersion(ctx context.Context, tx pgx.Tx, tenant, id string, version int) (responseapi.PluginVersion, error) {
	return scanResponsePlugin(tx.QueryRow(ctx, `SELECT `+responsePluginColumns+`,
		(SELECT max(h.version) FROM response_plugin_versions h WHERE h.tenant_id=v.tenant_id AND h.plugin_id=v.plugin_id)
		FROM response_plugin_versions v WHERE v.tenant_id=$1 AND v.plugin_id=$2 AND v.version=$3`, tenant, id, version), false)
}

func (p *Postgres) ResponsePluginVersion(ctx context.Context, u model.Principal, id string, version int) (responseapi.PluginVersion, error) {
	var result responseapi.PluginVersion
	if !contract.ValidID(id) || version < 1 || version > responseapi.MaxPluginVersions {
		return result, responseapi.ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := configurationActor(ctx, tx, u, true, responseapi.ErrPermission); err != nil {
			return err
		}
		var err error
		result, err = responsePluginVersion(ctx, tx, u.TenantID, id, version)
		return err
	})
	return result, err
}

func (p *Postgres) ResponsePlugins(ctx context.Context, u model.Principal, after string, limit int) (responseapi.PluginPage, error) {
	page := responseapi.PluginPage{Items: []responseapi.PluginVersion{}}
	if after != "" && !contract.ValidID(after) || limit < 1 || limit > 100 {
		return page, responseapi.ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := configurationActor(ctx, tx, u, true, responseapi.ErrPermission); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT DISTINCT ON (v.plugin_id COLLATE "C") `+responsePluginColumns+`
			FROM response_plugin_versions v WHERE v.tenant_id=$1 AND v.plugin_id COLLATE "C">$2
			ORDER BY v.plugin_id COLLATE "C", v.version DESC LIMIT $3`, u.TenantID, after, limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			item, err := scanResponsePlugin(rows, true)
			if err != nil {
				return err
			}
			page.Items = append(page.Items, item)
		}
		return rows.Err()
	})
	if err == nil && len(page.Items) > limit {
		page.NextAfter = page.Items[limit-1].ID
		page.Items = page.Items[:limit]
	}
	return page, err
}

func (p *Postgres) SaveResponsePluginDraft(ctx context.Context, u model.Principal, key string, draft responseapi.PluginDraft) (responseapi.PluginVersion, error) {
	var result responseapi.PluginVersion
	if draft.Validate() != nil || !contract.ValidID(key) || len(key) < 8 {
		return result, responseapi.ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	requestSHA, keySHA := draft.SHA256(), Hash(key)
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := configurationActor(ctx, tx, u, true, responseapi.ErrPermission); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, u.TenantID+"/response-plugins"); err != nil {
			return err
		}
		var savedID, savedSHA string
		var savedVersion int
		err := tx.QueryRow(ctx, `SELECT plugin_id,version,request_sha256 FROM response_plugin_versions
			WHERE tenant_id=$1 AND created_by=$2 AND request_key_sha256=$3`, u.TenantID, u.ID, keySHA).Scan(&savedID, &savedVersion, &savedSHA)
		if err == nil {
			if savedSHA != requestSHA || savedID != draft.ID || savedVersion != draft.ExpectedVersion+1 {
				return ErrConflict
			}
			result, err = responsePluginVersion(ctx, tx, u.TenantID, savedID, savedVersion)
			return err
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		var current int
		if err := tx.QueryRow(ctx, `SELECT COALESCE(max(version),0) FROM response_plugin_versions
			WHERE tenant_id=$1 AND plugin_id=$2`, u.TenantID, draft.ID).Scan(&current); err != nil {
			return err
		}
		if current != draft.ExpectedVersion {
			return ErrConflict
		}
		if current >= responseapi.MaxPluginVersions {
			return responseapi.ErrPluginQuota
		}
		if current == 0 {
			var count int
			if err := tx.QueryRow(ctx, `SELECT count(DISTINCT plugin_id) FROM response_plugin_versions WHERE tenant_id=$1`, u.TenantID).Scan(&count); err != nil {
				return err
			}
			if count >= responseapi.MaxPlugins {
				return responseapi.ErrPluginQuota
			}
		}
		raw, err := json.Marshal(draft.Template)
		if err != nil {
			return err
		}
		result, err = scanResponsePlugin(tx.QueryRow(ctx, `INSERT INTO response_plugin_versions AS v
			(tenant_id,plugin_id,version,name,device,template,template_sha256,created_by,request_key_sha256,request_sha256)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING `+responsePluginColumns,
			u.TenantID, draft.ID, current+1, draft.Name, draft.Device, raw, draft.Template.SHA256(), u.ID, keySHA, requestSHA), true)
		if err != nil {
			return err
		}
		return insertOperationAudit(ctx, tx, u, "response.plugin.draft.save", draft.ID, model.RequestMetadataFrom(ctx).RequestID)
	})
	if err == nil && (result.ID != draft.ID || result.Version != draft.ExpectedVersion+1 || result.TemplateSHA256 != draft.Template.SHA256() || result.Name != draft.Name || result.Device != draft.Device || result.CreatedBy != u.ID) {
		err = errors.New("联动插件草稿回执与原提交不一致")
	}
	return result, err
}
