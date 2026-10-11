package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/inventory"
	"github.com/kkx600/StarBeacon/internal/model"
)

func (p *Postgres) Inventory(ctx context.Context, tenant, kind, cursor, keyword string, limit int) (inventory.Page, error) {
	page := inventory.Page{Items: []inventory.Record{}}
	if !inventory.ValidKind(kind) || limit < 1 || limit > 100 || len([]rune(keyword)) > 128 || strings.ContainsAny(keyword, "\x00\r\n") || (cursor != "" && !contract.ValidID(cursor)) {
		return page, ErrConflict
	}
	err := p.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		pattern := "%" + strings.NewReplacer("!", "!!", "%", "!%", "_", "!_").Replace(keyword) + "%"
		rows, err := tx.Query(ctx, `SELECT id,kind,revision,data,created_at,updated_at FROM inventory_objects WHERE tenant_id=$1 AND kind=$2 AND id>$3 AND name ILIKE $5 ESCAPE '!' ORDER BY id LIMIT $4`, tenant, kind, cursor, limit+1, pattern)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var record inventory.Record
			if err := rows.Scan(&record.ID, &record.Kind, &record.Revision, &record.Data, &record.CreatedAt, &record.UpdatedAt); err != nil {
				return err
			}
			page.Items = append(page.Items, record)
		}
		return rows.Err()
	})
	if len(page.Items) > limit {
		page.NextCursor = page.Items[limit-1].ID
		page.Items = page.Items[:limit]
	}
	return page, err
}
func (p *Postgres) InventoryObject(ctx context.Context, tenant, kind, id string) (inventory.Record, error) {
	var record inventory.Record
	if !inventory.ValidKind(kind) || !contract.ValidID(id) {
		return record, ErrConflict
	}
	err := p.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT id,kind,revision,data,created_at,updated_at FROM inventory_objects WHERE tenant_id=$1 AND kind=$2 AND id=$3`, tenant, kind, id).Scan(&record.ID, &record.Kind, &record.Revision, &record.Data, &record.CreatedAt, &record.UpdatedAt)
	})
	return record, err
}
func (p *Postgres) SaveInventory(ctx context.Context, user model.Principal, kind, id string, expected int64, data json.RawMessage, request string) (inventory.Record, error) {
	var result inventory.Record
	if !contract.ValidID(id) || expected < 0 {
		return result, ErrConflict
	}
	normalized, err := inventory.Validate(kind, data)
	if err != nil {
		return result, err
	}
	if normalized.GroupID != "" && !contract.ValidID(normalized.GroupID) {
		return result, ErrConflict
	}
	err = p.TenantTx(ctx, user.TenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, user.TenantID+"/inventory/"+kind+"/"+id); err != nil {
			return err
		}
		var current int64
		err := tx.QueryRow(ctx, `SELECT revision FROM inventory_objects WHERE tenant_id=$1 AND kind=$2 AND id=$3 FOR UPDATE`, user.TenantID, kind, id).Scan(&current)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if current != expected {
			return ErrConflict
		}
		if normalized.GroupID != "" {
			var active bool
			if err := tx.QueryRow(ctx, `SELECT active FROM inventory_objects WHERE tenant_id=$1 AND kind='groups' AND id=$2 FOR SHARE`, user.TenantID, normalized.GroupID).Scan(&active); err != nil {
				return err
			}
			if normalized.Active && !active {
				return ErrConflict
			}
		}
		if kind == "groups" && !normalized.Active {
			var linked bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM inventory_objects WHERE tenant_id=$1 AND group_id=$2 AND active)`, user.TenantID, id).Scan(&linked); err != nil {
				return err
			}
			if linked {
				return ErrConflict
			}
		}
		result.ID = id
		result.Kind = kind
		result.Revision = current + 1
		result.Data = normalized.Data
		if err := tx.QueryRow(ctx, `INSERT INTO inventory_objects(tenant_id,kind,id,name,revision,group_id,active,data) VALUES($1,$2,$3,$4,$5,NULLIF($6,''),$7,$8) ON CONFLICT(tenant_id,kind,id) DO UPDATE SET name=EXCLUDED.name,revision=EXCLUDED.revision,group_id=EXCLUDED.group_id,active=EXCLUDED.active,data=EXCLUDED.data,updated_at=clock_timestamp() RETURNING created_at,updated_at`, user.TenantID, kind, id, normalized.Name, result.Revision, normalized.GroupID, normalized.Active, normalized.Data).Scan(&result.CreatedAt, &result.UpdatedAt); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO inventory_history(tenant_id,kind,id,revision,name,active,data,valid_from,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8::timestamptz,$8::timestamptz+make_interval(days=>COALESCE((SELECT days FROM retention_policies WHERE tenant_id=$1 AND category='asset_history'),180)))`, user.TenantID, kind, id, result.Revision, normalized.Name, normalized.Active, result.Data, result.UpdatedAt); err != nil {
			return err
		}
		return insertOperationAudit(ctx, tx, user, "inventory."+kind+".save", id, request)
	})
	var pgError *pgconn.PgError
	if errors.As(err, &pgError) && pgError.Code == "23503" {
		err = pgx.ErrNoRows
	}
	return result, err
}
func (p *Postgres) InventoryHistory(ctx context.Context, tenant, kind, id string, at time.Time) ([]inventory.Record, error) {
	result := []inventory.Record{}
	if !inventory.ValidKind(kind) || !contract.ValidID(id) {
		return result, ErrConflict
	}
	err := p.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id,kind,revision,data,valid_from,valid_from FROM inventory_history WHERE tenant_id=$1 AND kind=$2 AND id=$3 AND valid_from<=$4 AND expires_at>now() ORDER BY revision DESC LIMIT 100`, tenant, kind, id, at)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var v inventory.Record
			if err := rows.Scan(&v.ID, &v.Kind, &v.Revision, &v.Data, &v.CreatedAt, &v.UpdatedAt); err != nil {
				return err
			}
			result = append(result, v)
		}
		return rows.Err()
	})
	return result, err
}
