package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/gatewayblock"
	"github.com/kkx600/StarBeacon/internal/model"
)

func lockGatewayBlocks(ctx context.Context, tx pgx.Tx, tenant string) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, tenant+"/gateway-blocks")
	return err
}

func gatewaySettings(ctx context.Context, tx pgx.Tx, tenant string) (gatewayblock.Settings, error) {
	var out gatewayblock.Settings
	err := tx.QueryRow(ctx, `SELECT revision,enabled,per_minute,updated_at FROM gateway_block_settings WHERE tenant_id=$1`, tenant).
		Scan(&out.Revision, &out.Enabled, &out.PerMinute, &out.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return gatewayblock.Settings{PerMinute: gatewayblock.DefaultPerMinute}, nil
	}
	return out, err
}

func (p *Postgres) GatewayBlockSettings(ctx context.Context, u model.Principal) (gatewayblock.Settings, error) {
	var out gatewayblock.Settings
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := configurationActor(ctx, tx, u, false, gatewayblock.ErrPermission); err != nil {
			return err
		}
		var err error
		out, err = gatewaySettings(ctx, tx, u.TenantID)
		return err
	})
	return out, err
}

func (p *Postgres) SaveGatewayBlockSettings(ctx context.Context, u model.Principal, change gatewayblock.SettingsChange, requestID string) (gatewayblock.Settings, error) {
	var out gatewayblock.Settings
	if !change.Valid() {
		return out, gatewayblock.ErrInput
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := configurationActor(ctx, tx, u, true, gatewayblock.ErrPermission); err != nil {
			return err
		}
		if err := lockGatewayBlocks(ctx, tx, u.TenantID); err != nil {
			return err
		}
		current, err := gatewaySettings(ctx, tx, u.TenantID)
		if err != nil {
			return err
		}
		if current.Revision != change.ExpectedRevision {
			if current.Revision == change.ExpectedRevision+1 && current.Enabled == change.Enabled && current.PerMinute == change.PerMinute {
				out = current
				return nil
			}
			return ErrConflict
		}
		out = gatewayblock.Settings{Revision: current.Revision + 1, Enabled: change.Enabled, PerMinute: change.PerMinute}
		if err := tx.QueryRow(ctx, `INSERT INTO gateway_block_settings(tenant_id,revision,enabled,per_minute)
			VALUES($1,$2,$3,$4) ON CONFLICT(tenant_id) DO UPDATE SET revision=EXCLUDED.revision,enabled=EXCLUDED.enabled,
			 per_minute=EXCLUDED.per_minute,updated_at=clock_timestamp() RETURNING updated_at`,
			u.TenantID, out.Revision, out.Enabled, out.PerMinute).Scan(&out.UpdatedAt); err != nil {
			return err
		}
		return insertOperationAudit(ctx, tx, u, "gateway.block.settings.save", u.TenantID, requestID)
	})
	return out, err
}

const gatewayPolicyColumns = "id,revision,definition,author_id,updated_at"

func scanGatewayPolicy(row pgx.Row) (gatewayblock.Policy, error) {
	var policy gatewayblock.Policy
	var raw []byte
	if err := row.Scan(&policy.ID, &policy.Revision, &raw, &policy.AuthorID, &policy.UpdatedAt); err != nil {
		return policy, err
	}
	if json.Unmarshal(raw, &policy.Definition) != nil || !policy.Definition.Valid() || policy.UpdatedAt.IsZero() ||
		!contract.ValidID(policy.ID) || !contract.ValidID(policy.AuthorID) || policy.Revision < 1 || policy.Revision > gatewayblock.MaxRevision {
		return gatewayblock.Policy{}, gatewayblock.ErrInput
	}
	return policy, nil
}

func gatewayPolicy(ctx context.Context, tx pgx.Tx, tenant, id string) (gatewayblock.Policy, error) {
	return scanGatewayPolicy(tx.QueryRow(ctx, `SELECT `+gatewayPolicyColumns+` FROM gateway_block_policies WHERE tenant_id=$1 AND id=$2`, tenant, id))
}

func (p *Postgres) GatewayBlockPolicies(ctx context.Context, u model.Principal, cursor string, limit int) (gatewayblock.PolicyPage, error) {
	out := gatewayblock.PolicyPage{Items: []gatewayblock.Policy{}}
	if !contract.ValidListLimit(limit) || cursor != "" && !contract.ValidID(cursor) {
		return out, gatewayblock.ErrInput
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := configurationActor(ctx, tx, u, false, gatewayblock.ErrPermission); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT `+gatewayPolicyColumns+` FROM gateway_block_policies WHERE tenant_id=$1 AND id>$2 ORDER BY id LIMIT $3`, u.TenantID, cursor, limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			policy, err := scanGatewayPolicy(rows)
			if err != nil {
				return err
			}
			out.Items = append(out.Items, policy)
		}
		if len(out.Items) > limit {
			out.Items = out.Items[:limit]
			out.NextCursor = out.Items[limit-1].ID
		}
		return rows.Err()
	})
	return out, err
}

func (p *Postgres) SaveGatewayBlockPolicy(ctx context.Context, u model.Principal, id string, change gatewayblock.PolicyChange, requestID string) (gatewayblock.Policy, error) {
	var out gatewayblock.Policy
	if !contract.ValidID(id) || !change.Valid(time.Now()) {
		return out, gatewayblock.ErrInput
	}
	change.Definition.ValidUntil = change.Definition.ValidUntil.UTC()
	raw, _ := json.Marshal(change.Definition)
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := configurationActor(ctx, tx, u, true, gatewayblock.ErrPermission); err != nil {
			return err
		}
		if err := lockGatewayBlocks(ctx, tx, u.TenantID); err != nil {
			return err
		}
		current, err := gatewayPolicy(ctx, tx, u.TenantID, id)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if current.Revision != change.ExpectedRevision {
			previous, _ := json.Marshal(current.Definition)
			if current.Revision == change.ExpectedRevision+1 && current.AuthorID == u.ID && bytes.Equal(previous, raw) {
				out = current
				return nil
			}
			return ErrConflict
		}
		if current.Revision == 0 {
			var count int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM gateway_block_policies WHERE tenant_id=$1`, u.TenantID).Scan(&count); err != nil {
				return err
			}
			if count >= gatewayblock.MaxPolicies {
				return gatewayblock.ErrLimit
			}
		}
		if change.Definition.Enabled {
			var available bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM sensors WHERE tenant_id=$1 AND id=$2 AND registration_id=$3 AND active)`,
				u.TenantID, change.Definition.SensorID, change.Definition.RegistrationID).Scan(&available); err != nil {
				return err
			}
			if !available {
				return gatewayblock.ErrIneligible
			}
		}
		out, err = scanGatewayPolicy(tx.QueryRow(ctx, `INSERT INTO gateway_block_policies(tenant_id,id,revision,definition,author_id)
			VALUES($1,$2,$3,$4,$5) ON CONFLICT(tenant_id,id) DO UPDATE SET revision=EXCLUDED.revision,definition=EXCLUDED.definition,
			author_id=EXCLUDED.author_id,updated_at=clock_timestamp() RETURNING `+gatewayPolicyColumns,
			u.TenantID, id, current.Revision+1, raw, u.ID))
		if err != nil {
			return err
		}
		return insertOperationAudit(ctx, tx, u, "gateway.block.policy.save", id, requestID)
	})
	return out, err
}
