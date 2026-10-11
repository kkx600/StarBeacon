package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/kkx600/StarBeacon/internal/mcpaccess"
	"github.com/kkx600/StarBeacon/internal/model"
)

const bindingColumns = `id,name,issuer,subject,oauth_client_id,scopes,enabled,expires_at,requests_per_minute,owner_id,revision,created_at,updated_at`

func scanBinding(row pgx.Row) (mcpaccess.Binding, error) {
	var b mcpaccess.Binding
	err := row.Scan(&b.ID, &b.Name, &b.Issuer, &b.Subject, &b.OAuthClientID, &b.Scopes, &b.Enabled, &b.ExpiresAt, &b.RequestsPerMinute, &b.OwnerID, &b.Revision, &b.CreatedAt, &b.UpdatedAt)
	return b, err
}

func (p *Postgres) MCPBindings(ctx context.Context, tenant string) ([]mcpaccess.Binding, error) {
	out := []mcpaccess.Binding{}
	err := p.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+bindingColumns+` FROM mcp_bindings WHERE tenant_id=$1 ORDER BY created_at DESC,id LIMIT 100`, tenant)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			b, err := scanBinding(rows)
			if err != nil {
				return err
			}
			out = append(out, b)
		}
		return rows.Err()
	})
	return out, err
}

func (p *Postgres) SaveMCPBinding(ctx context.Context, u model.Principal, issuer string, c mcpaccess.Change, request string) (mcpaccess.Binding, error) {
	var out mcpaccess.Binding
	if u.Role != "admin" {
		return out, mcpaccess.ErrDenied
	}
	if err := c.Validate(time.Now().UTC()); err != nil {
		return out, err
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		// 与其他创建串行，确保多实例情况下租户的服务身份数量不超过 100。
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "mcp:bindings:"+u.TenantID); err != nil {
			return err
		}
		if c.ExpectedRevision == 0 {
			var count int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM mcp_bindings WHERE tenant_id=$1`, u.TenantID).Scan(&count); err != nil {
				return err
			}
			if count >= 100 {
				return mcpaccess.ErrQuota
			}
			_, err := tx.Exec(ctx, `INSERT INTO mcp_bindings(tenant_id,id,name,issuer,subject,oauth_client_id,scopes,enabled,expires_at,requests_per_minute,owner_id,revision) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,1)`, u.TenantID, c.ID, c.Name, issuer, c.Subject, c.OAuthClientID, c.Scopes, c.Enabled, c.ExpiresAt, c.RequestsPerMinute, u.ID)
			if err != nil {
				return err
			}
		} else {
			// 已登记的授权方、主体和 OAuth 客户端不可改绑；停用后另建身份。
			tag, err := tx.Exec(ctx, `UPDATE mcp_bindings SET name=$3,scopes=$4,enabled=$5,expires_at=$6,requests_per_minute=$7,revision=revision+1,updated_at=now() WHERE tenant_id=$1 AND id=$2 AND revision=$8 AND issuer=$9 AND subject=$10 AND oauth_client_id=$11`, u.TenantID, c.ID, c.Name, c.Scopes, c.Enabled, c.ExpiresAt, c.RequestsPerMinute, c.ExpectedRevision, issuer, c.Subject, c.OAuthClientID)
			if err != nil {
				return err
			}
			if tag.RowsAffected() != 1 {
				return mcpaccess.ErrConflict
			}
		}
		if c.ExpectedRevision == 0 {
			if _, err := tx.Exec(ctx, `INSERT INTO mcp_auth_routes(identity_hash,tenant_id,binding_id) VALUES($1,$2,$3)`, mcpaccess.TupleHash(issuer, c.Subject, c.OAuthClientID), u.TenantID, c.ID); err != nil {
				return err
			}
		}
		var err error
		out, err = scanBinding(tx.QueryRow(ctx, `SELECT `+bindingColumns+` FROM mcp_bindings WHERE tenant_id=$1 AND id=$2`, u.TenantID, c.ID))
		if err != nil {
			return err
		}
		return insertOperationAudit(ctx, tx, u, "mcp.binding.save", c.ID, request)
	})
	var pgerr *pgconn.PgError
	if errors.As(err, &pgerr) && pgerr.Code == "23505" {
		err = mcpaccess.ErrConflict
	}
	return out, err
}

func (p *Postgres) MCPIdentity(ctx context.Context, issuer, subject, clientID string) (mcpaccess.Identity, error) {
	var tenant, id string
	var out mcpaccess.Identity
	err := p.Pool.QueryRow(ctx, `SELECT tenant_id,binding_id FROM mcp_auth_routes WHERE identity_hash=$1`, mcpaccess.TupleHash(issuer, subject, clientID)).Scan(&tenant, &id)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, mcpaccess.ErrDenied
	}
	if err != nil {
		return out, err
	}
	err = p.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		var err error
		out.Binding, err = scanBinding(tx.QueryRow(ctx, `SELECT `+bindingColumns+` FROM mcp_bindings WHERE tenant_id=$1 AND id=$2 AND issuer=$3 AND subject=$4 AND oauth_client_id=$5 AND enabled AND expires_at>now()`, tenant, id, issuer, subject, clientID))
		if err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT u.id,u.tenant_id,u.username FROM users u JOIN tenants t ON t.id=u.tenant_id WHERE u.id=$1 AND u.tenant_id=$2 AND u.active AND t.active`, out.Binding.OwnerID, tenant).Scan(&out.Principal.ID, &out.Principal.TenantID, &out.Principal.Username)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		err = mcpaccess.ErrDenied
	}
	out.Principal.Role = "viewer"
	return out, err
}

func (p *Postgres) DeleteMCPBinding(ctx context.Context, u model.Principal, id string, revision int64, request string) error {
	if u.Role != "admin" || revision < 1 {
		return mcpaccess.ErrDenied
	}
	return p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM mcp_bindings WHERE tenant_id=$1 AND id=$2 AND revision=$3`, u.TenantID, id, revision)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return mcpaccess.ErrConflict
		}
		return insertOperationAudit(ctx, tx, u, "mcp.binding.delete", id, request)
	})
}

func (p *Postgres) MCPAudit(ctx context.Context, i mcpaccess.Identity, tool, result string) error {
	return p.TenantTx(ctx, i.Principal.TenantID, func(tx pgx.Tx) error {
		return insertOperationAudit(ctx, tx, i.Principal, "mcp.tool."+tool+"."+result, i.Binding.ID, model.RequestMetadataFrom(ctx).RequestID)
	})
}
