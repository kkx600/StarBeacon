package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/kkx600/StarBeacon/internal/accounts"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/model"
	"golang.org/x/crypto/bcrypt"
)

func userManager(ctx context.Context, tx pgx.Tx, u model.Principal) error {
	if !contract.ValidID(u.ID) || !contract.ValidID(u.TenantID) || u.Role != "admin" {
		return accounts.ErrUnavailable
	}
	var valid bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users u JOIN tenants t ON t.id=u.tenant_id WHERE u.tenant_id=$1 AND u.id=$2 AND u.active AND u.role='admin' AND t.active)`, u.TenantID, u.ID).Scan(&valid); err != nil {
		return err
	}
	if !valid {
		return accounts.ErrUnavailable
	}
	return nil
}
func userRow(row pgx.Row) (accounts.Record, error) {
	var r accounts.Record
	err := row.Scan(&r.ID, &r.Username, &r.Role, &r.Active, &r.Revision, &r.CreatedAt, &r.UpdatedAt)
	if err == nil && r.Validate() != nil {
		err = errors.New("用户记录校验失败")
	}
	return r, err
}
func (p *Postgres) Users(ctx context.Context, u model.Principal, q accounts.Query) (accounts.Page, error) {
	page := accounts.Page{Items: []accounts.Record{}}
	if q.Validate() != nil {
		return page, accounts.ErrInput
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := userManager(ctx, tx, u); err != nil {
			return err
		}
		if q.Before != "" {
			var exists bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE tenant_id=$1 AND id=$2)`, u.TenantID, q.Before).Scan(&exists); err != nil {
				return err
			}
			if !exists {
				return pgx.ErrNoRows
			}
		}
		rows, err := tx.Query(ctx, `SELECT id,username,role,active,revision,created_at,updated_at FROM users WHERE tenant_id=$1 AND ($2='' OR role=$2) AND ($3='' OR active=($3='true')) AND ($4='' OR id<$4) ORDER BY id DESC LIMIT 21`, u.TenantID, q.Role, q.Active, q.Before)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			r, err := userRow(rows)
			if err != nil {
				return err
			}
			page.Items = append(page.Items, r)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if len(page.Items) > 20 {
			page.Items = page.Items[:20]
			page.Next = page.Items[19].ID
		}
		return nil
	})
	return page, err
}
func (p *Postgres) User(ctx context.Context, u model.Principal, id string) (accounts.Record, error) {
	var r accounts.Record
	if !contract.ValidID(id) {
		return r, accounts.ErrInput
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := userManager(ctx, tx, u); err != nil {
			return err
		}
		var err error
		r, err = userRow(tx.QueryRow(ctx, `SELECT id,username,role,active,revision,created_at,updated_at FROM users WHERE tenant_id=$1 AND id=$2`, u.TenantID, id))
		return err
	})
	return r, err
}
func userWriteError(err error) error {
	var p *pgconn.PgError
	if errors.As(err, &p) {
		switch p.Code {
		case "22023":
			return accounts.ErrInput
		case "42501":
			return accounts.ErrUnavailable
		case "P0002":
			return pgx.ErrNoRows
		case "P0003":
			return accounts.ErrQuota
		case "P0004":
			return accounts.ErrProtected
		case "40001", "23505":
			return ErrConflict
		}
	}
	return err
}
func (p *Postgres) writeUser(ctx context.Context, u model.Principal, id, key, operation, inputHash, password string, change accounts.Change, created *accounts.Create) (accounts.Record, error) {
	var result accounts.Record
	if !contract.ValidID(key) || !contract.ValidID(u.ID) || u.Role != "admin" {
		return result, accounts.ErrInput
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, u.TenantID+"/users"); err != nil {
			return err
		}
		if err := userManager(ctx, tx, u); err != nil {
			return err
		}
		var oldHash, storedID string
		var raw []byte
		var expires time.Time
		err := tx.QueryRow(ctx, `SELECT input_hash,user_id,record,expires_at FROM user_management_requests WHERE tenant_id=$1 AND created_by=$2 AND operation=$3 AND key_hash=$4`, u.TenantID, u.ID, operation, Hash(key)).Scan(&oldHash, &storedID, &raw, &expires)
		if err == nil {
			if oldHash != inputHash {
				return ErrConflict
			}
			if !expires.After(time.Now()) {
				return accounts.ErrExpired
			}
			if json.Unmarshal(raw, &result) != nil || result.Validate() != nil || result.ID != storedID || (operation == "change" && (result.ID != id || result.Revision != change.ExpectedRevision+1 || result.Role != change.Role || result.Active != *change.Active)) || (created != nil && (result.Revision != 1 || result.Username != created.Username || result.Role != created.Role || result.Active != *created.Active)) {
				return errors.New("用户管理回执校验失败")
			}
			if created != nil {
				var hash string
				if err := tx.QueryRow(ctx, `SELECT password_hash FROM users WHERE tenant_id=$1 AND id=$2`, u.TenantID, result.ID).Scan(&hash); err != nil {
					return err
				}
				if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
					return ErrConflict
				}
			}
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		var count int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM user_management_requests WHERE tenant_id=$1 AND created_at>=date_trunc('day',now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'`, u.TenantID).Scan(&count); err != nil {
			return err
		}
		if count >= 1000 {
			return accounts.ErrQuota
		}
		name, hash := "", ""
		if created != nil {
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM users WHERE tenant_id=$1`, u.TenantID).Scan(&count); err != nil {
				return err
			}
			if count >= 500 {
				return accounts.ErrQuota
			}
			encoded, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
			if err != nil {
				return err
			}
			name, hash = created.Username, string(encoded)
			id = RandomID("user_")
			change = accounts.Change{Role: created.Role, Active: created.Active}
		}
		meta := model.RequestMetadataFrom(ctx)
		auditContext, _ := json.Marshal(map[string]string{"request_id": meta.RequestID, "source_ip": meta.SourceIP, "user_agent": meta.UserAgent})
		result, err = userRow(tx.QueryRow(ctx, `SELECT id,username,role,active,revision,created_at,updated_at FROM public.save_tenant_user($1,$2,$3,$4,$5,$6,$7,$8,$9)`, u.ID, id, name, hash, change.Role, *change.Active, change.ExpectedRevision, key, auditContext))
		if err != nil {
			return userWriteError(err)
		}
		raw, err = json.Marshal(result)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO user_management_requests(tenant_id,created_by,operation,key_hash,input_hash,user_id,record,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,now()+make_interval(days=>COALESCE((SELECT days FROM retention_policies WHERE tenant_id=$1 AND category='operations'),180)))`, u.TenantID, u.ID, operation, Hash(key), inputHash, result.ID, raw)
		return userWriteError(err)
	})
	return result, err
}
func (p *Postgres) CreateUser(ctx context.Context, u model.Principal, key string, input accounts.Create) (accounts.Record, error) {
	if input.Validate() != nil {
		return accounts.Record{}, accounts.ErrInput
	}
	return p.writeUser(ctx, u, "", key, "create", Hash(string(input.PublicInput())), input.Password, accounts.Change{}, &input)
}
func (p *Postgres) ChangeUser(ctx context.Context, u model.Principal, id, key string, input accounts.Change) (accounts.Record, error) {
	if input.Validate() != nil || !contract.ValidID(id) {
		return accounts.Record{}, accounts.ErrInput
	}
	raw, err := json.Marshal(input)
	if err != nil {
		return accounts.Record{}, err
	}
	return p.writeUser(ctx, u, id, key, "change", Hash(id+"\x00"+string(raw)), "", input, nil)
}
