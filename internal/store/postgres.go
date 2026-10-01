// Package store 将租户作用域绑定到事务，不在连接池中遗留会话级租户设置。
package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/transport"
)

type Postgres struct{ Pool *pgxpool.Pool }

var ErrSensorInactive = errors.New("探针身份已停用或未注册")

func RandomID(prefix string) string {
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return prefix + hex.EncodeToString(b)
}
func Token() string {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return hex.EncodeToString(b)
}
func Hash(s string) string { v := sha256.Sum256([]byte(s)); return hex.EncodeToString(v[:]) }
func Open(ctx context.Context, dsn string) (*Postgres, error) {
	c, e := pgxpool.ParseConfig(dsn)
	if e != nil {
		return nil, e
	}
	c.MaxConns = 16
	c.MinConns = 2
	c.MaxConnLifetime = 30 * time.Minute
	p, e := pgxpool.NewWithConfig(ctx, c)
	if e != nil {
		return nil, e
	}
	if e = p.Ping(ctx); e != nil {
		p.Close()
		return nil, e
	}
	return &Postgres{p}, nil
}
func (p *Postgres) Close() { p.Pool.Close() }
func (p *Postgres) TenantTx(ctx context.Context, tenant string, fn func(pgx.Tx) error) error {
	if !contract.ValidID(tenant) {
		return fmt.Errorf("租户标识不合法")
	}
	tx, e := p.Pool.BeginTx(ctx, pgx.TxOptions{})
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, "SELECT set_config('starbeacon.tenant_id',$1,true)", tenant); e != nil {
		return e
	}
	if e = fn(tx); e != nil {
		return e
	}
	return tx.Commit(ctx)
}
func (p *Postgres) VerifyRuntimeRole(ctx context.Context) error {
	var bad bool
	e := p.Pool.QueryRow(ctx, `SELECT r.rolsuper OR r.rolbypassrls OR EXISTS(SELECT 1 FROM pg_tables t WHERE t.schemaname='public' AND t.tablename IN ('tenants','users','sessions','sensors','routes','retention_policies','operation_audits','login_audits','sensor_tasks','rule_packages') AND t.tableowner=current_user) FROM pg_roles r WHERE r.rolname=current_user`).Scan(&bad)
	if e != nil {
		return e
	}
	if bad {
		return fmt.Errorf("运行账号不能是超级用户、BYPASSRLS 或业务表所有者")
	}
	return nil
}
func (p *Postgres) Password(ctx context.Context, username string) (model.Principal, string, error) {
	var u model.Principal
	var hash string
	e := p.Pool.QueryRow(ctx, `SELECT u.id,u.tenant_id,u.username,u.role,u.password_hash FROM users u JOIN tenants t ON t.id=u.tenant_id WHERE u.username=$1 AND u.active AND t.active`, username).Scan(&u.ID, &u.TenantID, &u.Username, &u.Role, &hash)
	if errors.Is(e, pgx.ErrNoRows) {
		e = model.ErrUnauthenticated
	}
	return u, hash, e
}
func (p *Postgres) CreateSession(ctx context.Context, u model.Principal) (string, string, error) {
	token, csrf := Token(), Token()
	_, e := p.Pool.Exec(ctx, `INSERT INTO sessions(token_hash,user_id,csrf_token,expires_at) VALUES($1,$2,$3,now()+interval '8 hours')`, Hash(token), u.ID, csrf)
	return token, csrf, e
}
func (p *Postgres) Session(ctx context.Context, token string) (model.Principal, error) {
	var u model.Principal
	e := p.Pool.QueryRow(ctx, `SELECT u.id,u.tenant_id,u.username,u.role,s.csrf_token FROM sessions s JOIN users u ON u.id=s.user_id JOIN tenants t ON t.id=u.tenant_id WHERE s.token_hash=$1 AND s.expires_at>now() AND u.active AND t.active`, Hash(token)).Scan(&u.ID, &u.TenantID, &u.Username, &u.Role, &u.CSRF)
	if errors.Is(e, pgx.ErrNoRows) {
		e = model.ErrUnauthenticated
	}
	return u, e
}
func (p *Postgres) DeleteSession(ctx context.Context, token string) error {
	_, e := p.Pool.Exec(ctx, "DELETE FROM sessions WHERE token_hash=$1", Hash(token))
	return e
}
func (p *Postgres) LoginAudit(ctx context.Context, u model.Principal, success bool) error {
	meta := model.RequestMetadataFrom(ctx)
	if u.TenantID == "" {
		_, e := p.Pool.Exec(ctx, `INSERT INTO login_audits(tenant_id,username,success,source_ip,user_agent,request_id) VALUES(NULL,$1,$2,$3,$4,$5)`, u.Username, success, meta.SourceIP, meta.UserAgent, meta.RequestID)
		return e
	}
	return p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO login_audits(tenant_id,username,success,source_ip,user_agent,request_id,expires_at) VALUES($1,$2,$3,$4,$5,$6,now()+make_interval(days=>COALESCE((SELECT days FROM retention_policies WHERE tenant_id=$1 AND category='logins'),180)))`, u.TenantID, u.Username, success, meta.SourceIP, meta.UserAgent, meta.RequestID)
		return e
	})

}
func (p *Postgres) Sensors(ctx context.Context, tenant string) ([]model.Sensor, error) {
	out := make([]model.Sensor, 0)
	e := p.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		rows, e := tx.Query(ctx, "SELECT id,name,registration_id,active,created_at,last_seen,health FROM sensors WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 500", tenant)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var s model.Sensor
			if e = rows.Scan(&s.ID, &s.Name, &s.RegistrationID, &s.Active, &s.CreatedAt, &s.LastSeen, &s.Health); e != nil {
				return e
			}
			s.Status = "offline"
			if s.LastSeen != nil && time.Since(*s.LastSeen) < 35*time.Second {
				s.Status = "online"
			}
			if !s.Active {
				s.Status = "disabled"
			}
			out = append(out, s)
		}
		return rows.Err()
	})
	return out, e
}
func (p *Postgres) SensorActive(ctx context.Context, id transport.SensorIdentity) error {
	return p.TenantTx(ctx, id.TenantID, func(tx pgx.Tx) error {
		var ok bool
		e := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM sensors s JOIN tenants t ON t.id=s.tenant_id WHERE s.tenant_id=$1 AND s.id=$2 AND s.registration_id=$3 AND s.active AND t.active)`, id.TenantID, id.SensorID, id.RegistrationID).Scan(&ok)
		if e != nil {
			return e
		}
		if !ok {
			return ErrSensorInactive
		}
		return nil
	})
}
func (p *Postgres) Heartbeat(ctx context.Context, id transport.SensorIdentity, h model.HostHealth) error {
	b, e := json.Marshal(h)
	if e != nil {
		return e
	}
	return p.TenantTx(ctx, id.TenantID, func(tx pgx.Tx) error {
		tag, e := tx.Exec(ctx, "UPDATE sensors SET last_seen=now(),health=$4 WHERE tenant_id=$1 AND id=$2 AND registration_id=$3 AND active", id.TenantID, id.SensorID, id.RegistrationID, b)
		if e == nil && tag.RowsAffected() != 1 {
			return fmt.Errorf("探针未注册或已停用")
		}
		return e
	})
}

type Route struct {
	Token, TenantID, SensorID, RegistrationID, StreamID, Partition string
	ExpiresAt                                                      time.Time
}

func (p *Postgres) Route(ctx context.Context, id transport.SensorIdentity, stream string) (Route, error) {
	var r Route
	r.TenantID = id.TenantID
	r.SensorID = id.SensorID
	r.RegistrationID = id.RegistrationID
	r.StreamID = stream
	e := p.TenantTx(ctx, id.TenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `INSERT INTO routes(token,tenant_id,sensor_id,registration_id,stream_id,partition_day,expires_at) VALUES($1,$2,$3,$4,$5,(now() AT TIME ZONE 'UTC')::date,now()+interval '180 days') ON CONFLICT(tenant_id,sensor_id,registration_id,stream_id,partition_day) DO UPDATE SET token=routes.token RETURNING token,partition_day::text,expires_at`, Token(), id.TenantID, id.SensorID, id.RegistrationID, stream).Scan(&r.Token, &r.Partition, &r.ExpiresAt)
	})
	return r, e
}
func (p *Postgres) ResolveRoute(ctx context.Context, id transport.SensorIdentity, token, stream string) (Route, error) {
	var r Route
	e := p.TenantTx(ctx, id.TenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT token,tenant_id,sensor_id,registration_id,stream_id,partition_day::text,expires_at FROM routes WHERE tenant_id=$1 AND sensor_id=$2 AND registration_id=$3 AND token=$4 AND stream_id=$5 AND expires_at>now()", id.TenantID, id.SensorID, id.RegistrationID, token, stream).Scan(&r.Token, &r.TenantID, &r.SensorID, &r.RegistrationID, &r.StreamID, &r.Partition, &r.ExpiresAt)
	})
	return r, e
}
func (p *Postgres) SetSensorActive(ctx context.Context, u model.Principal, id string, active bool, request string) error {
	return p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		tag, e := tx.Exec(ctx, "UPDATE sensors SET active=$3 WHERE tenant_id=$1 AND id=$2", u.TenantID, id, active)
		if e != nil {
			return e
		}
		if tag.RowsAffected() != 1 {
			return pgx.ErrNoRows
		}
		return insertOperationAudit(ctx, tx, u, fmt.Sprintf("sensor.active=%t", active), id, request)
	})
}
