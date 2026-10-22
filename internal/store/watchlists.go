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
	"github.com/kkx600/StarBeacon/internal/watchlist"
)

const watchlistColumns = `v.tenant_id,v.list_id,v.revision,v.name,v.description,v.active,v.definition,v.definition_sha256,v.created_by,v.created_at,v.expires_at`

func readWatchlist(row interface{ Scan(...any) error }, head bool) (watchlist.Record, error) {
	var out watchlist.Record
	var raw json.RawMessage
	var name, kind string
	var active bool
	fields := []any{&out.TenantID, &out.ID, &out.Revision, &out.Name, &out.Description, &out.Active, &raw, &out.DefinitionSHA256, &out.CreatedBy, &out.CreatedAt, &out.ExpiresAt}
	if head {
		fields = append(fields, &name, &kind, &active)
	}
	if e := row.Scan(fields...); e != nil {
		return out, e
	}
	if json.Unmarshal(raw, &out.Definition) != nil || out.Validate() != nil || head && (name != out.Name || kind != out.Definition.Kind || active != out.Active) {
		return out, watchlist.ErrSource
	}
	return out, nil
}

func watchlistActor(ctx context.Context, tx pgx.Tx, u model.Principal, write bool) error {
	return configurationActor(ctx, tx, u, write, watchlist.ErrPermission)
}

func (p *Postgres) Watchlists(ctx context.Context, u model.Principal, q watchlist.Query) (watchlist.Page, error) {
	out := watchlist.Page{Items: []watchlist.Record{}}
	after, e := q.Position(u.TenantID)
	if e != nil {
		return out, e
	}
	e = p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if e := watchlistActor(ctx, tx, u, false); e != nil {
			return e
		}
		pattern := "%" + strings.NewReplacer("!", "!!", "%", "!%", "_", "!_").Replace(q.Keyword) + "%"
		rows, e := tx.Query(ctx, `SELECT `+watchlistColumns+`,h.name,h.kind,h.active FROM watchlists h JOIN watchlist_revisions v ON v.tenant_id=h.tenant_id AND v.list_id=h.id AND v.revision=h.revision WHERE h.tenant_id=$1 AND h.id>$2 AND h.name ILIKE $3 ESCAPE '!' AND ($4='' OR h.active=($4='true')) AND ($5='' OR h.kind=$5) ORDER BY h.id LIMIT $6`, u.TenantID, after, pattern, q.Active, q.Kind, q.Limit+1)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			record, e := readWatchlist(rows, true)
			if e != nil {
				return e
			}
			out.Items = append(out.Items, record)
		}
		return rows.Err()
	})
	if len(out.Items) > q.Limit {
		out.NextCursor = q.Next(u.TenantID, out.Items[q.Limit-1].ID)
		out.Items = out.Items[:q.Limit]
	}
	return out, e
}

func (p *Postgres) Watchlist(ctx context.Context, u model.Principal, id string, revision int64) (watchlist.Record, error) {
	var out watchlist.Record
	if !contract.ValidID(id) || revision < 1 || revision > watchlist.MaxRevision {
		return out, watchlist.ErrInput
	}
	e := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if e := watchlistActor(ctx, tx, u, false); e != nil {
			return e
		}
		var e error
		out, e = readWatchlist(tx.QueryRow(ctx, `SELECT `+watchlistColumns+` FROM watchlist_revisions v WHERE v.tenant_id=$1 AND v.list_id=$2 AND v.revision=$3 AND (v.expires_at>now() OR EXISTS(SELECT 1 FROM watchlists h WHERE h.tenant_id=v.tenant_id AND h.id=v.list_id AND h.revision=v.revision))`, u.TenantID, id, revision), false)
		return e
	})
	return out, e
}

func watchlistSensorScope(ctx context.Context, tx pgx.Tx, tenant string, sensors []watchlist.Sensor) error {
	// 登记冻结注册身份，不锁定或授权设备；随后重注册的探针不能继承旧范围。
	for _, sensor := range sensors {
		var registration string
		var active bool
		e := tx.QueryRow(ctx, `SELECT registration_id,active FROM sensors WHERE tenant_id=$1 AND id=$2`, tenant, sensor.SensorID).Scan(&registration, &active)
		if errors.Is(e, pgx.ErrNoRows) {
			return ErrConflict
		}
		if e != nil {
			return e
		}
		if !active || registration != sensor.RegistrationID {
			return ErrConflict
		}
	}
	return nil
}

func (p *Postgres) SaveWatchlist(ctx context.Context, u model.Principal, key string, c watchlist.Change) (watchlist.Record, error) {
	var out watchlist.Record
	if c.Validate() != nil || !contract.ValidID(key) {
		return out, watchlist.ErrInput
	}
	e := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, `SET LOCAL lock_timeout='2s'; SET LOCAL statement_timeout='5s'`); e != nil {
			return e
		}
		if e := watchlistActor(ctx, tx, u, true); e != nil {
			return e
		}
		if _, e := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, u.TenantID+"/watchlists"); e != nil {
			return e
		}
		var input string
		e := tx.QueryRow(ctx, `SELECT input_hash FROM watchlist_revisions WHERE tenant_id=$1 AND created_by=$2 AND key_hash=$3`, u.TenantID, u.ID, Hash(key)).Scan(&input)
		if e == nil {
			if input != watchlist.Digest(c) {
				return ErrConflict
			}
			out, e = readWatchlist(tx.QueryRow(ctx, `SELECT `+watchlistColumns+` FROM watchlist_revisions v WHERE v.tenant_id=$1 AND v.created_by=$2 AND v.key_hash=$3`, u.TenantID, u.ID, Hash(key)), false)
			if e == nil && !out.ExpiresAt.After(time.Now()) {
				return ErrConflict
			}
			return e
		}
		if !errors.Is(e, pgx.ErrNoRows) {
			return e
		}
		var current watchlist.Record
		current, e = readWatchlist(tx.QueryRow(ctx, `SELECT `+watchlistColumns+`,h.name,h.kind,h.active FROM watchlists h JOIN watchlist_revisions v ON v.tenant_id=h.tenant_id AND v.list_id=h.id AND v.revision=h.revision WHERE h.tenant_id=$1 AND h.id=$2 FOR UPDATE OF h`, u.TenantID, c.ID), true)
		if e != nil && !errors.Is(e, pgx.ErrNoRows) {
			return e
		}
		if errors.Is(e, pgx.ErrNoRows) && c.ExpectedRevision > 0 {
			return pgx.ErrNoRows
		}
		if current.Revision != c.ExpectedRevision {
			return ErrConflict
		}
		if current.Revision > 0 && current.Name == c.Name && current.Description == c.Description && current.Active == *c.Active && current.DefinitionSHA256 == watchlist.Digest(c.Definition) {
			return watchlist.ErrInput
		}
		var now time.Time
		if e := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); e != nil {
			return e
		}
		if *c.Active && !c.Definition.Admissible(now) {
			return watchlist.ErrInput
		}
		// 旧范围失效后仍允许停用原配置；创建、改范围或重新启用必须核对当前注册。
		if *c.Active || current.Revision == 0 || current.DefinitionSHA256 != watchlist.Digest(c.Definition) {
			if e := watchlistSensorScope(ctx, tx, u.TenantID, c.Definition.Sensors); e != nil {
				return e
			}
		}
		var count int
		if current.Revision == 0 {
			if e := tx.QueryRow(ctx, `SELECT count(*) FROM watchlists WHERE tenant_id=$1`, u.TenantID).Scan(&count); e != nil {
				return e
			}
			if count >= watchlist.MaxLists {
				return watchlist.ErrQuota
			}
		}
		if e := tx.QueryRow(ctx, `SELECT count(*) FROM watchlist_revisions WHERE tenant_id=$1 AND created_at>now()-interval '24 hours'`, u.TenantID).Scan(&count); e != nil {
			return e
		}
		if count >= watchlist.MaxDailyChanges {
			return watchlist.ErrQuota
		}
		raw, e := json.Marshal(c.Definition)
		if e != nil {
			return e
		}
		out, e = readWatchlist(tx.QueryRow(ctx, `INSERT INTO watchlist_revisions AS v(tenant_id,list_id,revision,name,description,active,definition,definition_sha256,created_by,key_hash,input_hash,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,now()+make_interval(days=>COALESCE((SELECT days FROM retention_policies WHERE tenant_id=$1 AND category='operations'),180))) RETURNING `+watchlistColumns, u.TenantID, c.ID, c.ExpectedRevision+1, c.Name, c.Description, *c.Active, raw, watchlist.Digest(c.Definition), u.ID, Hash(key), watchlist.Digest(c)), false)
		if e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, `INSERT INTO watchlists(tenant_id,id,revision,name,kind,active) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(tenant_id,id) DO UPDATE SET revision=EXCLUDED.revision,name=EXCLUDED.name,kind=EXCLUDED.kind,active=EXCLUDED.active`, u.TenantID, c.ID, out.Revision, c.Name, c.Definition.Kind, *c.Active); e != nil {
			return e
		}
		return insertOperationAudit(ctx, tx, u, "watchlist.save", c.ID, model.RequestMetadataFrom(ctx).RequestID)
	})
	if e == nil && (out.TenantID != u.TenantID || out.ID != c.ID || out.Revision != c.ExpectedRevision+1 || out.CreatedBy != u.ID || out.Name != c.Name || out.Description != c.Description || out.Active != *c.Active || out.DefinitionSHA256 != watchlist.Digest(c.Definition)) {
		return out, watchlist.ErrSource
	}
	return out, e
}

func (p *Postgres) PreviewWatchlist(ctx context.Context, u model.Principal, input watchlist.PreviewRequest) (watchlist.Preview, error) {
	var out watchlist.Preview
	if input.Validate() != nil {
		return out, watchlist.ErrInput
	}
	e := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if e := watchlistActor(ctx, tx, u, true); e != nil {
			return e
		}
		if e := watchlistSensorScope(ctx, tx, u.TenantID, input.Definition.Sensors); e != nil {
			return e
		}
		var now time.Time
		if e := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); e != nil {
			return e
		}
		var e error
		out, e = input.Evaluate(now)
		if e != nil {
			return e
		}
		return insertOperationAudit(ctx, tx, u, "watchlist.preview", out.DefinitionSHA256, model.RequestMetadataFrom(ctx).RequestID)
	})
	return out, e
}

// CheckWatchlistResponseTx 仅约束调用事务之后签发的新单 IP 封禁，不追溯撤销既有任务。
// 调用方必须已核对用户、探针注册和任务授权；解除与回读不得调用此门禁。
func CheckWatchlistResponseTx(ctx context.Context, tx pgx.Tx, tenant, sensor, registration, targetIP string, now time.Time) (watchlist.ResponseCheck, error) {
	out := watchlist.ResponseCheck{SchemaVersion: watchlist.ResponseSchema, CheckedAt: now.UTC(), Matches: []watchlist.Reference{}}
	target := watchlist.Target{SensorID: sensor, RegistrationID: registration, Type: "ip", Value: targetIP}
	if !contract.ValidID(tenant) || !target.Valid() || now.IsZero() {
		return out, watchlist.ErrInput
	}
	var transactionTenant string
	if err := tx.QueryRow(ctx, `SELECT current_setting('starbeacon.tenant_id',true)`).Scan(&transactionTenant); err != nil {
		return out, err
	}
	if transactionTenant != tenant {
		return out, watchlist.ErrPermission
	}
	if _, e := tx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared(hashtextextended($1,0))`, tenant+"/watchlists"); e != nil {
		return out, e
	}
	// 取得锁后读取实际核对时间，避免等待期间跨越名单生效点仍使用旧时刻。
	var checkedAt time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&checkedAt); err != nil {
		return out, err
	}
	now = checkedAt.UTC()
	out.CheckedAt = now
	rows, e := tx.Query(ctx, `SELECT `+watchlistColumns+`,h.name,h.kind,h.active FROM watchlists h JOIN watchlist_revisions v ON v.tenant_id=h.tenant_id AND v.list_id=h.id AND v.revision=h.revision WHERE h.tenant_id=$1 ORDER BY h.id LIMIT $2`, tenant, watchlist.MaxLists+1)
	if e != nil {
		return out, e
	}
	defer rows.Close()
	state := []watchlist.Reference{}
	for rows.Next() {
		record, e := readWatchlist(rows, true)
		if e != nil {
			return out, e
		}
		if len(state) >= watchlist.MaxLists {
			return out, watchlist.ErrLimit
		}
		ref := watchlist.Reference{ID: record.ID, Revision: record.Revision, DefinitionSHA256: record.DefinitionSHA256}
		state = append(state, ref)
		if record.TenantID != tenant {
			return out, watchlist.ErrSource
		}
		if record.Definition.Kind == "protect" && record.Definition.Effective(record.Active, now) && record.Definition.Matches(target) {
			out.Matches = append(out.Matches, ref)
		}
	}
	if e := rows.Err(); e != nil {
		return out, e
	}
	out.StateSHA256 = watchlist.Digest(state)
	if len(out.Matches) > 0 {
		return out, watchlist.ErrProtected
	}
	return out, nil
}
