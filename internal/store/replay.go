package store

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/replay"
	"github.com/kkx600/StarBeacon/internal/transport"
)

func (p *Postgres) ReserveSample(ctx context.Context, u model.Principal, v replay.Sample, quota int64) error {
	return p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, u.TenantID+"/replay-quota"); e != nil {
			return e
		}
		var used int64
		var count int
		if e := tx.QueryRow(ctx, `SELECT COALESCE(sum(size),0),count(*) FROM replay_samples WHERE tenant_id=$1`, u.TenantID).Scan(&used, &count); e != nil {
			return e
		}
		if v.Size > quota-used || count >= replay.MaxSamples {
			return replay.ErrQuota
		}
		_, e := tx.Exec(ctx, `INSERT INTO replay_samples(tenant_id,id,name,size,state,created_by,expires_at) VALUES($1,$2,$3,$4,'uploading',$5,now()+make_interval(days=>COALESCE((SELECT days FROM retention_policies WHERE tenant_id=$1 AND category='pcap'),180)))`, u.TenantID, v.ID, v.Name, v.Size, u.ID)
		return e
	})
}
func (p *Postgres) CompleteSample(ctx context.Context, u model.Principal, id, sha, format, request string) error {
	return p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		tag, e := tx.Exec(ctx, `UPDATE replay_samples SET state='ready',sha256=$3,format=$4 WHERE tenant_id=$1 AND id=$2 AND state='uploading'`, u.TenantID, id, sha, format)
		if e != nil {
			return e
		}
		if tag.RowsAffected() != 1 {
			return pgx.ErrNoRows
		}
		return insertOperationAudit(ctx, tx, u, "replay.sample.import", id, request)
	})
}
func scanSample(row pgx.Row) (replay.Sample, error) {
	var v replay.Sample
	e := row.Scan(&v.ID, &v.Name, &v.Size, &v.SHA256, &v.Format, &v.CreatedAt, &v.ExpiresAt)
	return v, e
}
func (p *Postgres) Sample(ctx context.Context, tenant, id string) (replay.Sample, error) {
	var v replay.Sample
	e := p.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		var e error
		v, e = scanSample(tx.QueryRow(ctx, `SELECT id,name,size,sha256,format,created_at,expires_at FROM replay_samples WHERE tenant_id=$1 AND id=$2 AND state='ready' AND expires_at>now()`, tenant, id))
		return e
	})
	return v, e
}
func (p *Postgres) Samples(ctx context.Context, tenant string) ([]replay.Sample, error) {
	out := []replay.Sample{}
	e := p.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT id,name,size,sha256,format,created_at,expires_at FROM replay_samples WHERE tenant_id=$1 AND state='ready' AND expires_at>now() ORDER BY created_at DESC LIMIT 200`, tenant)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			v, e := scanSample(rows)
			if e != nil {
				return e
			}
			out = append(out, v)
		}
		return rows.Err()
	})
	return out, e
}
func (p *Postgres) RemoveSampleRow(ctx context.Context, tenant, id string) error {
	return p.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `DELETE FROM replay_samples WHERE tenant_id=$1 AND id=$2`, tenant, id)
		return e
	})
}
func (p *Postgres) SampleForTask(ctx context.Context, id transport.SensorIdentity, task, sample string) (replay.Sample, error) {
	var v replay.Sample
	e := p.TenantTx(ctx, id.TenantID, func(tx pgx.Tx) error {
		var raw []byte
		if e := tx.QueryRow(ctx, `SELECT command FROM sensor_tasks WHERE tenant_id=$1 AND id=$2 AND sensor_id=$3 AND registration_id=$4 AND kind='rules.replay' AND state IN ('delivered','running') AND expires_at>now()`, id.TenantID, task, id.SensorID, id.RegistrationID).Scan(&raw); e != nil {
			return e
		}
		var c control.Command
		var r control.Replay
		if e := json.Unmarshal(raw, &c); e != nil {
			return e
		}
		if e := json.Unmarshal(c.Payload, &r); e != nil {
			return e
		}
		if r.SampleID != sample {
			return pgx.ErrNoRows
		}
		var e error
		v, e = scanSample(tx.QueryRow(ctx, `SELECT id,name,size,sha256,format,created_at,expires_at FROM replay_samples WHERE tenant_id=$1 AND id=$2 AND state='ready' AND expires_at>now()`, id.TenantID, sample))
		if e != nil {
			return e
		}
		if v.SHA256 != r.SampleSHA256 || v.Size != r.SampleSize {
			return errors.New("重放样本与任务不一致")
		}
		return nil
	})
	return v, e
}

// SweepSamples 先删除对象再删除索引；中断时可重复执行，不释放尚未确认删除的容量。
func (p *Postgres) SweepSamples(ctx context.Context, objects replay.Storage) error {
	rows, e := p.Pool.Query(ctx, `SELECT id FROM tenants ORDER BY id`)
	if e != nil {
		return e
	}
	tenants := []string{}
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			return e
		}
		tenants = append(tenants, id)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	for _, tenant := range tenants {
		e = p.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
			rows, e := tx.Query(ctx, `SELECT id FROM replay_samples s WHERE tenant_id=$1 AND (expires_at<now()-interval '5 minutes' OR (state IN ('uploading','failed') AND created_at<now()-interval '1 hour')) AND NOT EXISTS(SELECT 1 FROM sensor_tasks t WHERE t.tenant_id=s.tenant_id AND t.kind='rules.replay' AND t.state IN ('queued','delivered','running') AND t.expires_at>now() AND (convert_from(t.command,'UTF8')::jsonb)->'payload'->>'sample_id'=s.id) LIMIT 100`, tenant)
			if e != nil {
				return e
			}
			ids := []string{}
			for rows.Next() {
				var id string
				if e = rows.Scan(&id); e != nil {
					rows.Close()
					return e
				}
				ids = append(ids, id)
			}
			e = rows.Err()
			rows.Close()
			if e != nil {
				return e
			}
			for _, id := range ids {
				if e = objects.Remove(ctx, replay.Key(tenant, id)); e != nil {
					return e
				}
				if _, e = tx.Exec(ctx, `DELETE FROM replay_samples WHERE tenant_id=$1 AND id=$2`, tenant, id); e != nil {
					return e
				}
			}
			return nil
		})
		if e != nil {
			return e
		}
	}
	return nil
}
