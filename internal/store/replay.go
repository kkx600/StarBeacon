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
	if v.Origin != nil && !v.Origin.Valid() {
		return errors.New("样本来源描述无效")
	}
	origin, err := json.Marshal(v.Origin)
	if err != nil {
		return err
	}
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
		_, e := tx.Exec(ctx, `INSERT INTO replay_samples(tenant_id,id,name,size,state,created_by,expires_at,origin) VALUES($1,$2,$3,$4,'uploading',$5,now()+make_interval(days=>COALESCE((SELECT days FROM retention_policies WHERE tenant_id=$1 AND category='pcap'),180)),$6)`, u.TenantID, v.ID, v.Name, v.Size, u.ID, origin)
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
	var origin []byte
	e := row.Scan(&v.ID, &v.Name, &v.Size, &v.SHA256, &v.Format, &v.CreatedAt, &v.ExpiresAt, &origin)
	if e == nil {
		e = json.Unmarshal(origin, &v.Origin)
		if e == nil && v.Origin != nil && !v.Origin.Valid() {
			e = errors.New("样本来源描述无效")
		}
	}
	return v, e
}
func (p *Postgres) Sample(ctx context.Context, tenant, id string) (replay.Sample, error) {
	var v replay.Sample
	e := p.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		var e error
		v, e = scanSample(tx.QueryRow(ctx, `SELECT id,name,size,sha256,format,created_at,expires_at,origin FROM replay_samples WHERE tenant_id=$1 AND id=$2 AND state='ready' AND expires_at>now()`, tenant, id))
		return e
	})
	return v, e
}
func (p *Postgres) Samples(ctx context.Context, tenant string) ([]replay.Sample, error) {
	out := []replay.Sample{}
	e := p.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT id,name,size,sha256,format,created_at,expires_at,origin FROM replay_samples WHERE tenant_id=$1 AND state='ready' AND expires_at>now() ORDER BY created_at DESC LIMIT 200`, tenant)
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
		v, e = scanSample(tx.QueryRow(ctx, `SELECT id,name,size,sha256,format,created_at,expires_at,origin FROM replay_samples WHERE tenant_id=$1 AND id=$2 AND state='ready' AND expires_at>now()`, id.TenantID, sample))
		if e != nil {
			return e
		}
		if v.SHA256 != r.SampleSHA256 || v.Size != r.SampleSize || !replay.SameOrigin(v.Origin, r.Origin) {
			return errors.New("重放样本与任务不一致")
		}
		return nil
	})
	return v, e
}

const sampleCleanupEligible = `(s.state='deleting' OR s.expires_at<now()-interval '5 minutes'
 OR (s.state IN ('uploading','failed') AND s.created_at<now()-interval '1 hour'))
 AND NOT EXISTS(SELECT 1 FROM rule_generation_jobs g WHERE g.tenant_id=s.tenant_id AND g.sample_id=s.id AND g.state IN ('queued','running') AND g.deadline>now())
 AND NOT EXISTS(SELECT 1 FROM sensor_tasks t WHERE t.tenant_id=s.tenant_id AND t.kind='rules.replay'
 AND t.state IN ('queued','delivered','running') AND t.expires_at>now()
 AND t.replay_sample_id=s.id)`

// SweepSamples 每轮最多扫描 32 个租户及处理 100 个样本；对象删除期间不占用数据库事务或连接。
func (p *Postgres) SweepSamples(ctx context.Context, objects replay.Storage) error {
	if objects == nil {
		return errors.New("样本对象存储未配置")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !p.sampleSweepMu.TryLock() {
		return errors.New("样本清理正在运行")
	}
	defer p.sampleSweepMu.Unlock()
	tenants, err := p.sampleCleanupTenants(ctx, p.sampleSweepAfter)
	if err != nil {
		return err
	}
	if len(tenants) == 0 && p.sampleSweepAfter != "" {
		p.sampleSweepAfter = ""
		tenants, err = p.sampleCleanupTenants(ctx, "")
		if err != nil {
			return err
		}
	}
	remaining := 100
	var failures []error
	for _, tenant := range tenants {
		if err := ctx.Err(); err != nil {
			return errors.Join(append(failures, err)...)
		}
		ids, err := p.sampleCleanupCandidates(ctx, tenant, remaining)
		if err != nil {
			failures = append(failures, err)
		} else {
			for _, id := range ids {
				remaining--
				if err := p.removeExpiredSample(ctx, tenant, id, objects); err != nil {
					failures = append(failures, err)
				}
				if err := ctx.Err(); err != nil {
					return errors.Join(append(failures, err)...)
				}
			}
		}
		// 进程内游标轮转使持续有积压的租户不独占每一轮；重启从首个租户重新扫描。
		p.sampleSweepAfter = tenant
		if remaining == 0 {
			break
		}
	}
	return errors.Join(failures...)
}

func (p *Postgres) sampleCleanupTenants(ctx context.Context, after string) ([]string, error) {
	rows, err := p.Pool.Query(ctx, `SELECT id FROM tenants WHERE id>$1 ORDER BY id LIMIT 32`, after)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func (p *Postgres) sampleCleanupCandidates(ctx context.Context, tenant string, limit int) ([]string, error) {
	out := []string{}
	err := p.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id FROM replay_samples s WHERE tenant_id=$1 AND `+sampleCleanupEligible+` ORDER BY expires_at,id LIMIT $2`, tenant, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return err
			}
			out = append(out, id)
		}
		return rows.Err()
	})
	return out, err
}

func (p *Postgres) removeExpiredSample(ctx context.Context, tenant, id string, objects replay.Storage) error {
	claimed := false
	err := p.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE replay_samples s SET state='deleting' WHERE tenant_id=$1 AND id=$2 AND `+sampleCleanupEligible, tenant, id)
		claimed = err == nil && tag.RowsAffected() == 1
		return err
	})
	if err != nil || !claimed {
		return err
	}
	// 持久删除标记先提交，崩溃或对象存储错误时继续占用额度，后续轮次可安全重试。
	if err := objects.Remove(ctx, replay.Key(tenant, id)); err != nil {
		return err
	}
	return p.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM replay_samples WHERE tenant_id=$1 AND id=$2 AND state='deleting'`, tenant, id)
		return err
	})
}
