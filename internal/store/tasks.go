package store

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/transport"
)

var ErrConflict = errors.New("资源修订或在途任务冲突")

type SensorTask struct {
	ID            string          `json:"id"`
	SensorID      string          `json:"sensor_id"`
	Kind          string          `json:"kind"`
	State         string          `json:"state"`
	CreatedBy     string          `json:"created_by"`
	CreatedAt     time.Time       `json:"created_at"`
	ExpiresAt     time.Time       `json:"expires_at"`
	DeliveryCount int             `json:"delivery_count"`
	UpdatedAt     time.Time       `json:"updated_at"`
	Receipt       json.RawMessage `json:"receipt"`
}
type TaskDelivery struct {
	ID                 string
	Command, Signature []byte
	ExpiresAt          time.Time
}

func (p *Postgres) CreateTask(ctx context.Context, u model.Principal, sensor, kind, key string, payload json.RawMessage, signer ed25519.PrivateKey) (string, error) {
	var id string
	request := control.Digest(append([]byte(sensor+"\x00"+kind+"\x00"), payload...))
	e := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, u.TenantID+"/task-key/"+key); e != nil {
			return e
		}
		var oldHash string
		e := tx.QueryRow(ctx, `SELECT id,request_sha256 FROM sensor_tasks WHERE tenant_id=$1 AND idempotency_key=$2`, u.TenantID, key).Scan(&id, &oldHash)
		if e == nil {
			if oldHash != request {
				return ErrConflict
			}
			return nil
		}
		if !errors.Is(e, pgx.ErrNoRows) {
			return e
		}
		if kind == "rules.replay" {
			var replay control.Replay
			if e = json.Unmarshal(payload, &replay); e != nil {
				return e
			}
			var sha string
			var size int64
			if e = tx.QueryRow(ctx, `SELECT sha256,size FROM replay_samples WHERE tenant_id=$1 AND id=$2 AND state='ready' AND expires_at>now()+interval '31 minutes' FOR SHARE`, u.TenantID, replay.SampleID).Scan(&sha, &size); e != nil {
				return e
			}
			if sha != replay.SampleSHA256 || size != replay.SampleSize {
				return ErrConflict
			}
		}
		var registration string
		if e = tx.QueryRow(ctx, `SELECT registration_id FROM sensors WHERE tenant_id=$1 AND id=$2 AND active FOR UPDATE`, u.TenantID, sensor).Scan(&registration); e != nil {
			return e
		}
		// 未曾投递的到期任务可安全终止；已投递任务需等待设备回读，不能猜测未执行。
		if _, e = tx.Exec(ctx, `UPDATE sensor_tasks SET state='expired',updated_at=now() WHERE tenant_id=$1 AND sensor_id=$2 AND state='queued' AND delivery_count=0 AND expires_at<=now()`, u.TenantID, sensor); e != nil {
			return e
		}
		id = RandomID("task_")
		now := time.Now().UTC()
		c := control.Command{ID: id, TenantID: u.TenantID, SensorID: sensor, RegistrationID: registration, Kind: kind, IssuedAt: now, ExpiresAt: now.Add(30 * time.Minute), Payload: payload}
		raw, signature, e := control.Encode(c, signer)
		if e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, `INSERT INTO sensor_tasks(tenant_id,id,sensor_id,registration_id,kind,idempotency_key,request_sha256,command,signature,command_sha256,created_by,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, u.TenantID, id, sensor, registration, kind, key, request, raw, signature, control.Digest(raw), u.ID, c.ExpiresAt); e != nil {
			var pe *pgconn.PgError
			if errors.As(e, &pe) && pe.Code == "23505" {
				return ErrConflict
			}
			return e
		}
		return insertOperationAudit(ctx, tx, u, "sensor.task."+kind, id, key)
	})
	return id, e
}
func (p *Postgres) Tasks(ctx context.Context, tenant, sensor string) ([]SensorTask, error) {
	out := []SensorTask{}
	e := p.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, `UPDATE sensor_tasks SET state='expired',updated_at=now() WHERE tenant_id=$1 AND ($2='' OR sensor_id=$2) AND state='queued' AND delivery_count=0 AND expires_at<=now()`, tenant, sensor); e != nil {
			return e
		}
		rows, e := tx.Query(ctx, `SELECT id,sensor_id,kind,state,created_by,created_at,expires_at,delivery_count,updated_at,COALESCE(receipt,'{}'::jsonb) FROM sensor_tasks WHERE tenant_id=$1 AND ($2='' OR sensor_id=$2) ORDER BY created_at DESC LIMIT 200`, tenant, sensor)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var v SensorTask
			if e = rows.Scan(&v.ID, &v.SensorID, &v.Kind, &v.State, &v.CreatedBy, &v.CreatedAt, &v.ExpiresAt, &v.DeliveryCount, &v.UpdatedAt, &v.Receipt); e != nil {
				return e
			}
			out = append(out, v)
		}
		return rows.Err()
	})
	return out, e
}
func (p *Postgres) NextTask(ctx context.Context, id transport.SensorIdentity) (*TaskDelivery, error) {
	var v TaskDelivery
	e := p.TenantTx(ctx, id.TenantID, func(tx pgx.Tx) error {

		return tx.QueryRow(ctx, `WITH picked AS (SELECT id FROM sensor_tasks WHERE tenant_id=$1 AND sensor_id=$2 AND registration_id=$3 AND state IN ('queued','delivered') AND (expires_at>now() OR delivery_count>0) AND (last_delivery_at IS NULL OR last_delivery_at<now()-interval '5 seconds') ORDER BY created_at LIMIT 1 FOR UPDATE SKIP LOCKED) UPDATE sensor_tasks SET state='delivered',delivery_count=delivery_count+1,last_delivery_at=now(),updated_at=now() FROM picked WHERE sensor_tasks.tenant_id=$1 AND sensor_tasks.id=picked.id RETURNING sensor_tasks.id,command,signature,expires_at`, id.TenantID, id.SensorID, id.RegistrationID).Scan(&v.ID, &v.Command, &v.Signature, &v.ExpiresAt)

	})
	if errors.Is(e, pgx.ErrNoRows) {
		return nil, nil
	}
	return &v, e
}
func (p *Postgres) SaveReceipt(ctx context.Context, id transport.SensorIdentity, receipt control.Receipt) error {
	if receipt.State != "running" && receipt.State != "succeeded" && receipt.State != "failed" && receipt.State != "unknown" {
		return errors.New("回执状态无效")
	}
	if receipt.StartedAt.IsZero() || len(receipt.Result) > 64*1024 || !json.Valid(receipt.Result) || len(receipt.Code) > 80 {
		return errors.New("回执内容无效")
	}
	if receipt.State == "running" && receipt.FinishedAt != nil || receipt.State != "running" && (receipt.FinishedAt == nil || receipt.FinishedAt.Before(receipt.StartedAt)) {
		return errors.New("回执时间无效")
	}
	raw, e := json.Marshal(receipt)
	if e != nil {
		return e
	}
	return p.TenantTx(ctx, id.TenantID, func(tx pgx.Tx) error {
		var state, hash string
		var existing []byte
		if e := tx.QueryRow(ctx, `SELECT state,command_sha256,receipt FROM sensor_tasks WHERE tenant_id=$1 AND id=$2 AND sensor_id=$3 AND registration_id=$4 FOR UPDATE`, id.TenantID, receipt.CommandID, id.SensorID, id.RegistrationID).Scan(&state, &hash, &existing); e != nil {
			return e
		}
		if hash != receipt.CommandSHA256 {
			return errors.New("回执与任务摘要不符")
		}
		if state == "succeeded" || state == "failed" || state == "unknown" {
			var old control.Receipt
			if e := json.Unmarshal(existing, &old); e != nil {
				return e
			}
			oldHash, e := control.JSONDigest(old.Result)
			if e != nil {
				return e
			}
			newHash, e := control.JSONDigest(receipt.Result)
			if e != nil {
				return e
			}
			if old.State != receipt.State || old.Code != receipt.Code || oldHash != newHash || !old.StartedAt.Equal(receipt.StartedAt) || !old.FinishedAt.Equal(*receipt.FinishedAt) {
				return ErrConflict
			}
			return nil
		}
		if state == "expired" || state == "cancelled" {
			return ErrConflict
		}
		_, e := tx.Exec(ctx, `UPDATE sensor_tasks SET state=$3,receipt=$4,updated_at=now() WHERE tenant_id=$1 AND id=$2`, id.TenantID, receipt.CommandID, receipt.State, raw)
		return e
	})
}
func (p *Postgres) CancelTask(ctx context.Context, u model.Principal, id, requestID string) error {
	return p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		v, e := tx.Exec(ctx, `UPDATE sensor_tasks SET state='cancelled',updated_at=now() WHERE tenant_id=$1 AND id=$2 AND state='queued' AND delivery_count=0 AND expires_at>now()`, u.TenantID, id)
		if e != nil {
			return e
		}
		if v.RowsAffected() != 1 {
			return ErrConflict
		}
		return insertOperationAudit(ctx, tx, u, "sensor.task.cancel", id, requestID)
	})
}
