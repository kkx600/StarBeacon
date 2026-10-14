package store

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/kkx600/StarBeacon/internal/application"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/model"
	responseapi "github.com/kkx600/StarBeacon/internal/response"
	"github.com/kkx600/StarBeacon/internal/transport"
)

var ErrConflict = errors.New("资源修订或在途任务冲突")

type SensorTask struct {
	ResponseAction *responseapi.Action `json:"response_action,omitempty"`
	ID             string              `json:"id"`
	SensorID       string              `json:"sensor_id"`
	Kind           string              `json:"kind"`
	State          string              `json:"state"`
	CreatedBy      string              `json:"created_by"`
	CreatedAt      time.Time           `json:"created_at"`
	ExpiresAt      time.Time           `json:"expires_at"`
	RetainUntil    time.Time           `json:"retain_until"`
	DeliveryCount  int                 `json:"delivery_count"`
	UpdatedAt      time.Time           `json:"updated_at"`
	Receipt        json.RawMessage     `json:"receipt"`
	RuleResolution json.RawMessage     `json:"rule_resolution,omitempty"`
}
type TaskDelivery struct {
	ID                 string
	Command, Signature []byte
	ExpiresAt          time.Time
}

func (p *Postgres) CreateTask(ctx context.Context, u model.Principal, sensor, kind, key string, payload json.RawMessage, signer ed25519.PrivateKey) (string, error) {
	var id string
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		var err error
		id, err = createTaskTx(ctx, tx, u, sensor, kind, key, payload, signer, false)
		return err
	})
	return id, err
}

// 同一事务供人工任务与研判处置确认复用，保持签名、预算、审计及在途约束一致。
func createTaskTx(ctx context.Context, tx pgx.Tx, u model.Principal, sensor, kind, key string, payload json.RawMessage, signer ed25519.PrivateKey, mustCreate bool) (string, error) {
	var id string
	var sampleID *string
	request := control.Digest(append([]byte(sensor+"\x00"+kind+"\x00"), payload...))
	if strings.HasPrefix(kind, "response.") || kind == "applications.apply" {
		request = control.Digest(append([]byte(u.ID+"\x00"+sensor+"\x00"+kind+"\x00"), payload...))
	}
	e := func() error {
		if kind == "applications.apply" {
			if err := applicationRuleUser(ctx, tx, u, true); err != nil {
				return err
			}
		}
		if strings.HasPrefix(kind, "response.") {
			if err := responseTaskActor(ctx, tx, u); err != nil {
				return err
			}
		}
		if _, e := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, u.TenantID+"/task-key/"+key); e != nil {
			return e
		}
		var oldHash string
		e := tx.QueryRow(ctx, `SELECT id,request_sha256 FROM sensor_tasks WHERE tenant_id=$1 AND idempotency_key=$2`, u.TenantID, key).Scan(&id, &oldHash)
		if e == nil {
			if mustCreate || oldHash != request {
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
			sampleID = &replay.SampleID
		}
		var registration string
		if e = tx.QueryRow(ctx, `SELECT registration_id FROM sensors WHERE tenant_id=$1 AND id=$2 AND active FOR UPDATE`, u.TenantID, sensor).Scan(&registration); e != nil {
			return e
		}
		if kind == "capture.configure" {
			if len(signer) != ed25519.PrivateKeySize {
				return errors.New("任务签名密钥未配置")
			}
			if e = qualifyCaptureTask(ctx, tx, u.TenantID, sensor, registration, payload, signer); e != nil {
				return e
			}
		}
		if kind == "applications.apply" {
			payload, e = qualifyApplicationTask(ctx, tx, u, sensor, registration, payload, signer)
			if e != nil {
				return e
			}
		}
		if kind == "rules.apply" {
			var unresolved int
			if e = tx.QueryRow(ctx, `SELECT count(*) FROM sensor_tasks WHERE tenant_id=$1 AND sensor_id=$2 AND kind='rules.apply' AND state='unknown' AND rule_resolution IS NULL`, u.TenantID, sensor).Scan(&unresolved); e != nil {
				return e
			}
			if unresolved != 0 {
				return ErrConflict
			}
			payload, e = qualifyRuleTask(ctx, tx, u.TenantID, sensor, registration, payload, signer)
			if e != nil {
				return e
			}
		}
		if kind == "rules.reconcile" {
			payload, e = reconcileRuleTask(ctx, tx, u.TenantID, sensor, registration, payload, signer)
			if e != nil {
				return e
			}
		}
		// 未曾投递的到期任务可安全终止；已投递任务需等待设备回读，不能猜测未执行。
		if _, e = tx.Exec(ctx, `UPDATE sensor_tasks SET state='expired',updated_at=now() WHERE tenant_id=$1 AND sensor_id=$2 AND state='queued' AND delivery_count=0 AND expires_at<=now()`, u.TenantID, sensor); e != nil {
			return e
		}
		id = RandomID("task_")
		now := time.Now().UTC()
		c := control.Command{ID: id, TenantID: u.TenantID, SensorID: sensor, RegistrationID: registration, Kind: kind, IssuedAt: now, ExpiresAt: now.Add(30 * time.Minute), Payload: payload}
		if strings.HasPrefix(kind, "response.") {
			c.Payload, c.ExpiresAt, e = qualifyResponseTask(ctx, tx, u, sensor, registration, kind, id, now, payload, signer)
			if e != nil {
				return e
			}
		}
		raw, signature, e := control.Encode(c, signer)
		if e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, `INSERT INTO sensor_tasks(tenant_id,id,sensor_id,registration_id,kind,idempotency_key,request_sha256,command,signature,command_sha256,created_by,expires_at,retain_until,replay_sample_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,now()+make_interval(days=>COALESCE((SELECT days FROM retention_policies WHERE tenant_id=$1 AND category='operations'),180)),$13)`, u.TenantID, id, sensor, registration, kind, key, request, raw, signature, control.Digest(raw), u.ID, c.ExpiresAt, sampleID); e != nil {
			var pe *pgconn.PgError
			if errors.As(e, &pe) && pe.Code == "23505" {
				return ErrConflict
			}
			return e
		}
		return insertOperationAudit(ctx, tx, u, "sensor.task."+kind, id, key)
	}()
	return id, e
}

const taskColumns = `id,sensor_id,kind,state,created_by,created_at,expires_at,retain_until,delivery_count,updated_at,COALESCE(receipt,'{}'::jsonb),rule_resolution,CASE WHEN kind LIKE 'response.%' THEN command ELSE NULL END,command_sha256,registration_id`

// 字段唯一性覆盖整个 JSON；命令封套与嵌套授权分别限定各自字段，不能混用层级。
func storedResponseCommand(raw []byte) (control.Command, error) {
	var c control.Command
	outer := []string{"id", "tenant_id", "sensor_id", "registration_id", "kind", "issued_at", "expires_at", "payload"}
	fields := append(append([]string{}, outer...), "schema_version", "connector_id", "config_sha256", "device_id", "lease_id", "owner_sha256", "target_ip", "requested_at", "reason")
	var root map[string]json.RawMessage
	if contract.JSONFields(string(raw), fields, 8192) != nil || json.Unmarshal(raw, &root) != nil || len(root) != len(outer) {
		return c, responseapi.ErrInput
	}
	for _, name := range outer {
		if _, ok := root[name]; !ok {
			return c, responseapi.ErrInput
		}
	}
	if json.Unmarshal(raw, &c) != nil || control.Validate(c) != nil {
		return c, responseapi.ErrInput
	}
	return c, nil
}

func storedTaskBinding(c control.Command, raw []byte, task SensorTask, tenant, registration, sha string) bool {
	// pgx 二进制时间戳以微秒截断；原签名命令的完整纳秒仍由原始字节摘要保护。
	return control.Digest(raw) == sha && c.ID == task.ID && c.TenantID == tenant && c.SensorID == task.SensorID && c.RegistrationID == registration && c.Kind == task.Kind && c.ExpiresAt.Truncate(time.Microsecond).Equal(task.ExpiresAt)
}

// 历史读取核对原始命令身份，不依赖当前探针注册、签名配置或设备在线状态。
func scanSensorTask(row pgx.Row, tenant string) (SensorTask, error) {
	var v SensorTask
	var rawCommand []byte
	var commandSHA, registration string
	if err := row.Scan(&v.ID, &v.SensorID, &v.Kind, &v.State, &v.CreatedBy, &v.CreatedAt, &v.ExpiresAt, &v.RetainUntil, &v.DeliveryCount, &v.UpdatedAt, &v.Receipt, &v.RuleResolution, &rawCommand, &commandSHA, &registration); err != nil {
		return v, err
	}
	if strings.HasPrefix(v.Kind, "response.") {
		c, err := storedResponseCommand(rawCommand)
		if err != nil || !storedTaskBinding(c, rawCommand, v, tenant, registration, commandSHA) {
			return v, responseapi.ErrInput
		}
		a, err := responseapi.ReadAction(c.Payload)
		if err != nil {
			return v, err
		}
		v.ResponseAction = &a
	}
	return v, nil
}

// 单条主键查询覆盖超过列表上限的历史任务；执行到期和记录留存分别处理。
func (p *Postgres) Task(ctx context.Context, tenant, id string) (SensorTask, error) {
	var out SensorTask
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	err := p.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout='2s'; SET LOCAL statement_timeout='4s'`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE sensor_tasks SET state='expired',updated_at=now() WHERE tenant_id=$1 AND id=$2 AND retain_until>now() AND state='queued' AND delivery_count=0 AND expires_at<=now()`, tenant, id); err != nil {
			return err
		}
		var err error
		out, err = scanSensorTask(tx.QueryRow(ctx, `SELECT `+taskColumns+` FROM sensor_tasks WHERE tenant_id=$1 AND id=$2 AND retain_until>now()`, tenant, id), tenant)
		return err
	})
	return out, err
}

func (p *Postgres) Tasks(ctx context.Context, tenant, sensor string) ([]SensorTask, error) {
	out := []SensorTask{}
	e := p.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, `UPDATE sensor_tasks SET state='expired',updated_at=now() WHERE tenant_id=$1 AND ($2='' OR sensor_id=$2) AND state='queued' AND delivery_count=0 AND expires_at<=now()`, tenant, sensor); e != nil {
			return e
		}
		rows, e := tx.Query(ctx, `SELECT `+taskColumns+` FROM sensor_tasks WHERE tenant_id=$1 AND ($2='' OR sensor_id=$2) AND retain_until>now() ORDER BY created_at DESC,id DESC LIMIT 200`, tenant, sensor)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			v, err := scanSensorTask(rows, tenant)
			if err != nil {
				return err
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
		// 与创建和核实任务按相同顺序锁定设备，避免核实原任务与新发布交错。
		var registration string
		if e := tx.QueryRow(ctx, `SELECT registration_id FROM sensors WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, id.TenantID, id.SensorID).Scan(&registration); e != nil {
			return e
		}
		if registration != id.RegistrationID {
			return ErrConflict
		}
		var state, hash, kind, createdBy string
		var existing, command []byte
		if e := tx.QueryRow(ctx, `SELECT state,command_sha256,receipt,kind,command,created_by FROM sensor_tasks WHERE tenant_id=$1 AND id=$2 AND sensor_id=$3 AND registration_id=$4 FOR UPDATE`, id.TenantID, receipt.CommandID, id.SensorID, id.RegistrationID).Scan(&state, &hash, &existing, &kind, &command, &createdBy); e != nil {
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
		if kind == "rules.reconcile" && receipt.State == "succeeded" {
			if e := saveRuleResolution(ctx, tx, id, receipt.CommandID, createdBy, command, receipt); e != nil {
				return e
			}
		}
		if kind == "capture.configure" && receipt.State == "succeeded" {
			if receipt.Code != "" {
				return errors.New("成功的采集配置回执不能包含失败代码")
			}
			var c control.Command
			if e := json.Unmarshal(command, &c); e != nil {
				return e
			}
			p, e := control.ReadCaptureConfiguration(c.Payload)
			if e != nil {
				return e
			}
			if e = control.ValidateCaptureResult(p, receipt.Result); e != nil {
				return e
			}
		}
		if kind == "applications.apply" && receipt.State == "succeeded" {
			var c control.Command
			if json.Unmarshal(command, &c) != nil || control.Validate(c) != nil || c.ID != receipt.CommandID || c.TenantID != id.TenantID || c.SensorID != id.SensorID || c.RegistrationID != id.RegistrationID {
				return application.ErrInput
			}
			if err := validateApplicationReceipt(c, receipt); err != nil {
				return err
			}
		}
		if strings.HasPrefix(kind, "response.") && receipt.State == "succeeded" {
			var c control.Command
			if receipt.Code != "" || json.Unmarshal(command, &c) != nil || control.Validate(c) != nil || c.TenantID != id.TenantID || c.SensorID != id.SensorID || c.RegistrationID != id.RegistrationID {
				return responseapi.ErrUnknown
			}
			a, err := responseapi.ReadAction(c.Payload)
			_, resultErr := responseapi.ReadResult(receipt.Result, a, kind, receipt.FinishedAt.UTC())
			if err != nil || resultErr != nil {
				return responseapi.ErrUnknown
			}
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
