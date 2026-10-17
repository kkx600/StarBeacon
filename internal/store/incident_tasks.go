package store

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/incident"
	"github.com/kkx600/StarBeacon/internal/model"
)

var ErrIncidentTasksPending = errors.New("事件仍有未完成的调查任务")
var ErrIncidentTaskClosed = errors.New("事件已结案，调查任务只读")
var ErrIncidentTaskQuota = errors.New("调查任务或变更额度不足")

const incidentTaskColumns = `record,id,incident_id,revision,state,created_at,expires_at`

func scanIncidentTask(row pgx.Row) (incident.TaskRecord, error) {
	var result incident.TaskRecord
	var raw []byte
	var id, parent, state string
	var revision int64
	var created, expires time.Time
	if err := row.Scan(&raw, &id, &parent, &revision, &state, &created, &expires); err != nil {
		return result, err
	}
	if json.Unmarshal(raw, &result) != nil || result.Validate() != nil || result.ID != id || result.IncidentID != parent || result.Revision != revision || result.Spec.Status != state || !result.CreatedAt.Equal(created) || !result.ExpiresAt.Equal(expires) {
		return incident.TaskRecord{}, errors.New("调查任务与目录不一致")
	}
	return result, nil
}

func taskParent(ctx context.Context, tx pgx.Tx, u model.Principal, id string, lock bool) (incident.Record, error) {
	if err := activePlanOwner(ctx, tx, u.TenantID, u.ID); err != nil {
		return incident.Record{}, err
	}
	query := `SELECT ` + incidentColumns + ` FROM incidents WHERE tenant_id=$1 AND id=$2 AND (state<>'closed' OR expires_at>clock_timestamp())`
	if lock {
		query += ` FOR UPDATE`
	}
	return scanIncident(tx.QueryRow(ctx, query, u.TenantID, id))
}

func (p *Postgres) IncidentTasks(ctx context.Context, u model.Principal, parent string, q incident.TaskQuery) (incident.TaskPage, error) {
	page := incident.TaskPage{Items: []incident.TaskRecord{}}
	if !incidentPrincipal(u) || !contract.ValidID(parent) || q.Validate() != nil {
		return page, incident.ErrTaskInput
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		owner, err := taskParent(ctx, tx, u, parent, false)
		if err != nil {
			return err
		}
		active := owner.Spec.Status != "closed"
		var before *time.Time
		if q.Before != "" {
			var value time.Time
			if err := tx.QueryRow(ctx, `SELECT created_at FROM incident_tasks WHERE tenant_id=$1 AND incident_id=$2 AND id=$3 AND ($4 OR expires_at>now())`, u.TenantID, parent, q.Before, active).Scan(&value); err != nil {
				return err
			}
			before = &value
		}
		rows, err := tx.Query(ctx, `SELECT `+incidentTaskColumns+` FROM incident_tasks WHERE tenant_id=$1 AND incident_id=$2 AND ($3='' OR state=$3) AND ($4 OR expires_at>now()) AND ($5::timestamptz IS NULL OR (created_at,id)<($5,$6)) ORDER BY created_at DESC,id DESC LIMIT 21`, u.TenantID, parent, q.Status, active, before, q.Before)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			record, err := scanIncidentTask(rows)
			if err != nil {
				return err
			}
			page.Items = append(page.Items, record)
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

func (p *Postgres) IncidentTask(ctx context.Context, u model.Principal, parent, id string) (incident.TaskRecord, error) {
	var result incident.TaskRecord
	if !incidentPrincipal(u) || !contract.ValidID(parent) || !contract.ValidID(id) {
		return result, incident.ErrTaskInput
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		owner, err := taskParent(ctx, tx, u, parent, false)
		if err != nil {
			return err
		}
		result, err = scanIncidentTask(tx.QueryRow(ctx, `SELECT `+incidentTaskColumns+` FROM incident_tasks WHERE tenant_id=$1 AND incident_id=$2 AND id=$3 AND ($4 OR expires_at>now())`, u.TenantID, parent, id, owner.Spec.Status != "closed"))
		return err
	})
	return result, err
}

func (p *Postgres) CreateIncidentTask(ctx context.Context, u model.Principal, parent, key string, input incident.TaskCreate, requestID string) (incident.TaskRecord, error) {
	if input.Validate() != nil {
		return incident.TaskRecord{}, incident.ErrTaskInput
	}
	return p.writeIncidentTask(ctx, u, parent, "", key, "create", input.IncidentRevision, 0, input.Spec, "建立协作任务", requestID)
}

func (p *Postgres) ChangeIncidentTask(ctx context.Context, u model.Principal, parent, id, key string, input incident.TaskChange, requestID string) (incident.TaskRecord, error) {
	if input.Validate() != nil || !contract.ValidID(id) {
		return incident.TaskRecord{}, incident.ErrTaskInput
	}
	return p.writeIncidentTask(ctx, u, parent, id, key, "change", input.IncidentRevision, input.ExpectedRevision, input.Spec, input.Note, requestID)
}

func (p *Postgres) writeIncidentTask(ctx context.Context, u model.Principal, parent, id, key, operation string, caseRevision, expected int64, spec incident.TaskSpec, note, requestID string) (incident.TaskRecord, error) {
	var result incident.TaskRecord
	if !incidentPrincipal(u) || !contract.ValidID(parent) || !contract.ValidID(key) {
		return result, incident.ErrTaskInput
	}
	if spec.DueAt != nil {
		value := spec.DueAt.UTC()
		spec.DueAt = &value
	}
	rawInput, _ := json.Marshal(struct {
		Parent, ID, Operation, Note string
		CaseRevision, Expected      int64
		Spec                        incident.TaskSpec
	}{parent, id, operation, note, caseRevision, expected, spec})
	inputHash := Hash(string(rawInput))
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		// 与事件结案共用串行边界，避免检查通过后又创建未完成任务。
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, u.TenantID+"/incidents"); err != nil {
			return err
		}
		if err := activePlanOwner(ctx, tx, u.TenantID, u.ID); err != nil {
			return err
		}
		var previous string
		var raw []byte
		var expired bool
		err := tx.QueryRow(ctx, `SELECT input_hash,record,expires_at<=now() FROM incident_task_changes WHERE tenant_id=$1 AND created_by=$2 AND operation=$3 AND idempotency_key_hash=$4`, u.TenantID, u.ID, operation, Hash(key)).Scan(&previous, &raw, &expired)
		if err == nil {
			if expired {
				return ErrIncidentExpired
			}
			if previous != inputHash {
				return ErrConflict
			}
			if json.Unmarshal(raw, &result) != nil || result.Validate() != nil || result.IncidentID != parent || id != "" && result.ID != id || result.Revision != expected+1 || result.ActorID != u.ID || result.IncidentRevision != caseRevision || result.Note != note {
				return errors.New("调查任务原回执无效")
			}
			encoded, _ := json.Marshal(result.Spec)
			wanted, _ := json.Marshal(spec)
			if string(encoded) != string(wanted) {
				return errors.New("调查任务原材料与回执不同")
			}
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		owner, err := taskParent(ctx, tx, u, parent, true)
		if err != nil {
			return err
		}
		if owner.Spec.Status == "closed" {
			return ErrIncidentTaskClosed
		}
		if owner.Revision != caseRevision {
			return ErrConflict
		}
		var current incident.TaskRecord
		if operation == "change" {
			current, err = scanIncidentTask(tx.QueryRow(ctx, `SELECT `+incidentTaskColumns+` FROM incident_tasks WHERE tenant_id=$1 AND incident_id=$2 AND id=$3 FOR UPDATE`, u.TenantID, parent, id))
			if err != nil {
				return err
			}
			if current.Revision != expected {
				return ErrConflict
			}
			if current.Revision >= incident.MaxRevision {
				return ErrIncidentTaskQuota
			}
		} else {
			id = RandomID("case_task_")
		}
		var count, total, changes int
		if err := tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM incident_tasks WHERE tenant_id=$1 AND incident_id=$2),(SELECT count(*) FROM incident_tasks WHERE tenant_id=$1),(SELECT count(*) FROM incident_task_changes WHERE tenant_id=$1 AND created_at>=date_trunc('day',now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC')`, u.TenantID, parent).Scan(&count, &total, &changes); err != nil {
			return err
		}
		if operation == "create" && (count >= incident.MaxTasks || total >= 10000) || changes >= 4096 {
			return ErrIncidentTaskQuota
		}
		assignee := ""
		if spec.AssigneeID != "" {
			if spec.Status == "cancelled" && spec.AssigneeID == current.Spec.AssigneeID {
				assignee = current.AssigneeName
			} else {
				if err := activePlanOwner(ctx, tx, u.TenantID, spec.AssigneeID); errors.Is(err, pgx.ErrNoRows) {
					return ErrIncidentOwner
				} else if err != nil {
					return err
				}
				if err := tx.QueryRow(ctx, `SELECT username FROM users WHERE tenant_id=$1 AND id=$2`, u.TenantID, spec.AssigneeID).Scan(&assignee); err != nil {
					return err
				}
			}
		}
		var actor string
		if err := tx.QueryRow(ctx, `SELECT username FROM users WHERE tenant_id=$1 AND id=$2`, u.TenantID, u.ID).Scan(&actor); err != nil {
			return err
		}
		var now, expires time.Time
		if err := tx.QueryRow(ctx, `SELECT clock_timestamp(),clock_timestamp()+make_interval(days=>COALESCE((SELECT days FROM retention_policies WHERE tenant_id=$1 AND category='incidents'),180))`, u.TenantID).Scan(&now, &expires); err != nil {
			return err
		}
		created := current.CreatedAt
		if created.IsZero() {
			created = now
		}
		result = incident.TaskRecord{ID: id, IncidentID: parent, IncidentRevision: caseRevision, Revision: expected + 1, Spec: spec, AssigneeName: assignee, Note: note, ActorID: u.ID, ActorName: actor, CreatedAt: created, RecordedAt: now, ExpiresAt: expires}
		if result.Validate() != nil {
			return incident.ErrTaskInput
		}
		raw, _ = json.Marshal(result)
		if _, err := tx.Exec(ctx, `INSERT INTO incident_tasks(tenant_id,incident_id,id,revision,state,record,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(tenant_id,id) DO UPDATE SET revision=EXCLUDED.revision,state=EXCLUDED.state,record=EXCLUDED.record,expires_at=EXCLUDED.expires_at`, u.TenantID, parent, id, result.Revision, spec.Status, raw, created, expires); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO incident_task_changes(tenant_id,incident_id,task_id,revision,created_by,operation,idempotency_key_hash,input_hash,record,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, u.TenantID, parent, id, result.Revision, u.ID, operation, Hash(key), inputHash, raw, now, expires); err != nil {
			return err
		}
		return insertOperationAudit(ctx, tx, u, "incidents.tasks."+operation, id, requestID)
	})
	return result, err
}

func (p *Postgres) IncidentTaskHistory(ctx context.Context, u model.Principal, parent, id, before string) (incident.TaskPage, error) {
	page := incident.TaskPage{Items: []incident.TaskRecord{}}
	boundary := int64(incident.MaxRevision + 1)
	if before != "" {
		value, err := strconv.ParseInt(before, 10, 64)
		if err != nil || value < 1 || value > incident.MaxRevision || strconv.FormatInt(value, 10) != before {
			return page, incident.ErrTaskInput
		}
		boundary = value
	}
	if !incidentPrincipal(u) || !contract.ValidID(parent) || !contract.ValidID(id) {
		return page, incident.ErrTaskInput
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		owner, err := taskParent(ctx, tx, u, parent, false)
		if err != nil {
			return err
		}
		if _, err := scanIncidentTask(tx.QueryRow(ctx, `SELECT `+incidentTaskColumns+` FROM incident_tasks WHERE tenant_id=$1 AND incident_id=$2 AND id=$3 AND ($4 OR expires_at>now())`, u.TenantID, parent, id, owner.Spec.Status != "closed")); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT record,revision FROM incident_task_changes WHERE tenant_id=$1 AND incident_id=$2 AND task_id=$3 AND revision<$4 AND ($5 OR expires_at>now()) ORDER BY revision DESC LIMIT 21`, u.TenantID, parent, id, boundary, owner.Spec.Status != "closed")
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var raw []byte
			var revision int64
			var record incident.TaskRecord
			if err := rows.Scan(&raw, &revision); err != nil {
				return err
			}
			if json.Unmarshal(raw, &record) != nil || record.Validate() != nil || record.ID != id || record.IncidentID != parent || record.Revision != revision {
				return errors.New("调查任务历史记录无效")
			}
			page.Items = append(page.Items, record)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if len(page.Items) > 20 {
			page.Items = page.Items[:20]
			page.Next = strconv.FormatInt(page.Items[19].Revision, 10)
		}
		return nil
	})
	return page, err
}
