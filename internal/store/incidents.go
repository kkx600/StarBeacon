package store

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/assessment"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/incident"
	"github.com/kkx600/StarBeacon/internal/model"
)

var ErrIncidentQuota = errors.New("安全事件额度不足")
var ErrIncidentExpired = errors.New("安全事件已到保留期限")
var ErrIncidentOwner = errors.New("事件责任人已停用或不属于当前租户")

type IncidentLinked struct{ ID string }

func (e *IncidentLinked) Error() string { return "告警已关联其他安全事件" }

func incidentPrincipal(u model.Principal) bool {
	return u.Role == "admin" && contract.ValidID(u.ID) && contract.ValidID(u.TenantID)
}

// JSON 和可筛选列必须一致，不能让损坏的存储返回虚假的状态或版本。
func scanIncident(row pgx.Row) (incident.Record, error) {
	var r incident.Record
	var raw []byte
	var id, state, severity string
	var revision int64
	var created, expires time.Time
	if err := row.Scan(&raw, &id, &revision, &state, &severity, &created, &expires); err != nil {
		return r, err
	}
	if json.Unmarshal(raw, &r) != nil || r.Validate() != nil || r.ID != id || r.Revision != revision || r.Spec.Status != state || r.Spec.Severity != severity || !r.CreatedAt.Equal(created) || !r.ExpiresAt.Equal(expires) {
		return incident.Record{}, errors.New("安全事件记录与目录不一致")
	}
	return r, nil
}

const incidentColumns = `record,id,revision,state,severity,created_at,expires_at`

func (p *Postgres) Incident(ctx context.Context, u model.Principal, id string) (incident.Record, error) {
	var result incident.Record
	if !incidentPrincipal(u) || !contract.ValidID(id) {
		return result, incident.ErrInput
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		var err error
		result, err = scanIncident(tx.QueryRow(ctx, `SELECT `+incidentColumns+` FROM incidents WHERE tenant_id=$1 AND id=$2 AND (state<>'closed' OR expires_at>clock_timestamp())`, u.TenantID, id))
		return err
	})
	return result, err
}

func (p *Postgres) Incidents(ctx context.Context, u model.Principal, q incident.Query) (incident.Page, error) {
	page := incident.Page{Items: []incident.Record{}}
	if !incidentPrincipal(u) || q.Validate() != nil {
		return page, incident.ErrInput
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		var before *time.Time
		if q.Before != "" {
			var t time.Time
			if err := tx.QueryRow(ctx, `SELECT created_at FROM incidents WHERE tenant_id=$1 AND id=$2 AND (state<>'closed' OR expires_at>now())`, u.TenantID, q.Before).Scan(&t); err != nil {
				return err
			}
			before = &t
		}
		rows, err := tx.Query(ctx, `SELECT `+incidentColumns+` FROM incidents WHERE tenant_id=$1 AND ($2='' OR state=$2) AND ($3='' OR severity=$3) AND (state<>'closed' OR expires_at>now()) AND ($4::timestamptz IS NULL OR (created_at,id)<($4,$5)) ORDER BY created_at DESC,id DESC LIMIT 21`, u.TenantID, q.Status, q.Severity, before, q.Before)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			r, err := scanIncident(rows)
			if err != nil {
				return err
			}
			page.Items = append(page.Items, r)
		}
		if err = rows.Err(); err != nil {
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

func (p *Postgres) IncidentAssignees(ctx context.Context, u model.Principal) ([]incident.Assignee, error) {
	result := []incident.Assignee{}
	if !incidentPrincipal(u) {
		return result, incident.ErrInput
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT u.id,u.username FROM users u JOIN tenants t ON t.id=u.tenant_id WHERE u.tenant_id=$1 AND u.active AND u.role='admin' AND t.active ORDER BY u.username,u.id LIMIT 101`, u.TenantID)
		if err != nil {
			return err
		}
		result, err = pgx.CollectRows(rows, pgx.RowToStructByPos[incident.Assignee])
		if err != nil {
			return err
		}
		if len(result) > 100 {
			return ErrIncidentQuota
		}
		return nil
	})
	return result, err
}

func validIncidentEvidence(refs []incident.AlertRef, frozen []incident.AlertEvidence) bool {
	if len(refs) != len(frozen) {
		return false
	}
	for i, r := range refs {
		if frozen[i].AlertRef != r || !contract.ValidID(frozen[i].SensorID) || frozen[i].EventTime.IsZero() || frozen[i].ObservedAt.IsZero() {
			return false
		}
	}
	return true
}

func IncidentCreateHash(input incident.Create) string {
	raw, _ := json.Marshal(input)
	return Hash(string(raw))
}

func IncidentChangeHash(id string, input incident.Change) string {
	raw, _ := json.Marshal(struct {
		ID     string          `json:"id"`
		Change incident.Change `json:"change"`
	}{id, input})
	return Hash(string(raw))
}

// 原提交已经持久化时，确认操作只读取冻结回执，不依赖仍在线或尚未到期的 ES 原文。
// 活动管理员身份和请求摘要仍需重新核对，不能用回执绕过禁用或改变原输入。
func (p *Postgres) IncidentReceipt(ctx context.Context, u model.Principal, key, operation, inputHash string) (incident.Record, error) {
	var result incident.Record
	if !incidentPrincipal(u) || !contract.ValidID(key) || (operation != "create" && operation != "change") || !assessment.ValidDigest(inputHash) {
		return result, incident.ErrInput
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := activePlanOwner(ctx, tx, u.TenantID, u.ID); err != nil {
			return err
		}
		var previous string
		var raw []byte
		var expired bool
		if err := tx.QueryRow(ctx, `SELECT input_hash,record,expires_at<=now() FROM incident_changes WHERE tenant_id=$1 AND created_by=$2 AND operation=$3 AND idempotency_key_hash=$4`, u.TenantID, u.ID, operation, Hash(key)).Scan(&previous, &raw, &expired); err != nil {
			return err
		}
		if expired {
			return ErrIncidentExpired
		}
		if previous != inputHash {
			return ErrConflict
		}
		if json.Unmarshal(raw, &result) != nil || result.Validate() != nil || result.ActorID != u.ID {
			return errors.New("原事件操作回执无效")
		}
		return nil
	})
	return result, err
}

func (p *Postgres) CreateIncident(ctx context.Context, u model.Principal, key string, input incident.Create, frozen []incident.AlertEvidence, requestID string) (incident.Record, error) {
	if input.Validate() != nil || !validIncidentEvidence(input.Alerts, frozen) {
		return incident.Record{}, incident.ErrInput
	}
	return p.writeIncident(ctx, u, "", key, "create", IncidentCreateHash(input), 0, input.Spec, "建立事件调查", frozen, requestID)
}
func (p *Postgres) ChangeIncident(ctx context.Context, u model.Principal, id, key string, input incident.Change, frozen []incident.AlertEvidence, requestID string) (incident.Record, error) {
	if !contract.ValidID(id) || input.Validate() != nil || !validIncidentEvidence(input.AddAlerts, frozen) {
		return incident.Record{}, incident.ErrInput
	}
	return p.writeIncident(ctx, u, id, key, "change", IncidentChangeHash(id, input), input.ExpectedRevision, input.Spec, input.Note, frozen, requestID)
}

func (p *Postgres) writeIncident(ctx context.Context, u model.Principal, id, key, operation, inputHash string, expected int64, spec incident.Spec, note string, added []incident.AlertEvidence, requestID string) (incident.Record, error) {
	var result incident.Record
	if !incidentPrincipal(u) || !contract.ValidID(key) {
		return result, incident.ErrInput
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		// 同租户创建、关联和修改串行化，避免同一告警同时升级到两份案件。
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, u.TenantID+"/incidents"); err != nil {
			return err
		}
		if err := activePlanOwner(ctx, tx, u.TenantID, u.ID); err != nil {
			return err
		}
		var previous string
		var raw []byte
		var expired bool
		err := tx.QueryRow(ctx, `SELECT input_hash,record,expires_at<=now() FROM incident_changes WHERE tenant_id=$1 AND created_by=$2 AND operation=$3 AND idempotency_key_hash=$4`, u.TenantID, u.ID, operation, Hash(key)).Scan(&previous, &raw, &expired)
		if err == nil {
			if expired {
				return ErrIncidentExpired
			}
			if previous != inputHash {
				return ErrConflict
			}
			if json.Unmarshal(raw, &result) != nil || result.Validate() != nil {
				return errors.New("原事件操作回执无效")
			}
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		current := incident.Record{Alerts: []incident.AlertEvidence{}}
		if operation == "change" {
			current, err = scanIncident(tx.QueryRow(ctx, `SELECT `+incidentColumns+` FROM incidents WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, u.TenantID, id))
			if err != nil {
				return err
			}
			var now time.Time
			if err = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
				return err
			}
			if current.Spec.Status == "closed" && !current.ExpiresAt.After(now) {
				return ErrIncidentExpired
			}
			if current.Revision != expected {
				return ErrConflict
			}
			if current.Spec.Status == "closed" && spec.Status == "open" {
				return incident.ErrInput
			}
			if current.Revision >= incident.MaxRevision {
				return ErrIncidentQuota
			}
		} else {
			id = RandomID("incident_")
		}
		if spec.Status == "closed" {
			var unfinished bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM incident_tasks WHERE tenant_id=$1 AND incident_id=$2 AND state IN('open','in_progress'))`, u.TenantID, id).Scan(&unfinished); err != nil {
				return err
			}
			if unfinished {
				return ErrIncidentTasksPending
			}
		}
		if len(current.Alerts)+len(added) > incident.MaxAlerts {
			return incident.ErrInput
		}
		known := map[string]bool{}
		for _, r := range current.Alerts {
			known[r.EventID] = true
		}
		for _, r := range added {
			if known[r.EventID] {
				return incident.ErrInput
			}
			known[r.EventID] = true
			var linked string
			err = tx.QueryRow(ctx, `SELECT incident_id FROM incident_alert_links WHERE tenant_id=$1 AND event_id=$2`, u.TenantID, r.EventID).Scan(&linked)
			if err == nil {
				return &IncidentLinked{ID: linked}
			}
			if !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
		}
		var count, changes int
		if err = tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM incidents WHERE tenant_id=$1),(SELECT count(*) FROM incident_changes WHERE tenant_id=$1 AND created_at>=date_trunc('day',now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC')`, u.TenantID).Scan(&count, &changes); err != nil {
			return err
		}
		if changes >= 4096 || (operation == "create" && count >= 10000) {
			return ErrIncidentQuota
		}
		ownerName := ""
		if spec.OwnerID != "" {
			if err = activePlanOwner(ctx, tx, u.TenantID, spec.OwnerID); errors.Is(err, pgx.ErrNoRows) {
				return ErrIncidentOwner
			} else if err != nil {
				return err
			}
			if err = tx.QueryRow(ctx, `SELECT username FROM users WHERE tenant_id=$1 AND id=$2`, u.TenantID, spec.OwnerID).Scan(&ownerName); err != nil {
				return err
			}
		}
		var actorName string
		if err = tx.QueryRow(ctx, `SELECT username FROM users WHERE tenant_id=$1 AND id=$2`, u.TenantID, u.ID).Scan(&actorName); err != nil {
			return err
		}
		var now, expires time.Time
		if err = tx.QueryRow(ctx, `SELECT clock_timestamp(),clock_timestamp()+make_interval(days=>COALESCE((SELECT days FROM retention_policies WHERE tenant_id=$1 AND category='incidents'),180))`, u.TenantID).Scan(&now, &expires); err != nil {
			return err
		}
		created := current.CreatedAt
		if created.IsZero() {
			created = now
		}
		result = incident.Record{ID: id, Revision: current.Revision + 1, Spec: spec, OwnerName: ownerName, Alerts: append(current.Alerts, added...), Note: note, ActorID: u.ID, ActorName: actorName, CreatedAt: created, RecordedAt: now, ExpiresAt: expires}
		if result.Validate() != nil {
			return incident.ErrInput
		}
		raw, _ = json.Marshal(result)
		if _, err = tx.Exec(ctx, `INSERT INTO incidents(tenant_id,id,revision,state,severity,record,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(tenant_id,id) DO UPDATE SET revision=EXCLUDED.revision,state=EXCLUDED.state,severity=EXCLUDED.severity,record=EXCLUDED.record,expires_at=EXCLUDED.expires_at`, u.TenantID, id, result.Revision, spec.Status, spec.Severity, raw, created, expires); err != nil {
			return err
		}
		for _, r := range added {
			if _, err = tx.Exec(ctx, `INSERT INTO incident_alert_links(tenant_id,event_id,incident_id,raw_sha256) VALUES($1,$2,$3,$4)`, u.TenantID, r.EventID, id, r.SHA256); err != nil {
				return err
			}
		}
		if _, err = tx.Exec(ctx, `INSERT INTO incident_changes(tenant_id,incident_id,revision,created_by,operation,idempotency_key_hash,input_hash,record,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, u.TenantID, id, result.Revision, u.ID, operation, Hash(key), inputHash, raw, now, expires); err != nil {
			return err
		}
		return insertOperationAudit(ctx, tx, u, "incidents."+operation, id, requestID)
	})
	return result, err
}

func (p *Postgres) IncidentHistory(ctx context.Context, u model.Principal, id, before string) (incident.Page, error) {
	page := incident.Page{Items: []incident.Record{}}
	boundary := int64(incident.MaxRevision + 1)
	if before != "" {
		n, err := strconv.ParseInt(before, 10, 64)
		if err != nil || n < 1 || n > incident.MaxRevision || strconv.FormatInt(n, 10) != before {
			return page, incident.ErrInput
		}
		boundary = n
	}
	if !incidentPrincipal(u) || !contract.ValidID(id) {
		return page, incident.ErrInput
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		var active bool
		if err := tx.QueryRow(ctx, `SELECT state<>'closed' FROM incidents WHERE tenant_id=$1 AND id=$2 AND (state<>'closed' OR expires_at>now())`, u.TenantID, id).Scan(&active); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT record,revision FROM incident_changes WHERE tenant_id=$1 AND incident_id=$2 AND revision<$3 AND ($4 OR expires_at>now()) ORDER BY revision DESC LIMIT 21`, u.TenantID, id, boundary, active)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var raw []byte
			var revision int64
			var r incident.Record
			if err = rows.Scan(&raw, &revision); err != nil {
				return err
			}
			if json.Unmarshal(raw, &r) != nil || r.Validate() != nil || r.ID != id || r.Revision != revision {
				return errors.New("事件调查时间线记录无效")
			}
			page.Items = append(page.Items, r)
		}
		if err = rows.Err(); err != nil {
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
