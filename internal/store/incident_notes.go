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

var ErrIncidentNoteClosed = errors.New("事件已结案，调查笔记只读")
var ErrIncidentNoteQuota = errors.New("调查笔记或变更额度不足")

var ErrIncidentNoteAuthor = errors.New("只有笔记作者可以修改或撤回记录")

const incidentNoteColumns = `record,id,incident_id,revision,state,created_at,expires_at,author_id`

func scanIncidentNote(row pgx.Row) (incident.NoteRecord, error) {
	var result incident.NoteRecord
	var raw []byte
	var id, parent, state, author string
	var revision int64
	var created, expires time.Time
	if err := row.Scan(&raw, &id, &parent, &revision, &state, &created, &expires, &author); err != nil {
		return result, err
	}
	if json.Unmarshal(raw, &result) != nil || result.Validate() != nil || result.ID != id || result.IncidentID != parent || result.Revision != revision || result.Spec.Status != state || result.AuthorID != author || !result.CreatedAt.Equal(created) || !result.ExpiresAt.Equal(expires) {
		return incident.NoteRecord{}, errors.New("调查笔记与目录不一致")
	}
	return result, nil
}

func noteParent(ctx context.Context, tx pgx.Tx, u model.Principal, id string, lock bool) (incident.Record, error) {
	if err := activePlanOwner(ctx, tx, u.TenantID, u.ID); err != nil {
		return incident.Record{}, err
	}
	query := `SELECT ` + incidentColumns + ` FROM incidents WHERE tenant_id=$1 AND id=$2 AND (state<>'closed' OR expires_at>clock_timestamp())`
	if lock {
		query += ` FOR UPDATE`
	}
	return scanIncident(tx.QueryRow(ctx, query, u.TenantID, id))
}

func (p *Postgres) IncidentNotes(ctx context.Context, u model.Principal, parent string, q incident.NoteQuery) (incident.NotePage, error) {
	page := incident.NotePage{Items: []incident.NoteRecord{}}
	if !incidentPrincipal(u) || !contract.ValidID(parent) || q.Validate() != nil {
		return page, incident.ErrNoteInput
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		owner, err := noteParent(ctx, tx, u, parent, false)
		if err != nil {
			return err
		}
		active := owner.Spec.Status != "closed"
		var before *time.Time
		if q.Before != "" {
			var value time.Time
			if err := tx.QueryRow(ctx, `SELECT created_at FROM incident_notes WHERE tenant_id=$1 AND incident_id=$2 AND id=$3 AND ($4 OR expires_at>now())`, u.TenantID, parent, q.Before, active).Scan(&value); err != nil {
				return err
			}
			before = &value
		}
		rows, err := tx.Query(ctx, `SELECT `+incidentNoteColumns+` FROM incident_notes WHERE tenant_id=$1 AND incident_id=$2 AND ($3='' OR state=$3) AND ($4 OR expires_at>now()) AND ($5::timestamptz IS NULL OR (created_at,id)<($5,$6)) ORDER BY created_at DESC,id DESC LIMIT 21`, u.TenantID, parent, q.Status, active, before, q.Before)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			record, err := scanIncidentNote(rows)
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

func (p *Postgres) IncidentNote(ctx context.Context, u model.Principal, parent, id string) (incident.NoteRecord, error) {
	var result incident.NoteRecord
	if !incidentPrincipal(u) || !contract.ValidID(parent) || !contract.ValidID(id) {
		return result, incident.ErrNoteInput
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		owner, err := noteParent(ctx, tx, u, parent, false)
		if err != nil {
			return err
		}
		result, err = scanIncidentNote(tx.QueryRow(ctx, `SELECT `+incidentNoteColumns+` FROM incident_notes WHERE tenant_id=$1 AND incident_id=$2 AND id=$3 AND ($4 OR expires_at>now())`, u.TenantID, parent, id, owner.Spec.Status != "closed"))
		return err
	})
	return result, err
}

func (p *Postgres) CreateIncidentNote(ctx context.Context, u model.Principal, parent, key string, input incident.NoteCreate, requestID string) (incident.NoteRecord, error) {
	if input.Validate() != nil {
		return incident.NoteRecord{}, incident.ErrNoteInput
	}
	return p.writeIncidentNote(ctx, u, parent, "", key, "create", input.IncidentRevision, 0, input.Spec, "建立调查笔记", requestID)
}

func (p *Postgres) ChangeIncidentNote(ctx context.Context, u model.Principal, parent, id, key string, input incident.NoteChange, requestID string) (incident.NoteRecord, error) {
	if input.Validate() != nil || !contract.ValidID(id) {
		return incident.NoteRecord{}, incident.ErrNoteInput
	}
	return p.writeIncidentNote(ctx, u, parent, id, key, "change", input.IncidentRevision, input.ExpectedRevision, input.Spec, input.Reason, requestID)
}

func (p *Postgres) writeIncidentNote(ctx context.Context, u model.Principal, parent, id, key, operation string, caseRevision, expected int64, spec incident.NoteSpec, reason, requestID string) (incident.NoteRecord, error) {
	var result incident.NoteRecord
	if !incidentPrincipal(u) || !contract.ValidID(parent) || !contract.ValidID(key) {
		return result, incident.ErrNoteInput
	}

	rawInput, _ := json.Marshal(struct {
		Parent, ID, Operation, Reason string
		CaseRevision, Expected        int64
		Spec                          incident.NoteSpec
	}{parent, id, operation, reason, caseRevision, expected, spec})
	inputHash := Hash(string(rawInput))
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		// 与事件结案共用串行边界，确保结案后不会接受新的调查材料。
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, u.TenantID+"/incidents"); err != nil {
			return err
		}
		if err := activePlanOwner(ctx, tx, u.TenantID, u.ID); err != nil {
			return err
		}
		var previous string
		var raw []byte
		var expired bool
		err := tx.QueryRow(ctx, `SELECT input_hash,record,expires_at<=now() FROM incident_note_changes WHERE tenant_id=$1 AND created_by=$2 AND operation=$3 AND idempotency_key_hash=$4`, u.TenantID, u.ID, operation, Hash(key)).Scan(&previous, &raw, &expired)
		if err == nil {
			if expired {
				return ErrIncidentExpired
			}
			if previous != inputHash {
				return ErrConflict
			}
			if json.Unmarshal(raw, &result) != nil || result.Validate() != nil || result.IncidentID != parent || id != "" && result.ID != id || result.Revision != expected+1 || result.ActorID != u.ID || result.IncidentRevision != caseRevision || result.Reason != reason {
				return errors.New("调查笔记原回执无效")
			}
			encoded, _ := json.Marshal(result.Spec)
			wanted, _ := json.Marshal(spec)
			if string(encoded) != string(wanted) {
				return errors.New("调查笔记原材料与回执不同")
			}
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		owner, err := noteParent(ctx, tx, u, parent, true)
		if err != nil {
			return err
		}
		if owner.Spec.Status == "closed" {
			return ErrIncidentNoteClosed
		}
		if owner.Revision != caseRevision {
			return ErrConflict
		}
		var current incident.NoteRecord
		if operation == "change" {
			current, err = scanIncidentNote(tx.QueryRow(ctx, `SELECT `+incidentNoteColumns+` FROM incident_notes WHERE tenant_id=$1 AND incident_id=$2 AND id=$3 FOR UPDATE`, u.TenantID, parent, id))
			if err != nil {
				return err
			}
			if current.AuthorID != u.ID {
				return ErrIncidentNoteAuthor
			}
			if current.Revision != expected {
				return ErrConflict
			}
			if current.Revision >= incident.MaxRevision {
				return ErrIncidentNoteQuota
			}
		} else {
			id = RandomID("case_note_")
		}
		var count, total, changes int
		if err := tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM incident_notes WHERE tenant_id=$1 AND incident_id=$2),(SELECT count(*) FROM incident_notes WHERE tenant_id=$1),(SELECT count(*) FROM incident_note_changes WHERE tenant_id=$1 AND created_at>=date_trunc('day',now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC')`, u.TenantID, parent).Scan(&count, &total, &changes); err != nil {
			return err
		}
		if operation == "create" && (count >= incident.MaxNotes || total >= 10000) || changes >= 4096 {
			return ErrIncidentNoteQuota
		}

		var actor string
		if err := tx.QueryRow(ctx, `SELECT username FROM users WHERE tenant_id=$1 AND id=$2`, u.TenantID, u.ID).Scan(&actor); err != nil {
			return err
		}
		var now, expires time.Time
		if err := tx.QueryRow(ctx, `SELECT clock_timestamp(),clock_timestamp()+make_interval(days=>COALESCE((SELECT days FROM retention_policies WHERE tenant_id=$1 AND category='incidents'),180))`, u.TenantID).Scan(&now, &expires); err != nil {
			return err
		}
		if current.AuthorID == "" {
			current.AuthorID, current.AuthorName = u.ID, actor
		}
		created := current.CreatedAt
		if created.IsZero() {
			created = now
		}
		result = incident.NoteRecord{ID: id, IncidentID: parent, IncidentRevision: caseRevision, Revision: expected + 1, Spec: spec, AuthorID: current.AuthorID, AuthorName: current.AuthorName, Reason: reason, ActorID: u.ID, ActorName: actor, CreatedAt: created, RecordedAt: now, ExpiresAt: expires}
		if result.Validate() != nil {
			return incident.ErrNoteInput
		}
		raw, _ = json.Marshal(result)
		if _, err := tx.Exec(ctx, `INSERT INTO incident_notes(tenant_id,incident_id,id,revision,state,record,created_at,expires_at,author_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(tenant_id,id) DO UPDATE SET revision=EXCLUDED.revision,state=EXCLUDED.state,record=EXCLUDED.record,expires_at=EXCLUDED.expires_at`, u.TenantID, parent, id, result.Revision, spec.Status, raw, created, expires, result.AuthorID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO incident_note_changes(tenant_id,incident_id,note_id,revision,created_by,operation,idempotency_key_hash,input_hash,record,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, u.TenantID, parent, id, result.Revision, u.ID, operation, Hash(key), inputHash, raw, now, expires); err != nil {
			return err
		}
		return insertOperationAudit(ctx, tx, u, "incidents.notes."+operation, id, requestID)
	})
	return result, err
}

func (p *Postgres) IncidentNoteHistory(ctx context.Context, u model.Principal, parent, id, before string) (incident.NotePage, error) {
	page := incident.NotePage{Items: []incident.NoteRecord{}}
	boundary := int64(incident.MaxRevision + 1)
	if before != "" {
		value, err := strconv.ParseInt(before, 10, 64)
		if err != nil || value < 1 || value > incident.MaxRevision || strconv.FormatInt(value, 10) != before {
			return page, incident.ErrNoteInput
		}
		boundary = value
	}
	if !incidentPrincipal(u) || !contract.ValidID(parent) || !contract.ValidID(id) {
		return page, incident.ErrNoteInput
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		owner, err := noteParent(ctx, tx, u, parent, false)
		if err != nil {
			return err
		}
		current, err := scanIncidentNote(tx.QueryRow(ctx, `SELECT `+incidentNoteColumns+` FROM incident_notes WHERE tenant_id=$1 AND incident_id=$2 AND id=$3 AND ($4 OR expires_at>now())`, u.TenantID, parent, id, owner.Spec.Status != "closed"))
		if err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT record,revision FROM incident_note_changes WHERE tenant_id=$1 AND incident_id=$2 AND note_id=$3 AND revision<$4 AND ($5 OR expires_at>now()) ORDER BY revision DESC LIMIT 21`, u.TenantID, parent, id, boundary, owner.Spec.Status != "closed")
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var raw []byte
			var revision int64
			var record incident.NoteRecord
			if err := rows.Scan(&raw, &revision); err != nil {
				return err
			}
			if json.Unmarshal(raw, &record) != nil || record.Validate() != nil || record.ID != id || record.IncidentID != parent || record.Revision != revision || record.AuthorID != current.AuthorID || record.AuthorName != current.AuthorName || !record.CreatedAt.Equal(current.CreatedAt) {
				return errors.New("调查笔记历史记录无效")
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
