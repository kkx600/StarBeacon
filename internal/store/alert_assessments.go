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
	"github.com/kkx600/StarBeacon/internal/model"
)

func validAssessmentIdentity(user model.Principal, id, digest string) bool {
	return user.Role == "admin" && contract.ValidID(user.TenantID) && contract.ValidID(user.ID) && contract.ValidID(id) && assessment.ValidDigest(digest)
}

func (p *Postgres) AlertAssessment(ctx context.Context, user model.Principal, id, digest string) (assessment.Record, error) {
	result := assessment.Record{EventID: id, SHA256: digest, Spec: assessment.Default(), Basis: "unreviewed"}
	if !validAssessmentIdentity(user, id, digest) {
		return result, assessment.ErrInput
	}
	err := p.TenantTx(ctx, user.TenantID, func(tx pgx.Tx) error {
		var raw []byte
		var expired bool
		err := tx.QueryRow(ctx, `SELECT record,expires_at<=now() FROM alert_assessments WHERE tenant_id=$1 AND event_id=$2`, user.TenantID, id).Scan(&raw, &expired)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if expired {
			return ErrAssessmentExpired
		}
		if err := json.Unmarshal(raw, &result); err != nil {
			return err
		}
		if result.SHA256 != digest || result.EventID != id {
			return ErrConflict
		}
		return nil
	})
	return result, err
}

// 原始告警由 ES 校验。PG 只保存研判操作，不保存载荷，也不参与检索结果的二次筛选。
func (p *Postgres) SaveAlertAssessment(ctx context.Context, user model.Principal, id, digest, key string, change assessment.Change, requestID string) (assessment.Record, error) {
	var result assessment.Record
	if !validAssessmentIdentity(user, id, digest) || !contract.ValidID(key) || change.Validate() != nil {
		return result, assessment.ErrInput
	}
	input, _ := json.Marshal(struct {
		Digest string            `json:"raw_sha256"`
		Change assessment.Change `json:"change"`
	}{digest, change})
	inputHash := Hash(string(input))
	err := p.TenantTx(ctx, user.TenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, user.TenantID+"/assessments"); err != nil {
			return err
		}
		if err := activePlanOwner(ctx, tx, user.TenantID, user.ID); err != nil {
			return err
		}
		var priorHash string
		var raw []byte
		var expired bool
		err := tx.QueryRow(ctx, `SELECT input_hash,record,expires_at<=now() FROM alert_assessment_changes WHERE tenant_id=$1 AND event_id=$2 AND created_by=$3 AND idempotency_key_hash=$4`, user.TenantID, id, user.ID, Hash(key)).Scan(&priorHash, &raw, &expired)
		if err == nil {
			if expired {
				return ErrAssessmentExpired
			}
			if priorHash != inputHash {
				return ErrConflict
			}
			return json.Unmarshal(raw, &result)
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		current := assessment.Record{}
		err = tx.QueryRow(ctx, `SELECT record,expires_at<=now() FROM alert_assessments WHERE tenant_id=$1 AND event_id=$2 FOR UPDATE`, user.TenantID, id).Scan(&raw, &expired)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if err == nil {
			if expired {
				return ErrAssessmentExpired
			}
			if err := json.Unmarshal(raw, &current); err != nil {
				return err
			}
			if current.EventID != id || current.SHA256 != digest {
				return ErrConflict
			}
		}
		if current.Revision != change.ExpectedRevision {
			return ErrConflict
		}
		var changes int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM alert_assessment_changes WHERE tenant_id=$1 AND created_at>=date_trunc('day',now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'`, user.TenantID).Scan(&changes); err != nil {
			return err
		}
		if changes >= 10000 || current.Revision >= 1000 {
			return ErrAssessmentQuota
		}
		var now, expires time.Time
		if err := tx.QueryRow(ctx, `SELECT clock_timestamp(),now()+make_interval(days=>COALESCE((SELECT days FROM retention_policies WHERE tenant_id=$1 AND category='alerts'),180))`, user.TenantID).Scan(&now, &expires); err != nil {
			return err
		}
		result = assessment.Record{EventID: id, SHA256: digest, Revision: current.Revision + 1, Spec: change.Spec, OwnerID: current.OwnerID, OwnerName: current.OwnerName, AnalystID: user.ID, Analyst: user.Username, Basis: "human", UpdatedAt: &now, ExpiresAt: &expires}
		if change.Claim {
			result.OwnerID, result.OwnerName = user.ID, user.Username
		}
		raw, _ = json.Marshal(result)
		if _, err := tx.Exec(ctx, `INSERT INTO alert_assessments(tenant_id,event_id,raw_sha256,revision,record,expires_at) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(tenant_id,event_id) DO UPDATE SET revision=EXCLUDED.revision,record=EXCLUDED.record,expires_at=EXCLUDED.expires_at`, user.TenantID, id, digest, result.Revision, raw, expires); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO alert_assessment_changes(tenant_id,event_id,revision,created_by,idempotency_key_hash,input_hash,record,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, user.TenantID, id, result.Revision, user.ID, Hash(key), inputHash, raw, expires); err != nil {
			return err
		}
		return insertOperationAudit(ctx, tx, user, "alerts.assessment.save", id, requestID)
	})
	return result, err
}

var ErrAssessmentQuota = errors.New("告警研判变更额度不足")
var ErrAssessmentExpired = errors.New("研判记录已到保留期限")

func (p *Postgres) AlertAssessmentHistory(ctx context.Context, user model.Principal, id, digest, before string) (assessment.HistoryPage, error) {
	page := assessment.HistoryPage{Items: []assessment.Record{}}
	boundary := int64(1 << 53)
	if before != "" {
		value, err := strconv.ParseInt(before, 10, 64)
		if err != nil || value < 1 || value >= 1<<53 || strconv.FormatInt(value, 10) != before {
			return page, assessment.ErrInput
		}
		boundary = value
	}
	if !validAssessmentIdentity(user, id, digest) {
		return page, assessment.ErrInput
	}
	err := p.TenantTx(ctx, user.TenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT record FROM alert_assessment_changes WHERE tenant_id=$1 AND event_id=$2 AND record->>'raw_sha256'=$3 AND revision<$4 AND expires_at>now() ORDER BY revision DESC LIMIT 21`, user.TenantID, id, digest, boundary)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var raw []byte
			var record assessment.Record
			if err := rows.Scan(&raw); err != nil {
				return err
			}
			if err := json.Unmarshal(raw, &record); err != nil {
				return err
			}
			page.Items = append(page.Items, record)
		}
		if len(page.Items) > 20 {
			page.Items = page.Items[:20]
			page.Next = strconv.FormatInt(page.Items[19].Revision, 10)
		}
		return rows.Err()
	})
	return page, err
}
