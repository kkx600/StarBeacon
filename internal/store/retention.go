package store

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/retention"
)

func (p *Postgres) RetentionPolicies(ctx context.Context, tenant string) ([]retention.Policy, error) {
	result := []retention.Policy{}
	err := p.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, "SELECT category,days,revision,updated_at FROM retention_policies WHERE tenant_id=$1 ORDER BY category", tenant)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var item retention.Policy
			if err := rows.Scan(&item.Category, &item.Days, &item.Revision, &item.UpdatedAt); err != nil {
				return err
			}
			result = append(result, item)
		}
		return rows.Err()
	})
	return result, err
}
func (p *Postgres) PreviewRetention(ctx context.Context, user model.Principal, candidate retention.Candidate) (retention.Preview, error) {
	if err := candidate.Validate(); err != nil {
		return retention.Preview{}, err
	}
	category, _ := retention.Lookup(candidate.Category)
	result := retention.Preview{ID: RandomID("retprev_"), Candidate: candidate, Scope: category.Scope, Boundary: category.Boundary, ExistingUnmodified: true}
	err := p.TenantTx(ctx, user.TenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", user.TenantID+"/retention"); err != nil {
			return err
		}
		var revision int64
		if err := tx.QueryRow(ctx, "SELECT days,revision FROM retention_policies WHERE tenant_id=$1 AND category=$2", user.TenantID, candidate.Category).Scan(&result.CurrentDays, &revision); err != nil {
			return err
		}
		if revision != candidate.ExpectedRevision {
			return ErrConflict
		}
		// 预览是短期确认凭据，不承载业务历史；每名管理员最多保留十份有效预览。
		if _, err := tx.Exec(ctx, "DELETE FROM retention_previews WHERE tenant_id=$1 AND (expires_at<=now() OR (created_by=$2 AND id IN(SELECT id FROM retention_previews WHERE tenant_id=$1 AND created_by=$2 ORDER BY created_at DESC,id DESC OFFSET 9)))", user.TenantID, user.ID); err != nil {
			return err
		}
		raw, err := json.Marshal(candidate)
		if err != nil {
			return err
		}
		return tx.QueryRow(ctx, "INSERT INTO retention_previews(tenant_id,id,created_by,candidate,current_days) VALUES($1,$2,$3,$4,$5) RETURNING expires_at", user.TenantID, result.ID, user.ID, raw, result.CurrentDays).Scan(&result.ExpiresAt)
	})
	return result, err
}
func (p *Postgres) SaveRetention(ctx context.Context, user model.Principal, input retention.Change, key string) (retention.Policy, bool, error) {
	var result retention.Policy
	duplicate := false
	if !contract.ValidID(input.PreviewID) || input.Candidate.Validate() != nil || !contract.ValidID(key) {
		return result, false, ErrConflict
	}
	raw, err := json.Marshal(input)
	if err != nil {
		return result, false, err
	}
	fingerprint := Hash(string(raw))
	err = p.TenantTx(ctx, user.TenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", user.TenantID+"/retention"); err != nil {
			return err
		}
		var previous string
		err := tx.QueryRow(ctx, "SELECT category,days,revision,created_at,request_hash FROM retention_changes WHERE tenant_id=$1 AND created_by=$2 AND idempotency_key_hash=$3", user.TenantID, user.ID, Hash(key)).Scan(&result.Category, &result.Days, &result.Revision, &result.UpdatedAt, &previous)
		if err == nil {
			if previous != fingerprint {
				return ErrConflict
			}
			duplicate = true
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		var previewRaw []byte
		// 类别发布与预览消费共享租户事务锁，不额外授予短期预览 UPDATE 权限。
		if err := tx.QueryRow(ctx, "SELECT candidate FROM retention_previews WHERE tenant_id=$1 AND id=$2 AND created_by=$3 AND expires_at>clock_timestamp()", user.TenantID, input.PreviewID, user.ID).Scan(&previewRaw); err != nil {
			return err
		}
		var frozen retention.Candidate
		if json.Unmarshal(previewRaw, &frozen) != nil || frozen != input.Candidate {
			return ErrConflict
		}
		result.Category, result.Days = input.Candidate.Category, input.Candidate.Days
		if err := tx.QueryRow(ctx, "UPDATE retention_policies SET days=$3,revision=revision+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND category=$2 AND revision=$4 RETURNING revision,updated_at", user.TenantID, result.Category, result.Days, input.Candidate.ExpectedRevision).Scan(&result.Revision, &result.UpdatedAt); errors.Is(err, pgx.ErrNoRows) {
			return ErrConflict
		} else if err != nil {
			return err
		}
		changeID := RandomID("retchange_")
		if _, err := tx.Exec(ctx, "INSERT INTO retention_changes(tenant_id,id,created_by,category,days,revision,request_hash,idempotency_key_hash,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$9::timestamptz+make_interval(days=>COALESCE((SELECT days FROM retention_policies WHERE tenant_id=$1 AND category='operations'),180)))", user.TenantID, changeID, user.ID, result.Category, result.Days, result.Revision, fingerprint, Hash(key), result.UpdatedAt); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "DELETE FROM retention_previews WHERE tenant_id=$1 AND id=$2", user.TenantID, input.PreviewID); err != nil {
			return err
		}
		return insertOperationAudit(ctx, tx, user, "retention.change", input.Candidate.Category, key)
	})
	return result, duplicate, err
}

// 新索引固化策略后不随配置变更漂移；既有对象的期限由首次创建时的事实决定。
func (p *Postgres) EventRetention(ctx context.Context, tenant, stream string) (int, error) {
	category := "network"
	if stream == "alerts" {
		category = "alerts"
	} else if stream == "logs" {
		category = "security_logs"
	} else if stream != "context" {
		return 0, errors.New("事件流无效")
	}
	days := retention.DefaultDays
	err := p.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT days FROM retention_policies WHERE tenant_id=$1 AND category=$2", tenant, category).Scan(&days)
	})
	return days, err
}
