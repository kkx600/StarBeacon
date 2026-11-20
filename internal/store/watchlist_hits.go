package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/watchlist"
)

const watchlistHitColumns = `id,list_id,list_revision,definition_sha256,event_id,raw_sha256,sensor_id,registration_id,matches,severity,rule_id,rule_name,observed_at,received_at,created_at,expires_at`

func readWatchlistHit(row interface{ Scan(...any) error }, tenant string) (watchlist.Hit, error) {
	out := watchlist.Hit{SchemaVersion: watchlist.HitSchema}
	var matches []byte
	if e := row.Scan(&out.ID, &out.ListID, &out.ListRevision, &out.DefinitionSHA256, &out.EventID, &out.RawSHA256, &out.SensorID, &out.RegistrationID, &matches, &out.Severity, &out.RuleID, &out.RuleName, &out.ObservedAt, &out.ReceivedAt, &out.CreatedAt, &out.ExpiresAt); e != nil {
		return out, e
	}
	if json.Unmarshal(matches, &out.Matches) != nil || out.Validate(tenant) != nil {
		return out, watchlist.ErrSource
	}
	out.ObservedAt, out.ReceivedAt, out.CreatedAt, out.ExpiresAt = out.ObservedAt.UTC(), out.ReceivedAt.UTC(), out.CreatedAt.UTC(), out.ExpiresAt.UTC()
	return out, nil
}

// RecordWatchlistHits 在告警成功入索引后登记观察名单命中，与名单保存共享事务锁。
// 同一告警重投按稳定标识去重；每份名单每个 UTC 处理日和每个批次都有登记上限，超过时只记录截断时刻。
func (p *Postgres) RecordWatchlistHits(ctx context.Context, tenant string, alerts []model.Alert) error {
	if !contract.ValidID(tenant) || len(alerts) > contract.MaxBatchRecords {
		return watchlist.ErrInput
	}
	if len(alerts) == 0 {
		return nil
	}
	return p.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, `SET LOCAL lock_timeout='2s'; SET LOCAL statement_timeout='5s'`); e != nil {
			return e
		}
		if _, e := tx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared(hashtextextended($1,0))`, tenant+"/watchlists"); e != nil {
			return e
		}
		rows, e := tx.Query(ctx, `SELECT `+watchlistColumns+`,h.name,h.kind,h.active FROM watchlists h JOIN watchlist_revisions v ON v.tenant_id=h.tenant_id AND v.list_id=h.id AND v.revision=h.revision WHERE h.tenant_id=$1 AND h.kind='observe' AND h.active ORDER BY h.id LIMIT $2`, tenant, watchlist.MaxLists+1)
		if e != nil {
			return e
		}
		lists := []watchlist.Record{}
		for rows.Next() {
			record, e := readWatchlist(rows, true)
			// 校验失败时 readWatchlist 已返回 ErrSource；扫描阶段的连接类错误必须原样返回，
			// 否则会被索引器当作确定性错误吞掉，丢失本批命中。
			if e == nil && record.TenantID != tenant {
				e = watchlist.ErrSource
			}
			if e != nil {
				rows.Close()
				return e
			}
			lists = append(lists, record)
		}
		rows.Close()
		if e := rows.Err(); e != nil {
			return e
		}
		if len(lists) > watchlist.MaxLists {
			return watchlist.ErrLimit
		}
		if len(lists) == 0 {
			return nil
		}
		domains := slices.ContainsFunc(lists, func(r watchlist.Record) bool { return r.Definition.MatchType == "domain" })
		targets := make([][]watchlist.Observed, len(alerts))
		for i, a := range alerts {
			if a.TenantID != tenant || !contract.ValidID(a.EventID) || !watchlist.ValidDigest(a.RawSHA256) || a.Event.Kind != "alert" {
				return watchlist.ErrSource
			}
			targets[i] = watchlist.AlertTargets(a, domains)
		}
		var day string
		if e := tx.QueryRow(ctx, `SELECT (clock_timestamp() AT TIME ZONE 'UTC')::date::text`).Scan(&day); e != nil {
			return e
		}
		budget := watchlist.MaxBatchHits
		for _, list := range lists {
			candidates := []watchlist.Hit{}
			for i, a := range alerts {
				if matches := list.AlertMatches(a, targets[i]); len(matches) > 0 {
					hit := watchlist.NewHit(tenant, list, a, matches)
					if !slices.ContainsFunc(candidates, func(h watchlist.Hit) bool { return h.ID == hit.ID }) {
						candidates = append(candidates, hit)
					}
				}
			}
			if len(candidates) == 0 {
				continue
			}
			if e := recordListHits(ctx, tx, tenant, list.ID, day, candidates, &budget); e != nil {
				return e
			}
		}
		return nil
	})
}

func recordListHits(ctx context.Context, tx pgx.Tx, tenant, list, day string, candidates []watchlist.Hit, budget *int) error {
	// 先锁定处理日计数，再判断已登记记录，保证并发批次和重投都不会越过上限或误标截断。
	if _, e := tx.Exec(ctx, `INSERT INTO watchlist_hit_days(tenant_id,list_id,day,expires_at) VALUES($1,$2,$3::date,(($3::date+1)::timestamp AT TIME ZONE 'UTC')+make_interval(days=>COALESCE((SELECT days FROM retention_policies WHERE tenant_id=$1 AND category='alerts'),180))) ON CONFLICT DO NOTHING`, tenant, list, day); e != nil {
		return e
	}
	var recorded int
	if e := tx.QueryRow(ctx, `SELECT recorded FROM watchlist_hit_days WHERE tenant_id=$1 AND list_id=$2 AND day=$3::date FOR UPDATE`, tenant, list, day).Scan(&recorded); e != nil {
		return e
	}
	ids := make([]string, 0, len(candidates))
	for _, h := range candidates {
		ids = append(ids, h.ID)
	}
	rows, e := tx.Query(ctx, `SELECT id FROM watchlist_hits WHERE tenant_id=$1 AND id=ANY($2)`, tenant, ids)
	if e != nil {
		return e
	}
	existing := map[string]bool{}
	for rows.Next() {
		var id string
		if e := rows.Scan(&id); e != nil {
			rows.Close()
			return e
		}
		existing[id] = true
	}
	rows.Close()
	if e := rows.Err(); e != nil {
		return e
	}
	fresh := []watchlist.Hit{}
	for _, h := range candidates {
		if !existing[h.ID] {
			fresh = append(fresh, h)
		}
	}
	if len(fresh) == 0 {
		return nil
	}
	allowed := max(0, min(len(fresh), watchlist.MaxDailyHits-recorded, *budget))
	inserted := 0
	if allowed > 0 {
		batch := &pgx.Batch{}
		for _, h := range fresh[:allowed] {
			matches, e := json.Marshal(h.Matches)
			if e != nil || h.Validate(tenant) != nil {
				return watchlist.ErrSource
			}
			batch.Queue(`INSERT INTO watchlist_hits(tenant_id,id,list_id,list_revision,definition_sha256,event_id,raw_sha256,sensor_id,registration_id,matches,severity,rule_id,rule_name,observed_at,received_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,now()+make_interval(days=>COALESCE((SELECT days FROM retention_policies WHERE tenant_id=$1 AND category='alerts'),180))) ON CONFLICT DO NOTHING`, tenant, h.ID, h.ListID, h.ListRevision, h.DefinitionSHA256, h.EventID, h.RawSHA256, h.SensorID, h.RegistrationID, matches, h.Severity, h.RuleID, h.RuleName, h.ObservedAt, h.ReceivedAt)
		}
		results := tx.SendBatch(ctx, batch)
		for range allowed {
			tag, e := results.Exec()
			if e != nil {
				results.Close()
				return e
			}
			inserted += int(tag.RowsAffected())
		}
		if e := results.Close(); e != nil {
			return e
		}
	}
	*budget -= inserted
	_, e = tx.Exec(ctx, `UPDATE watchlist_hit_days SET recorded=recorded+$4,capped_at=CASE WHEN $5 THEN COALESCE(capped_at,clock_timestamp()) ELSE capped_at END WHERE tenant_id=$1 AND list_id=$2 AND day=$3::date`, tenant, list, day, inserted, allowed < len(fresh))
	return e
}

// WatchlistHits 读取单份名单在观测时间窗内仍在留存期的命中；名单停用或修订变化不删除既有命中。
func (p *Postgres) WatchlistHits(ctx context.Context, u model.Principal, q watchlist.HitQuery) (watchlist.HitPage, error) {
	out := watchlist.HitPage{Items: []watchlist.Hit{}, CappedDays: []watchlist.HitDay{}}
	if q.Validate(time.Now()) != nil {
		return out, watchlist.ErrInput
	}
	before, after, e := q.Position(u.TenantID)
	if e != nil {
		return out, e
	}
	e = p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, `SET LOCAL statement_timeout='5s'`); e != nil {
			return e
		}
		if e := watchlistActor(ctx, tx, u, false); e != nil {
			return e
		}
		var exists bool
		if e := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM watchlists WHERE tenant_id=$1 AND id=$2),clock_timestamp()`, u.TenantID, q.ListID).Scan(&exists, &out.ObservedAt); e != nil {
			return e
		}
		if !exists {
			return pgx.ErrNoRows
		}
		out.ObservedAt = out.ObservedAt.UTC()
		rows, e := tx.Query(ctx, `SELECT `+watchlistHitColumns+` FROM watchlist_hits WHERE tenant_id=$1 AND list_id=$2 AND observed_at>=$3 AND (observed_at,id)<($4::timestamptz,$5::text) AND expires_at>now() ORDER BY observed_at DESC,id DESC LIMIT $6`, u.TenantID, q.ListID, q.Start, before, after, q.Limit+1)
		if e != nil {
			return e
		}
		for rows.Next() {
			hit, e := readWatchlistHit(rows, u.TenantID)
			if e != nil || hit.ListID != q.ListID || hit.ObservedAt.Before(q.Start) || !hit.ObservedAt.Before(q.End) {
				rows.Close()
				return errors.Join(watchlist.ErrSource, e)
			}
			out.Items = append(out.Items, hit)
		}
		rows.Close()
		if e := rows.Err(); e != nil {
			return e
		}
		days, e := tx.Query(ctx, `SELECT day::text,recorded,capped_at FROM watchlist_hit_days WHERE tenant_id=$1 AND list_id=$2 AND capped_at IS NOT NULL AND day>=($3::timestamptz AT TIME ZONE 'UTC')::date AND day<=($4::timestamptz AT TIME ZONE 'UTC')::date AND expires_at>now() ORDER BY day DESC LIMIT 32`, u.TenantID, q.ListID, q.Start, q.End)
		if e != nil {
			return e
		}
		defer days.Close()
		for days.Next() {
			var d watchlist.HitDay
			if e := days.Scan(&d.Day, &d.Recorded, &d.CappedAt); e != nil {
				return e
			}
			if d.CappedAt != nil {
				at := d.CappedAt.UTC()
				d.CappedAt = &at
			}
			out.CappedDays = append(out.CappedDays, d)
		}
		return days.Err()
	})
	if e != nil {
		return watchlist.HitPage{Items: []watchlist.Hit{}, CappedDays: []watchlist.HitDay{}}, e
	}
	if len(out.Items) > q.Limit {
		out.Items = out.Items[:q.Limit]
		out.NextCursor = q.Next(u.TenantID, out.Items[q.Limit-1])
	}
	return out, nil
}

// AlertWatchlistHits 按告警身份和原始摘要读取命中；摘要不一致的告警材料不能借用其他告警的关联。
func (p *Postgres) AlertWatchlistHits(ctx context.Context, u model.Principal, event, digest string) (watchlist.AlertHits, error) {
	out := watchlist.AlertHits{Items: []watchlist.Hit{}}
	if !contract.ValidID(event) || !watchlist.ValidDigest(digest) {
		return out, watchlist.ErrInput
	}
	e := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, `SET LOCAL statement_timeout='5s'`); e != nil {
			return e
		}
		if e := watchlistActor(ctx, tx, u, false); e != nil {
			return e
		}
		if e := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&out.ObservedAt); e != nil {
			return e
		}
		out.ObservedAt = out.ObservedAt.UTC()
		rows, e := tx.Query(ctx, `SELECT `+watchlistHitColumns+` FROM watchlist_hits WHERE tenant_id=$1 AND event_id=$2 AND raw_sha256=$3 AND expires_at>now() ORDER BY list_id,list_revision LIMIT $4`, u.TenantID, event, digest, watchlist.MaxLists+1)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			hit, e := readWatchlistHit(rows, u.TenantID)
			if e != nil || hit.EventID != event || hit.RawSHA256 != digest {
				return errors.Join(watchlist.ErrSource, e)
			}
			out.Items = append(out.Items, hit)
		}
		if e := rows.Err(); e != nil {
			return e
		}
		if len(out.Items) > watchlist.MaxLists {
			return watchlist.ErrLimit
		}
		return nil
	})
	if e != nil {
		return watchlist.AlertHits{Items: []watchlist.Hit{}}, e
	}
	return out, nil
}

// BeginWatchlistImpact 核对管理员与修订并先记录操作审计，再由调用方执行有界历史检索。
func (p *Postgres) BeginWatchlistImpact(ctx context.Context, u model.Principal, id string, revision int64) (watchlist.Record, bool, time.Time, error) {
	var out watchlist.Record
	var current bool
	var checked time.Time
	if !contract.ValidID(id) || revision < 1 || revision > watchlist.MaxRevision {
		return out, false, checked, watchlist.ErrInput
	}
	e := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, `SET LOCAL lock_timeout='2s'; SET LOCAL statement_timeout='5s'`); e != nil {
			return e
		}
		if e := watchlistActor(ctx, tx, u, true); e != nil {
			return e
		}
		// 预览审计与额度计数在同一租户锁内完成，并发请求不会同时越过滚动 24 小时上限；
		// 该锁只在预览之间互斥，不阻塞命中登记使用的名单锁。修订不存在时事务回滚，不占用额度。
		if _, e := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, u.TenantID+"/watchlist-impact"); e != nil {
			return e
		}
		var used int
		if e := tx.QueryRow(ctx, `SELECT count(*) FROM operation_audits WHERE tenant_id=$1 AND action='watchlist.impact' AND created_at>now()-interval '24 hours'`, u.TenantID).Scan(&used); e != nil {
			return e
		}
		if used >= watchlist.MaxDailyImpacts {
			return watchlist.ErrQuota
		}
		var e error
		out, e = readWatchlist(tx.QueryRow(ctx, `SELECT `+watchlistColumns+` FROM watchlist_revisions v WHERE v.tenant_id=$1 AND v.list_id=$2 AND v.revision=$3 AND (v.expires_at>now() OR EXISTS(SELECT 1 FROM watchlists h WHERE h.tenant_id=v.tenant_id AND h.id=v.list_id AND h.revision=v.revision))`, u.TenantID, id, revision), false)
		if e != nil {
			return e
		}
		if e := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM watchlists WHERE tenant_id=$1 AND id=$2 AND revision=$3),clock_timestamp()`, u.TenantID, id, revision).Scan(&current, &checked); e != nil {
			return e
		}
		return insertOperationAudit(ctx, tx, u, "watchlist.impact", id, model.RequestMetadataFrom(ctx).RequestID)
	})
	if e == nil && (out.TenantID != u.TenantID || out.ID != id || out.Revision != revision) {
		return out, false, checked, watchlist.ErrSource
	}
	return out, current, checked.UTC(), e
}

// WatchlistImpact 只读告警数据流；超时、分片失败或材料不一致时不交付部分计数。
func (s *Elasticsearch) WatchlistImpact(ctx context.Context, tenant string, d watchlist.Definition, start, end time.Time) (int64, []watchlist.ValueCount, []watchlist.ImpactSample, error) {
	body, err := watchlist.ImpactDSL(tenant, d, start, end)
	if err != nil {
		return 0, nil, nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	res, err := s.API.Search(s.API.Search.WithIndex(contract.SearchIndex("alerts")), s.API.Search.WithBody(bytes.NewReader(body)), s.API.Search.WithIgnoreUnavailable(false), s.API.Search.WithAllowNoIndices(true), s.API.Search.WithAllowPartialSearchResults(false), s.API.Search.WithContext(ctx))
	if err != nil {
		if res != nil && res.Body != nil {
			res.Body.Close()
		}
		return 0, nil, nil, errors.Join(watchlist.ErrIncomplete, err)
	}
	defer res.Body.Close()
	if res.IsError() {
		return 0, nil, nil, watchlist.ErrIncomplete
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, watchlist.MaxImpactBytes+1))
	if err != nil {
		return 0, nil, nil, errors.Join(watchlist.ErrIncomplete, err)
	}
	return watchlist.DecodeImpact(raw, tenant, d, start, end)
}
