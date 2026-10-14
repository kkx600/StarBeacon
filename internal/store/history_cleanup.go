package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// 清理谓词只引用已固化的到期时间。活动配置、未决副作用和被引用版本均独立保护。
type historyCategory struct {
	table, expiry, predicate string
}

var historyCategories = []historyCategory{
	{"operation_audits", "expires_at", "true"},
	{"login_audits", "expires_at", "true"},
	{"sensor_tasks", "retain_until", `(state IN ('succeeded','failed','expired','cancelled') OR (state='unknown' AND (kind<>'rules.apply' OR rule_resolution IS NOT NULL)) OR (state='queued' AND delivery_count=0 AND expires_at<=now())) AND (kind<>'applications.apply' OR state NOT IN ('succeeded','unknown') OR EXISTS(SELECT 1 FROM sensor_tasks n WHERE n.tenant_id=h.tenant_id AND n.sensor_id=h.sensor_id AND n.registration_id=h.registration_id AND n.kind='applications.apply' AND n.state='succeeded' AND n.created_at>h.created_at))`},
	{"inventory_history", "expires_at", "true"},
	{"retention_previews", "expires_at", "true"},
	{"retention_changes", "expires_at", "true"},
	{"notification_deliveries", "expires_at", `state<>'running' AND (lease_until IS NULL OR lease_until<=now())`},
	{"notification_batches", "expires_at", `NOT EXISTS(SELECT 1 FROM notification_deliveries d WHERE d.tenant_id=h.tenant_id AND d.batch_id=h.id)`},
	{"notification_channel_versions", "expires_at", `NOT EXISTS(SELECT 1 FROM notification_channels c WHERE c.tenant_id=h.tenant_id AND c.id=h.channel_id AND c.revision=h.revision) AND NOT EXISTS(SELECT 1 FROM notification_batches b WHERE b.tenant_id=h.tenant_id AND b.channel_id=h.channel_id AND b.channel_revision=h.revision)`},
	{"model_capability_checks", "expires_at", `state<>'running'`},
	{"model_provider_versions", "expires_at", `NOT EXISTS(SELECT 1 FROM model_providers p WHERE p.tenant_id=h.tenant_id AND p.id=h.provider_id AND p.revision=h.revision) AND NOT EXISTS(SELECT 1 FROM model_capability_checks c WHERE c.tenant_id=h.tenant_id AND c.provider_id=h.provider_id AND c.provider_revision=h.revision) AND NOT EXISTS(SELECT 1 FROM analysis_jobs j WHERE j.tenant_id=h.tenant_id AND j.provider_id=h.provider_id AND j.provider_revision=h.revision) AND NOT EXISTS(SELECT 1 FROM rule_generation_jobs g WHERE g.tenant_id=h.tenant_id AND g.provider_id=h.provider_id AND g.provider_revision=h.revision) AND NOT EXISTS(SELECT 1 FROM alert_triage_jobs t WHERE t.tenant_id=h.tenant_id AND t.provider_id=h.provider_id AND t.provider_revision=h.revision) AND NOT EXISTS(SELECT 1 FROM report_plans p WHERE p.tenant_id=h.tenant_id AND p.provider_id=h.provider_id AND p.provider_revision=h.revision) AND NOT EXISTS(SELECT 1 FROM report_plan_runs r WHERE r.tenant_id=h.tenant_id AND r.provider_id=h.provider_id AND r.provider_revision=h.revision)`},
	{"report_plan_runs", "expires_at", `(state<>'preparing' OR deadline<=now()) AND NOT EXISTS(SELECT 1 FROM starbeacon_jobs.river_job j WHERE j.id=h.river_job_id AND j.state NOT IN ('completed','cancelled','discarded'))`},
	{"analysis_jobs", "expires_at", `state NOT IN ('queued','running') AND NOT EXISTS(SELECT 1 FROM starbeacon_jobs.river_job j WHERE j.id=h.river_job_id AND j.state NOT IN ('completed','cancelled','discarded')) AND NOT EXISTS(SELECT 1 FROM report_plan_runs r WHERE r.tenant_id=h.tenant_id AND r.analysis_id=h.id)`},
	{"analysis_threads", "expires_at", `NOT EXISTS(SELECT 1 FROM analysis_jobs j WHERE j.tenant_id=h.tenant_id AND j.thread_id=h.id)`},
	{"sessions", "expires_at", `user_id IN(SELECT id FROM users WHERE tenant_id=$1)`},
	{"routes", "expires_at", "true"},
	// 已持久化的分类游标保持原序，新分类放在末尾；先清历史，再清无引用的当前记录。
	{"alert_assessment_changes", "expires_at", "true"},
	{"alert_assessments", "expires_at", `NOT EXISTS(SELECT 1 FROM alert_assessment_changes c WHERE c.tenant_id=h.tenant_id AND c.event_id=h.event_id)`},
	{"rule_generation_jobs", "expires_at", `state NOT IN ('queued','running') AND NOT EXISTS(SELECT 1 FROM starbeacon_jobs.river_job j WHERE j.id=h.river_job_id AND j.state NOT IN ('completed','cancelled','discarded')) AND NOT EXISTS(SELECT 1 FROM rule_packages p WHERE p.tenant_id=h.tenant_id AND p.generation_id=h.id)`},
	{"alert_triage_jobs", "expires_at", `state NOT IN ('queued','running') AND NOT EXISTS(SELECT 1 FROM starbeacon_jobs.river_job j WHERE j.id=h.river_job_id AND j.state NOT IN ('completed','cancelled','discarded'))`},
	{"incident_changes", "expires_at", `NOT EXISTS(SELECT 1 FROM incidents i WHERE i.tenant_id=h.tenant_id AND i.id=h.incident_id AND i.state<>'closed')`},
	{"incidents", "expires_at", `state='closed' AND NOT EXISTS(SELECT 1 FROM incident_changes c WHERE c.tenant_id=h.tenant_id AND c.incident_id=h.id)`},
	{"user_management_requests", "expires_at", "true"},
	{"sensor_management_requests", "expires_at", "true"},
	{"saved_search_changes", "expires_at", "true"},
	{"saved_searches", "expires_at", `NOT active AND NOT EXISTS(SELECT 1 FROM saved_search_changes c WHERE c.tenant_id=h.tenant_id AND c.query_id=h.id AND c.generation_id=h.generation_id)`},
	{"application_rule_revisions", "expires_at", `NOT EXISTS(SELECT 1 FROM application_rules c WHERE c.tenant_id=h.tenant_id AND c.id=h.rule_id AND c.revision=h.revision)`},
	{"decision_policy_revisions", "expires_at", `NOT EXISTS(SELECT 1 FROM decision_policies c WHERE c.tenant_id=h.tenant_id AND c.id=h.policy_id AND c.revision=h.revision)`},
	{"decision_evaluations", "expires_at", "true"},
	{"decision_responses", "expires_at", "true"},
	{"decision_continuous_runs", "expires_at", "true"},
	{"decision_triage_triggers", "expires_at", `state<>'pending'`},
}

type HistorySweep struct {
	Tenants int
	Deleted int64
	ByTable map[string]int64
}

// 每轮最多访问 32 个租户、删除 4096 条记录；单租户最多 1024 条、单表最多 256 条。
// 分类游标和删除同事务持久化；租户行锁使多实例跳过正在处理的租户。
func (p *Postgres) SweepHistory(parent context.Context) (HistorySweep, error) {
	report := HistorySweep{ByTable: map[string]int64{}}
	if err := parent.Err(); err != nil {
		return report, err
	}
	if !p.historySweepMu.TryLock() {
		return report, errors.New("历史清理已在运行")
	}
	defer p.historySweepMu.Unlock()
	ctx, cancel := context.WithTimeout(parent, 20*time.Second)
	defer cancel()
	// 匿名登录审计不能借用其他租户的作用域，也不能无限占用剩余清理预算。
	anonymous, err := p.sweepAnonymousLogins(ctx)
	report.Deleted, report.ByTable["login_audits"] = anonymous, anonymous
	// 一个作用域失败不阻止其他租户；返回部分提交结果与失败，不能宣称全部清理完成。
	rows, queryErr := p.Pool.Query(ctx, `SELECT id FROM tenants WHERE id>$1 ORDER BY id LIMIT 32`, p.historySweepAfter)
	if queryErr != nil {
		return report, errors.Join(err, queryErr)
	}
	tenants, queryErr := pgx.CollectRows(rows, pgx.RowTo[string])
	if queryErr != nil {
		return report, errors.Join(err, queryErr)
	}
	if len(tenants) == 0 {
		p.historySweepAfter = ""
		rows, queryErr = p.Pool.Query(ctx, `SELECT id FROM tenants ORDER BY id LIMIT 32`)
		if queryErr != nil {
			return report, errors.Join(err, queryErr)
		}
		tenants, queryErr = pgx.CollectRows(rows, pgx.RowTo[string])
		if queryErr != nil {
			return report, errors.Join(err, queryErr)
		}
	}
	for _, tenant := range tenants {
		if report.Deleted >= 4096 || ctx.Err() != nil {
			break
		}
		counts, sweepErr := p.sweepTenantHistory(ctx, tenant, int(4096-report.Deleted))
		p.historySweepAfter = tenant
		report.Tenants++
		if sweepErr != nil {
			err = errors.Join(err, sweepErr)
			continue
		}
		for table, count := range counts {
			report.ByTable[table] += count
			report.Deleted += count
		}
	}
	return report, errors.Join(err, ctx.Err())
}

func historyTimeouts(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, `SET LOCAL lock_timeout='500ms'; SET LOCAL statement_timeout='2s'`)
	return err
}

func (p *Postgres) sweepAnonymousLogins(ctx context.Context) (int64, error) {
	tx, err := p.Pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT set_config('starbeacon.tenant_id','',true)`); err != nil {
		return 0, err
	}
	if err = historyTimeouts(ctx, tx); err != nil {
		return 0, err
	}
	tag, err := tx.Exec(ctx, `WITH picked AS(SELECT ctid FROM login_audits WHERE tenant_id IS NULL AND expires_at<=now() ORDER BY expires_at,id LIMIT 256) DELETE FROM login_audits h USING picked WHERE h.ctid=picked.ctid`)
	if err != nil {
		return 0, err
	}
	if err = tx.Commit(ctx); err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func (p *Postgres) sweepTenantHistory(ctx context.Context, tenant string, budget int) (map[string]int64, error) {
	counts := map[string]int64{}
	err := p.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		if err := historyTimeouts(ctx, tx); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO retention_maintenance(tenant_id) VALUES($1) ON CONFLICT DO NOTHING`, tenant); err != nil {
			return err
		}
		var next int
		if err := tx.QueryRow(ctx, `SELECT next_category FROM retention_maintenance WHERE tenant_id=$1 FOR UPDATE SKIP LOCKED`, tenant).Scan(&next); errors.Is(err, pgx.ErrNoRows) {
			return nil
		} else if err != nil {
			return err
		}
		if next < 0 || next >= len(historyCategories) {
			return errors.New("历史清理分类续点无效")
		}
		var deleted int64
		last := ""
		for visited := 0; visited < len(historyCategories); {
			remaining := min(budget-int(deleted), 1024-int(deleted))
			if remaining <= 0 {
				break
			}
			// 批内按每表的最大删除量预留预算，不能用尚未返回的删除数预支额度。
			// 同一事务顺序执行，减少空分类的数据库往返，不改变引用检查和分类续点。
			limit := min(256, remaining)
			size := min(remaining/limit, len(historyCategories)-visited)
			batch := &pgx.Batch{}
			for offset := range size {
				category := historyCategories[(next+offset)%len(historyCategories)]
				scope := "h.tenant_id=$1"
				if category.table == "sessions" {
					scope = "true"
				}
				// 标识符和条件均为内部常量；租户与上限始终绑定，不授予历史 UPDATE。
				query := fmt.Sprintf(`WITH picked AS(SELECT h.ctid FROM %s h WHERE %s AND h.%s<=now() AND (%s) ORDER BY h.%s,h.ctid LIMIT $2) DELETE FROM %s h USING picked WHERE h.ctid=picked.ctid`, category.table, scope, category.expiry, category.predicate, category.expiry, category.table)
				batch.Queue(query, tenant, limit)
			}
			results := tx.SendBatch(ctx, batch)
			for range size {
				tag, err := results.Exec()
				if err != nil {
					return errors.Join(err, results.Close())
				}
				category := historyCategories[next]
				counts[category.table] += tag.RowsAffected()
				deleted += tag.RowsAffected()
				last, next = category.table, (next+1)%len(historyCategories)
				visited++
			}
			if err := results.Close(); err != nil {
				return err
			}
		}
		_, err := tx.Exec(ctx, `UPDATE retention_maintenance SET next_category=$2,last_category=$3,last_deleted=$4::bigint::integer,total_deleted=total_deleted+$4::bigint,checked_at=clock_timestamp() WHERE tenant_id=$1`, tenant, next, last, deleted)
		return err
	})
	if err != nil {
		return nil, err
	}
	return counts, nil
}
