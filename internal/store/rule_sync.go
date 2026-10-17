package store

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/rulerelease"
	"github.com/kkx600/StarBeacon/internal/rulesync"
)

const ruleSyncPlanJSON = `jsonb_build_object('id',p.id,'revision',p.revision,'spec',p.spec,'created_by',p.created_by,'updated_at',p.updated_at,'next_at',p.next_at,'processed_revision',p.processed_revision)`
const ruleSyncRunJSON = `jsonb_build_object('id',r.id,'plan_revision',r.plan_revision,'spec',r.spec,'created_by',r.created_by,'state',r.state,'code',r.code,'stage',r.stage,'tasks',r.tasks,'expected_sha256',r.expected_sha256,'created_at',r.created_at,'finished_at',r.finished_at,'expires_at',r.expires_at)`

func readRuleSyncPlan(row pgx.Row) (rulesync.Plan, error) {
	var p rulesync.Plan
	var raw []byte
	err := row.Scan(&raw)
	if err == nil {
		err = json.Unmarshal(raw, &p)
	}
	return p, err
}

func readRuleSyncRun(row pgx.Row) (*rulesync.Run, error) {
	var r rulesync.Run
	var raw []byte
	if err := row.Scan(&raw); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, err
	}
	if r.Spec.Validate() != nil || !contract.ValidID(r.CreatedBy) {
		return nil, rulesync.ErrInput
	}
	return &r, nil
}

func ruleSyncLatest(ctx context.Context, tx pgx.Tx, tenant, id string) (*rulesync.Run, error) {
	r, err := readRuleSyncRun(tx.QueryRow(ctx, `SELECT `+ruleSyncRunJSON+` FROM rule_sync_runs r WHERE tenant_id=$1 AND plan_id=$2 AND (expires_at>now() OR finished_at IS NULL) ORDER BY plan_revision DESC LIMIT 1`, tenant, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return r, err
}

type RuleSyncPage struct {
	Items      []rulesync.Plan `json:"items"`
	NextCursor string          `json:"next_cursor"`
}

func (p *Postgres) RuleSyncPlans(ctx context.Context, u model.Principal, cursor string) (RuleSyncPage, error) {
	page := RuleSyncPage{Items: []rulesync.Plan{}}
	if cursor != "" && !contract.ValidID(cursor) {
		return page, rulesync.ErrInput
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := sensorManager(ctx, tx, u); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT `+ruleSyncPlanJSON+` FROM rule_sync_plans p WHERE tenant_id=$1 AND id>$2 ORDER BY id LIMIT 21`, u.TenantID, cursor)
		if err != nil {
			return err
		}
		for rows.Next() {
			item, err := readRuleSyncPlan(rows)
			if err != nil {
				rows.Close()
				return err
			}
			page.Items = append(page.Items, item)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		if len(page.Items) > 20 {
			page.Items = page.Items[:20]
			page.NextCursor = page.Items[19].ID
		}
		for i := range page.Items {
			page.Items[i].Run, err = ruleSyncLatest(ctx, tx, u.TenantID, page.Items[i].ID)
			if err != nil {
				return err
			}
		}
		return nil
	})
	return page, err
}

// 计划绑定单台设备及注册代次；目录分页和分组变化不会扩大授权范围。
func (p *Postgres) SaveRuleSyncPlan(ctx context.Context, u model.Principal, c rulesync.Change, request string) (rulesync.Plan, error) {
	var out rulesync.Plan
	if c.Validate() != nil {
		return out, rulesync.ErrInput
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := sensorManager(ctx, tx, u); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, u.TenantID+"/rule-sync"); err != nil {
			return err
		}
		prior, err := readRuleSyncPlan(tx.QueryRow(ctx, `SELECT `+ruleSyncPlanJSON+` FROM rule_sync_plans p WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, u.TenantID, c.ID))
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if prior.ID != "" && prior.CreatedBy != u.ID {
			return pgx.ErrNoRows
		}
		if prior.Revision == c.ExpectedRevision+1 && prior.Spec == c.Spec {
			out = prior
			return nil
		}
		if prior.Revision != c.ExpectedRevision {
			return ErrConflict
		}
		if prior.ID != "" && prior.Spec.SensorID != c.Spec.SensorID {
			return rulesync.ErrInput
		}
		var changes, count int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM operation_audits WHERE tenant_id=$1 AND action='rules.sync.save' AND created_at>now()-interval '24 hours'`, u.TenantID).Scan(&changes); err != nil {
			return err
		}
		if changes >= 10000 {
			return rulesync.ErrQuota
		}
		if prior.ID == "" {
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM rule_sync_plans WHERE tenant_id=$1`, u.TenantID).Scan(&count); err != nil {
				return err
			}
			if count >= 10000 {
				return rulesync.ErrQuota
			}
		}
		run, err := ruleSyncLatest(ctx, tx, u.TenantID, c.ID)
		if err != nil {
			return err
		}
		if run != nil && !rulesync.Terminal(run.State) {
			paused := prior.Spec
			paused.Enabled = false
			if c.Spec != paused {
				return ErrConflict
			}
		}
		// 停用不能因设备离线或样本失效而被拒绝；启用时才重新核对授权依赖。
		if c.Spec.Enabled {
			var registration string
			if err := tx.QueryRow(ctx, `SELECT registration_id FROM sensors WHERE tenant_id=$1 AND id=$2 AND active FOR SHARE`, u.TenantID, c.Spec.SensorID).Scan(&registration); err != nil {
				return err
			}
			if registration != c.Spec.RegistrationID {
				return ErrConflict
			}
			var exists bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM rule_packages WHERE tenant_id=$1 AND id=$2 AND revision=$3)`, u.TenantID, c.Spec.PackageID, c.Spec.PackageRevision).Scan(&exists); err != nil {
				return err
			}
			if !exists {
				return pgx.ErrNoRows
			}
			var positive, negative string
			if err := tx.QueryRow(ctx, `SELECT a.sha256,b.sha256 FROM replay_samples a JOIN replay_samples b ON b.tenant_id=a.tenant_id WHERE a.tenant_id=$1 AND a.id=$2 AND b.id=$3 AND a.state='ready' AND b.state='ready' AND a.expires_at>now()+interval '31 minutes' AND b.expires_at>now()+interval '31 minutes' FOR SHARE OF a,b`, u.TenantID, c.Spec.PositiveSampleID, c.Spec.NegativeSampleID).Scan(&positive, &negative); err != nil {
				return err
			}
			if positive == negative {
				return rulesync.ErrInput
			}
		}
		raw, _ := json.Marshal(c.Spec)
		_, err = tx.Exec(ctx, `INSERT INTO rule_sync_plans(tenant_id,id,sensor_id,registration_id,revision,created_by,spec,enabled) VALUES($1,$2,$3,$4,1,$5,$6,$7) ON CONFLICT(tenant_id,id) DO UPDATE SET revision=rule_sync_plans.revision+1,registration_id=excluded.registration_id,spec=excluded.spec,enabled=excluded.enabled,updated_at=clock_timestamp(),next_at=clock_timestamp()`, u.TenantID, c.ID, c.Spec.SensorID, c.Spec.RegistrationID, u.ID, raw, c.Spec.Enabled)
		if err != nil {
			return sensorWriteError(err)
		}
		out, err = readRuleSyncPlan(tx.QueryRow(ctx, `SELECT `+ruleSyncPlanJSON+` FROM rule_sync_plans p WHERE tenant_id=$1 AND id=$2`, u.TenantID, c.ID))
		if err != nil {
			return err
		}
		out.Run = run
		return insertOperationAudit(ctx, tx, u, "rules.sync.save", c.ID, request)
	})
	return out, err
}

func finishRuleSync(ctx context.Context, tx pgx.Tx, tenant string, plan rulesync.Plan, run *rulesync.Run, state, code string) error {
	if _, err := tx.Exec(ctx, `UPDATE rule_sync_runs SET state=$3,code=$4,stage=$5,finished_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND finished_at IS NULL`, tenant, run.ID, state, code, run.Stage); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `UPDATE rule_sync_plans SET processed_revision=greatest(processed_revision,$3) WHERE tenant_id=$1 AND id=$2`, tenant, plan.ID, run.PlanRevision)
	return err
}

// 每轮最多十六个到期设备；任务与阶段推进同事务，进程中断后从持久回执继续。
func (p *Postgres) SweepRuleSync(ctx context.Context, tenant string, signer ed25519.PrivateKey) (int, error) {
	if len(signer) != ed25519.PrivateKeySize {
		return 0, rulesync.ErrInput
	}
	ids := []string{}
	err := p.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id FROM rule_sync_plans WHERE tenant_id=$1 AND next_at<=now() AND (enabled OR EXISTS(SELECT 1 FROM rule_sync_runs r WHERE r.tenant_id=$1 AND r.plan_id=rule_sync_plans.id AND r.finished_at IS NULL)) ORDER BY next_at,id LIMIT 16`, tenant)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return err
			}
			ids = append(ids, id)
		}
		return rows.Err()
	})
	if err != nil {
		return 0, err
	}
	count := 0
	var failures error
	for _, id := range ids {
		err := p.advanceRuleSync(ctx, tenant, id, signer)
		if errors.Is(err, pgx.ErrNoRows) {
			continue
		}
		if err != nil {
			failures = errors.Join(failures, err)
			continue
		}
		count++
	}
	return count, failures
}

func (p *Postgres) advanceRuleSync(ctx context.Context, tenant, id string, signer ed25519.PrivateKey) error {
	return p.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout='2s'; SET LOCAL statement_timeout='4s'`); err != nil {
			return err
		}
		// 管理员资格锁先于计划和设备，保持与编辑操作的锁顺序一致。
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, tenant+"/users"); err != nil {
			return err
		}
		plan, err := readRuleSyncPlan(tx.QueryRow(ctx, `SELECT `+ruleSyncPlanJSON+` FROM rule_sync_plans p WHERE tenant_id=$1 AND id=$2 AND next_at<=now() FOR UPDATE SKIP LOCKED`, tenant, id))
		if err != nil {
			return err
		}
		if plan.Spec.Validate() != nil {
			return rulesync.ErrInput
		}
		if _, err := tx.Exec(ctx, `UPDATE rule_sync_plans SET next_at=clock_timestamp()+make_interval(secs=>$3) WHERE tenant_id=$1 AND id=$2`, tenant, id, plan.Spec.IntervalSeconds); err != nil {
			return err
		}
		run, err := ruleSyncLatest(ctx, tx, tenant, id)
		if err != nil {
			return err
		}
		if run == nil || rulesync.Terminal(run.State) {
			if !plan.Spec.Enabled || plan.ProcessedRevision >= plan.Revision {
				return nil
			}
			frozen, _ := json.Marshal(plan.Spec)
			run, err = readRuleSyncRun(tx.QueryRow(ctx, `INSERT INTO rule_sync_runs AS r(tenant_id,id,plan_id,plan_revision,state,expected_sha256,spec,created_by,expires_at) VALUES($1,$2,$3,$4,'pending','',$5,$6,now()+make_interval(days=>COALESCE((SELECT days FROM retention_policies WHERE tenant_id=$1 AND category='operations'),180))) RETURNING `+ruleSyncRunJSON, tenant, RandomID("sync_run_"), id, plan.Revision, frozen, plan.CreatedBy))
			if err != nil {
				return err
			}
		}
		u := model.Principal{ID: plan.CreatedBy, TenantID: tenant, Role: "admin"}
		// 已签名任务不能由停用计划推定取消；先核对其独立终态，再禁止后续步骤。
		if run.Stage < 4 && run.Tasks[run.Stage] != "" {
			var taskState string
			var receipt []byte
			if _, err := tx.Exec(ctx, `UPDATE sensor_tasks SET state='expired',updated_at=now() WHERE tenant_id=$1 AND id=$2 AND state='queued' AND delivery_count=0 AND expires_at<=now()`, tenant, run.Tasks[run.Stage]); err != nil {
				return err
			}
			err := tx.QueryRow(ctx, `SELECT state,COALESCE(receipt,'{}'::jsonb) FROM sensor_tasks WHERE tenant_id=$1 AND id=$2 AND sensor_id=$3 AND registration_id=$4 FOR SHARE`, tenant, run.Tasks[run.Stage], plan.Spec.SensorID, plan.Spec.RegistrationID).Scan(&taskState, &receipt)
			if errors.Is(err, pgx.ErrNoRows) {
				return finishRuleSync(ctx, tx, tenant, plan, run, "blocked", "task_record_unavailable")
			}
			if err != nil {
				return err
			}
			switch taskState {
			case "queued", "delivered", "running":
				return nil
			case "succeeded":
				if run.Stage == 3 {
					var r control.Receipt
					var expected string
					if err := tx.QueryRow(ctx, `SELECT sha256 FROM rule_packages WHERE tenant_id=$1 AND id=$2 AND revision=$3`, tenant, plan.Spec.PackageID, plan.Spec.PackageRevision).Scan(&expected); err != nil {
						return err
					}
					if json.Unmarshal(receipt, &r) != nil || !rulesync.Applied(r.Result, expected) {
						return finishRuleSync(ctx, tx, tenant, plan, run, "blocked", "apply_receipt_unverified")
					}
					return finishRuleSync(ctx, tx, tenant, plan, run, "succeeded", "applied")
				}
				run.Stage++
			default:
				return finishRuleSync(ctx, tx, tenant, plan, run, "blocked", "task_"+taskState)
			}
		}
		if plan.Revision != run.PlanRevision || !plan.Spec.Enabled {
			return finishRuleSync(ctx, tx, tenant, plan, run, "paused", "plan_disabled")
		}
		if err := sensorManager(ctx, tx, u); errors.Is(err, pgx.ErrNoRows) {
			return finishRuleSync(ctx, tx, tenant, plan, run, "blocked", "owner_unavailable")
		} else if err != nil {
			return err
		}
		var registration string
		var active bool
		var seen *time.Time
		var raw []byte
		if err := tx.QueryRow(ctx, `SELECT registration_id,active,last_seen,health FROM sensors WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenant, plan.Spec.SensorID).Scan(&registration, &active, &seen, &raw); err != nil {
			return err
		}
		if !active || registration != plan.Spec.RegistrationID {
			return finishRuleSync(ctx, tx, tenant, plan, run, "blocked", "sensor_identity_changed")
		}
		if seen == nil || time.Since(*seen) > 90*time.Second {
			// 离线尚未创建任务的阶段留在原位，恢复后再核对；不重复已完成的步骤。
			_, err := tx.Exec(ctx, `UPDATE rule_sync_runs SET stage=$3,state='pending',code='sensor_offline' WHERE tenant_id=$1 AND id=$2`, tenant, run.ID, run.Stage)
			return err
		}
		var health model.HostHealth
		if json.Unmarshal(raw, &health) != nil || health.CommandSignerSHA256 != control.Digest(signer.Public().(ed25519.PublicKey)) {
			return finishRuleSync(ctx, tx, tenant, plan, run, "blocked", "device_trust_changed")
		}
		for _, kind := range []string{"rules.validate", "rules.replay", "rules.apply"} {
			found := false
			for _, cap := range health.TaskCapabilities {
				found = found || cap == kind
			}
			if !found {
				return finishRuleSync(ctx, tx, tenant, plan, run, "blocked", "capability_unavailable")
			}
		}
		if len(health.RegisteredRulesSHA256) != 64 {
			return finishRuleSync(ctx, tx, tenant, plan, run, "blocked", "rules_digest_unavailable")
		}
		if run.ExpectedSHA256 == "" {
			run.ExpectedSHA256 = health.RegisteredRulesSHA256
		}
		if run.ExpectedSHA256 != health.RegisteredRulesSHA256 {
			return finishRuleSync(ctx, tx, tenant, plan, run, "blocked", "rules_digest_changed")
		}
		var text, sha, engine string
		if err := tx.QueryRow(ctx, `SELECT rules_text,sha256,engine_version FROM rule_packages WHERE tenant_id=$1 AND id=$2 AND revision=$3`, tenant, plan.Spec.PackageID, plan.Spec.PackageRevision).Scan(&text, &sha, &engine); err != nil {
			return err
		}
		rules := control.RulePackage{PackageID: plan.Spec.PackageID, Revision: plan.Spec.PackageRevision, Text: text, SHA256: sha, EngineVersion: engine}
		var payload json.RawMessage
		if run.Stage == 1 || run.Stage == 2 {
			sample := plan.Spec.PositiveSampleID
			if run.Stage == 2 {
				sample = plan.Spec.NegativeSampleID
			}
			v, err := scanSample(tx.QueryRow(ctx, `SELECT id,name,size,sha256,format,created_at,expires_at,origin FROM replay_samples WHERE tenant_id=$1 AND id=$2 AND state='ready' AND expires_at>now()+interval '31 minutes' FOR SHARE`, tenant, sample))
			if errors.Is(err, pgx.ErrNoRows) {
				return finishRuleSync(ctx, tx, tenant, plan, run, "blocked", "sample_unavailable")
			}
			if err != nil {
				return err
			}
			payload, err = control.ReplayPayload(control.Replay{SampleID: v.ID, SampleSHA256: v.SHA256, SampleSize: v.Size, RuleMode: "package", Package: &rules, Origin: v.Origin})
		} else {
			if run.Stage == 3 {
				rules.Authorization = &control.RuleAuthorization{ValidationTaskID: run.Tasks[0], PositiveReplayTaskID: run.Tasks[1], NegativeReplayTaskID: run.Tasks[2], ExpectedRulesSHA256: run.ExpectedSHA256}
			}
			payload, err = control.RulePayload(rules)
		}
		if err != nil {
			return err
		}
		// 保存点允许确定性拒绝留档；数据库故障仍回滚整步，不留下半个任务。
		nested, err := tx.Begin(ctx)
		if err != nil {
			return err
		}
		taskID, taskErr := createTaskTx(ctx, nested, u, plan.Spec.SensorID, rulesync.Kind(run.Stage), "rulesync_"+id+"_"+strconv.FormatInt(plan.Revision, 10)+"_"+strconv.Itoa(run.Stage), payload, signer, false)
		if taskErr != nil {
			if err := nested.Rollback(ctx); err != nil {
				return err
			}
			if errors.Is(taskErr, ErrConflict) || errors.Is(taskErr, pgx.ErrNoRows) || errors.Is(taskErr, rulerelease.ErrQualification) {
				return finishRuleSync(ctx, tx, tenant, plan, run, "blocked", "task_qualification_changed")
			}
			return taskErr
		}
		if err := nested.Commit(ctx); err != nil {
			return err
		}
		run.Tasks[run.Stage] = taskID
		tasks, _ := json.Marshal(run.Tasks)
		_, err = tx.Exec(ctx, `UPDATE rule_sync_runs SET stage=$3,state=$4,code='',tasks=$5,expected_sha256=$6 WHERE tenant_id=$1 AND id=$2`, tenant, run.ID, run.Stage, rulesync.State(run.Stage), tasks, run.ExpectedSHA256)
		return err
	})
}
