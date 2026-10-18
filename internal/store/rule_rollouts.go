package store

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/rulerollout"
	"github.com/kkx600/StarBeacon/internal/rulesync"
)

const ruleRolloutJSON = `jsonb_build_object('id',r.id,'spec',r.spec,'created_by',r.created_by,'state',r.state,'code',r.code,'current_batch',r.current_batch,'package_sha256',r.package_sha256,'created_at',r.created_at,'deadline',r.deadline,'next_at',r.next_at,'observation_started_at',r.observation_started_at,'finished_at',r.finished_at,'expires_at',r.expires_at,'stop_reason',r.stop_reason,'stopped_by',r.stopped_by)`

func readRuleRollout(row pgx.Row) (rulerollout.Rollout, error) {
	var r rulerollout.Rollout
	var raw []byte
	err := row.Scan(&raw)
	if err == nil {
		err = json.Unmarshal(raw, &r)
	}
	if err == nil {
		r.Code = rulerollout.RecordCode(r.State, r.Code)
	}
	return r, err
}

func ruleRolloutTargets(ctx context.Context, tx pgx.Tx, tenant, id string) ([]rulerollout.Target, error) {
	items := []rulerollout.Target{}
	rows, err := tx.Query(ctx, `SELECT t.ordinal,t.batch,t.plan_id,t.authorized_revision,t.execution_revision,t.spec,t.state,t.code,CASE WHEN r.id IS NULL THEN NULL ELSE `+ruleSyncRunJSON+` END FROM rule_rollout_targets t LEFT JOIN rule_sync_runs r ON r.tenant_id=t.tenant_id AND r.plan_id=t.plan_id AND r.plan_revision=t.execution_revision WHERE t.tenant_id=$1 AND t.rollout_id=$2 ORDER BY t.ordinal`, tenant, id)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var t rulerollout.Target
		var raw, runRaw []byte
		if err = rows.Scan(&t.Ordinal, &t.Batch, &t.PlanID, &t.AuthorizedRevision, &t.ExecutionRevision, &raw, &t.State, &t.Code, &runRaw); err == nil {
			err = json.Unmarshal(raw, &t.Spec)
		}
		if err == nil && len(runRaw) > 0 {
			t.Run = new(rulesync.Run)
			err = json.Unmarshal(runRaw, t.Run)
			if err == nil && (t.Run.Spec.Validate() != nil || !contract.ValidID(t.Run.CreatedBy)) {
				err = rulesync.ErrInput
			}
		}
		if err != nil {
			rows.Close()
			return nil, err
		}
		items = append(items, t)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	return items, nil
}

type RuleRolloutPage struct {
	Items      []rulerollout.Rollout `json:"items"`
	NextCursor string                `json:"next_cursor"`
}

func (p *Postgres) RuleRollouts(ctx context.Context, u model.Principal, cursor string) (RuleRolloutPage, error) {
	out := RuleRolloutPage{Items: []rulerollout.Rollout{}}
	if cursor != "" && !contract.ValidID(cursor) {
		return out, rulerollout.ErrInput
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := sensorManager(ctx, tx, u); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT `+ruleRolloutJSON+` FROM rule_rollouts r WHERE tenant_id=$1 AND id>$2 AND (expires_at>now() OR finished_at IS NULL) ORDER BY id LIMIT 21`, u.TenantID, cursor)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			r, err := readRuleRollout(rows)
			if err != nil {
				return err
			}
			out.Items = append(out.Items, r)
		}
		if err = rows.Err(); err != nil {
			return err
		}
		if len(out.Items) > 20 {
			out.Items = out.Items[:20]
			out.NextCursor = out.Items[19].ID
		}
		return nil
	})
	return out, err
}

func (p *Postgres) RuleRollout(ctx context.Context, u model.Principal, id string) (rulerollout.Rollout, error) {
	var out rulerollout.Rollout
	if !contract.ValidID(id) {
		return out, rulerollout.ErrInput
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := sensorManager(ctx, tx, u); err != nil {
			return err
		}
		var err error
		out, err = readRuleRollout(tx.QueryRow(ctx, `SELECT `+ruleRolloutJSON+` FROM rule_rollouts r WHERE tenant_id=$1 AND id=$2 AND (expires_at>now() OR finished_at IS NULL)`, u.TenantID, id))
		if err != nil {
			return err
		}
		out.Targets, err = ruleRolloutTargets(ctx, tx, u.TenantID, id)
		return err
	})
	return out, err
}

// 创建、目标预留及批准快照同事务提交。只有原批准者自己的停用计划可入批次。
func (p *Postgres) CreateRuleRollout(ctx context.Context, u model.Principal, c rulerollout.Create, request string) (rulerollout.Rollout, error) {
	var out rulerollout.Rollout
	if c.Validate() != nil {
		return out, rulerollout.ErrInput
	}
	raw, _ := json.Marshal(c.Spec)
	sha := Hash(string(raw))
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := sensorManager(ctx, tx, u); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, u.TenantID+"/rule-sync"); err != nil {
			return err
		}
		prior, err := readRuleRollout(tx.QueryRow(ctx, `SELECT `+ruleRolloutJSON+` FROM rule_rollouts r WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, u.TenantID, c.ID))
		if err == nil {
			if prior.CreatedBy != u.ID {
				return pgx.ErrNoRows
			}
			var old string
			if err = tx.QueryRow(ctx, `SELECT request_sha256 FROM rule_rollouts WHERE tenant_id=$1 AND id=$2`, u.TenantID, c.ID).Scan(&old); err != nil {
				return err
			}
			if old != sha || prior.FinishedAt != nil && !prior.ExpiresAt.After(time.Now()) {
				return ErrConflict
			}
			out = prior
			out.Targets, err = ruleRolloutTargets(ctx, tx, u.TenantID, c.ID)
			return err
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		var total, active, changes int
		if err = tx.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE finished_at IS NULL) FROM rule_rollouts WHERE tenant_id=$1`, u.TenantID).Scan(&total, &active); err != nil {
			return err
		}
		if err = tx.QueryRow(ctx, `SELECT count(*) FROM operation_audits WHERE tenant_id=$1 AND action='rules.rollout.create' AND created_at>now()-interval '24 hours'`, u.TenantID).Scan(&changes); err != nil {
			return err
		}
		if total >= 10000 || active >= 10 || changes >= 1000 {
			return rulerollout.ErrQuota
		}
		ordered := append([]rulerollout.Selection(nil), c.Spec.Plans...)
		sort.Slice(ordered, func(i, j int) bool { return ordered[i].PlanID < ordered[j].PlanID })
		plans := map[string]rulesync.Plan{}
		for _, sel := range ordered {
			plan, err := readRuleSyncPlan(tx.QueryRow(ctx, `SELECT `+ruleSyncPlanJSON+` FROM rule_sync_plans p WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, u.TenantID, sel.PlanID))
			if err != nil {
				return err
			}
			if plan.CreatedBy != u.ID {
				return pgx.ErrNoRows
			}
			if plan.Revision != sel.Revision || plan.Spec.Enabled {
				return ErrConflict
			}
			if plan.Spec.Validate() != nil {
				return rulerollout.ErrInput
			}
			var occupied bool
			if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM rule_rollout_targets WHERE tenant_id=$1 AND plan_id=$2 AND NOT released) OR EXISTS(SELECT 1 FROM rule_sync_runs WHERE tenant_id=$1 AND plan_id=$2 AND finished_at IS NULL)`, u.TenantID, plan.ID).Scan(&occupied); err != nil {
				return err
			}
			if occupied {
				return ErrConflict
			}
			var registration string
			if err = tx.QueryRow(ctx, `SELECT registration_id FROM sensors WHERE tenant_id=$1 AND id=$2 AND active FOR SHARE`, u.TenantID, plan.Spec.SensorID).Scan(&registration); err != nil {
				return err
			}
			if registration != plan.Spec.RegistrationID {
				return ErrConflict
			}
			plans[plan.ID] = plan
		}
		base := plans[c.Spec.Plans[0].PlanID].Spec
		for _, plan := range plans {
			if !rulerollout.SameRelease(base, plan.Spec) {
				return rulerollout.ErrInput
			}
		}
		var pkgSHA, positive, negative string
		if err = tx.QueryRow(ctx, `SELECT sha256 FROM rule_packages WHERE tenant_id=$1 AND id=$2 AND revision=$3`, u.TenantID, base.PackageID, base.PackageRevision).Scan(&pkgSHA); err != nil {
			return err
		}
		if err = tx.QueryRow(ctx, `SELECT a.sha256,b.sha256 FROM replay_samples a JOIN replay_samples b ON b.tenant_id=a.tenant_id WHERE a.tenant_id=$1 AND a.id=$2 AND b.id=$3 AND a.state='ready' AND b.state='ready' AND a.expires_at>now()+interval '31 minutes' AND b.expires_at>now()+interval '31 minutes' FOR SHARE OF a,b`, u.TenantID, base.PositiveSampleID, base.NegativeSampleID).Scan(&positive, &negative); err != nil {
			return err
		}
		if positive == negative {
			return rulerollout.ErrInput
		}
		_, err = tx.Exec(ctx, `INSERT INTO rule_rollouts(tenant_id,id,spec,request_sha256,created_by,package_sha256,deadline,expires_at) VALUES($1,$2,$3,$4,$5,$6,now()+make_interval(secs=>$7),now()+make_interval(days=>COALESCE((SELECT days FROM retention_policies WHERE tenant_id=$1 AND category='operations'),180)))`, u.TenantID, c.ID, raw, sha, u.ID, pkgSHA, c.Spec.TimeoutSeconds)
		if err != nil {
			return err
		}
		for i, sel := range c.Spec.Plans {
			frozen, _ := json.Marshal(plans[sel.PlanID].Spec)
			if _, err = tx.Exec(ctx, `INSERT INTO rule_rollout_targets(tenant_id,rollout_id,ordinal,batch,plan_id,authorized_revision,spec) VALUES($1,$2,$3,$4,$5,$6,$7)`, u.TenantID, c.ID, i, c.Spec.Batch(i), sel.PlanID, sel.Revision, frozen); err != nil {
				return sensorWriteError(err)
			}
		}
		out, err = readRuleRollout(tx.QueryRow(ctx, `SELECT `+ruleRolloutJSON+` FROM rule_rollouts r WHERE tenant_id=$1 AND id=$2`, u.TenantID, c.ID))
		if err != nil {
			return err
		}
		out.Targets, err = ruleRolloutTargets(ctx, tx, u.TenantID, c.ID)
		if err != nil {
			return err
		}
		return insertOperationAudit(ctx, tx, u, "rules.rollout.create", c.ID, request)
	})
	return out, err
}

// 停止先撤回后续阶段的计划授权，已签名任务继续按原回执核对。
func stopRuleRollout(ctx context.Context, tx pgx.Tx, tenant string, r *rulerollout.Rollout, code string) error {
	if r.State != "stopping" {
		if _, err := tx.Exec(ctx, `UPDATE rule_rollouts SET state='stopping',code=$3,observation_started_at=NULL,next_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2`, tenant, r.ID, code); err != nil {
			return err
		}
		r.State = "stopping"
		r.Code = code
	}
	_, err := tx.Exec(ctx, `UPDATE rule_sync_plans p SET revision=p.revision+1,spec=jsonb_set(p.spec,'{enabled}','false'),enabled=false,updated_at=clock_timestamp(),next_at=clock_timestamp() FROM rule_rollout_targets t WHERE t.tenant_id=$1 AND t.rollout_id=$2 AND t.execution_revision>0 AND p.tenant_id=t.tenant_id AND p.id=t.plan_id AND p.revision=t.execution_revision AND p.enabled`, tenant, r.ID)
	return err
}

func (p *Postgres) StopRuleRollout(ctx context.Context, u model.Principal, id string, input rulerollout.Stop, request string) (rulerollout.Rollout, error) {
	var out rulerollout.Rollout
	if !contract.ValidID(id) || input.Validate() != nil {
		return out, rulerollout.ErrInput
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := sensorManager(ctx, tx, u); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, u.TenantID+"/rule-sync"); err != nil {
			return err
		}
		var err error
		out, err = readRuleRollout(tx.QueryRow(ctx, `SELECT `+ruleRolloutJSON+` FROM rule_rollouts r WHERE tenant_id=$1 AND id=$2 AND (expires_at>now() OR finished_at IS NULL) FOR UPDATE`, u.TenantID, id))
		if err != nil {
			return err
		}
		if out.StoppedBy != "" {
			if out.StoppedBy != u.ID || out.StopReason != input.Reason {
				return ErrConflict
			}
		} else {
			if rulerollout.Terminal(out.State) || out.State == "stopping" {
				return ErrConflict
			}
			if err = stopRuleRollout(ctx, tx, u.TenantID, &out, "operator_stopped"); err != nil {
				return err
			}
			if _, err = tx.Exec(ctx, `UPDATE rule_rollouts SET stopped_by=$3,stop_reason=$4 WHERE tenant_id=$1 AND id=$2`, u.TenantID, id, u.ID, input.Reason); err != nil {
				return err
			}
			out.StoppedBy = u.ID
			out.StopReason = input.Reason
			if err = insertOperationAudit(ctx, tx, u, "rules.rollout.stop", id, request); err != nil {
				return err
			}
		}
		out.Targets, err = ruleRolloutTargets(ctx, tx, u.TenantID, id)
		return err
	})
	return out, err
}

// 分批控制只改变已批准计划的启用状态；四步签名和原生资格继续由同步执行器负责。
func (p *Postgres) SweepRuleRollouts(ctx context.Context, tenant string) (int, error) {
	ids := []string{}
	err := p.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id FROM rule_rollouts WHERE tenant_id=$1 AND finished_at IS NULL AND next_at<=now() ORDER BY next_at,id LIMIT 2`, tenant)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if err = rows.Scan(&id); err != nil {
				return err
			}
			ids = append(ids, id)
		}
		return rows.Err()
	})
	if err != nil {
		return 0, err
	}
	n := 0
	var failures error
	for _, id := range ids {
		if err = p.advanceRuleRollout(ctx, tenant, id); errors.Is(err, pgx.ErrNoRows) {
			continue
		} else if err != nil {
			failures = errors.Join(failures, err)
		} else {
			n++
		}
	}
	return n, failures
}

func finishRuleRollout(ctx context.Context, tx pgx.Tx, tenant string, r rulerollout.Rollout, state string) error {
	if _, err := tx.Exec(ctx, `UPDATE rule_rollout_targets SET released=true WHERE tenant_id=$1 AND rollout_id=$2`, tenant, r.ID); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `UPDATE rule_rollouts SET state=$3,code=CASE WHEN $3='succeeded' THEN 'observed' ELSE code END,finished_at=clock_timestamp(),observation_started_at=NULL WHERE tenant_id=$1 AND id=$2`, tenant, r.ID, state)
	return err
}

func saveRolloutTarget(ctx context.Context, tx pgx.Tx, tenant, id string, t rulerollout.Target) error {
	_, err := tx.Exec(ctx, `UPDATE rule_rollout_targets SET state=$4,code=$5 WHERE tenant_id=$1 AND rollout_id=$2 AND ordinal=$3`, tenant, id, t.Ordinal, t.State, t.Code)
	return err
}

func (p *Postgres) advanceRuleRollout(ctx context.Context, tenant, id string) error {
	return p.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout='2s'; SET LOCAL statement_timeout='4s'`); err != nil {
			return err
		}
		for _, key := range []string{tenant + "/users", tenant + "/rule-sync"} {
			if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, key); err != nil {
				return err
			}
		}
		r, err := readRuleRollout(tx.QueryRow(ctx, `SELECT `+ruleRolloutJSON+` FROM rule_rollouts r WHERE tenant_id=$1 AND id=$2 AND finished_at IS NULL AND next_at<=now() FOR UPDATE SKIP LOCKED`, tenant, id))
		if err != nil {
			return err
		}
		if r.Spec.Validate() != nil {
			return rulerollout.ErrInput
		}
		if _, err = tx.Exec(ctx, `UPDATE rule_rollouts SET next_at=clock_timestamp()+interval '5 seconds' WHERE tenant_id=$1 AND id=$2`, tenant, id); err != nil {
			return err
		}
		targets, err := ruleRolloutTargets(ctx, tx, tenant, id)
		if err != nil {
			return err
		}
		if len(targets) != len(r.Spec.Plans) {
			return rulerollout.ErrInput
		}
		var now time.Time
		if err = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
			return err
		}
		if r.State != "stopping" {
			ownerErr := sensorManager(ctx, tx, model.Principal{ID: r.CreatedBy, TenantID: tenant, Role: "admin"})
			code := ""
			if errors.Is(ownerErr, pgx.ErrNoRows) {
				code = "owner_unavailable"
			} else if ownerErr != nil {
				return ownerErr
			}
			if !now.Before(r.Deadline) {
				code = "deadline_exceeded"
			}
			if code != "" {
				if err = stopRuleRollout(ctx, tx, tenant, &r, code); err != nil {
					return err
				}
			}
		}
		allReady := true
		for i := range targets {
			t := &targets[i]
			if t.ExecutionRevision == 0 {
				continue
			}
			if t.Run == nil {
				allReady = false
				continue
			}
			expectedSpec := t.Spec
			expectedSpec.Enabled = true
			if t.Run.PlanRevision != t.ExecutionRevision || t.Run.CreatedBy != r.CreatedBy || t.Run.Spec != expectedSpec {
				return rulerollout.ErrInput
			}
			if !rulesync.Terminal(t.Run.State) {
				allReady = false
				continue
			}
			if t.Run.State == "succeeded" {
				t.State = "observing"
				if r.State == "stopping" || t.Batch < r.CurrentBatch {
					t.State = "succeeded"
				}
				if t.Code != "observed" {
					t.Code = "applied"
				}
			} else {
				t.State = "blocked"
				t.Code = t.Run.Code
				if r.State != "stopping" {
					if err = stopRuleRollout(ctx, tx, tenant, &r, "target_failed"); err != nil {
						return err
					}
				}
			}
			if err = saveRolloutTarget(ctx, tx, tenant, id, *t); err != nil {
				return err
			}
		}
		if r.State == "stopping" {
			pending := false
			for i := range targets {
				t := &targets[i]
				if t.ExecutionRevision == 0 || t.Run == nil {
					t.State = "stopped"
					t.Code = "not_dispatched"
					if err = saveRolloutTarget(ctx, tx, tenant, id, *t); err != nil {
						return err
					}
				} else if !rulesync.Terminal(t.Run.State) {
					pending = true
				}
			}
			if pending {
				return nil
			}
			state := "blocked"
			if r.Code == "operator_stopped" {
				state = "stopped"
			}
			return finishRuleRollout(ctx, tx, tenant, r, state)
		}
		// 已执行批次在后续推进中仍参与设备身份、实际摘要和心跳水位核对。
		fresh := true
		code := "waiting_for_results"
		for _, t := range targets {
			if t.ExecutionRevision == 0 || t.Run == nil || t.Run.State != "succeeded" {
				continue
			}
			var active bool
			var registration string
			var seen *time.Time
			var raw []byte
			if err = tx.QueryRow(ctx, `SELECT registration_id,active,last_seen,health FROM sensors WHERE tenant_id=$1 AND id=$2 FOR SHARE`, tenant, t.Spec.SensorID).Scan(&registration, &active, &seen, &raw); err != nil {
				return err
			}
			if !active || registration != t.Spec.RegistrationID {
				return stopRuleRollout(ctx, tx, tenant, &r, "sensor_identity_changed")
			}
			var h model.HostHealth
			if seen == nil || now.Sub(*seen) > 90*time.Second || seen.After(now.Add(5*time.Second)) || json.Unmarshal(raw, &h) != nil || h.ObservedAt.IsZero() || now.Sub(h.ObservedAt) > 90*time.Second || h.ObservedAt.After(now.Add(5*time.Second)) || t.Run.FinishedAt == nil || seen.Before(*t.Run.FinishedAt) {
				fresh = false
				code = "waiting_for_heartbeat"
				continue
			}
			if !h.RegisteredRulesAvailable || h.RegisteredRulesSHA256 != r.PackageSHA256 {
				return stopRuleRollout(ctx, tx, tenant, &r, "rules_digest_changed")
			}
			var uncertain bool
			if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM sensor_tasks WHERE tenant_id=$1 AND sensor_id=$2 AND kind='rules.apply' AND (state IN('queued','delivered','running') OR (state='unknown' AND rule_resolution IS NULL)))`, tenant, t.Spec.SensorID).Scan(&uncertain); err != nil {
				return err
			}
			if uncertain {
				fresh = false
				code = "waiting_for_rule_task"
			}
			if r.ObservationStartedAt != nil {
				end := r.ObservationStartedAt.Add(time.Duration(r.Spec.ObservationSeconds) * time.Second)
				if seen.Before(end) || h.ObservedAt.Before(end) {
					code = "observing"
				}
			}
		}
		if !allReady || !fresh {
			_, err = tx.Exec(ctx, `UPDATE rule_rollouts SET code=$3,observation_started_at=NULL WHERE tenant_id=$1 AND id=$2`, tenant, id, code)
			return err
		}
		started := false
		for _, t := range targets {
			started = started || t.Batch == r.CurrentBatch && t.ExecutionRevision > 0
		}
		if !started {
			for _, t := range targets {
				if t.Batch != r.CurrentBatch {
					continue
				}
				plan, err := readRuleSyncPlan(tx.QueryRow(ctx, `SELECT `+ruleSyncPlanJSON+` FROM rule_sync_plans p WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenant, t.PlanID))
				if err != nil {
					return err
				}
				if plan.Revision != t.AuthorizedRevision || plan.Spec != t.Spec || plan.Spec.Enabled {
					return stopRuleRollout(ctx, tx, tenant, &r, "plan_changed")
				}
				if _, err = tx.Exec(ctx, `UPDATE rule_sync_plans SET revision=revision+1,spec=jsonb_set(spec,'{enabled}','true'),enabled=true,next_at=clock_timestamp(),updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2`, tenant, t.PlanID); err != nil {
					return err
				}
				if _, err = tx.Exec(ctx, `UPDATE rule_rollout_targets SET execution_revision=$4,state='active',code='' WHERE tenant_id=$1 AND rollout_id=$2 AND ordinal=$3`, tenant, id, t.Ordinal, t.AuthorizedRevision+1); err != nil {
					return err
				}
			}
			_, err = tx.Exec(ctx, `UPDATE rule_rollouts SET state='running',code='',observation_started_at=NULL WHERE tenant_id=$1 AND id=$2`, tenant, id)
			return err
		}
		if r.ObservationStartedAt == nil {
			_, err = tx.Exec(ctx, `UPDATE rule_rollouts SET state='observing',code='observing',observation_started_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2`, tenant, id)
			return err
		}
		end := r.ObservationStartedAt.Add(time.Duration(r.Spec.ObservationSeconds) * time.Second)
		if now.Before(end) || code == "observing" {
			return nil
		}
		if _, err = tx.Exec(ctx, `UPDATE rule_rollout_targets SET state='succeeded',code='observed' WHERE tenant_id=$1 AND rollout_id=$2 AND batch=$3`, tenant, id, r.CurrentBatch); err != nil {
			return err
		}
		if r.CurrentBatch == r.Spec.Batch(len(r.Spec.Plans)-1) {
			return finishRuleRollout(ctx, tx, tenant, r, "succeeded")
		}
		_, err = tx.Exec(ctx, `UPDATE rule_rollouts SET current_batch=current_batch+1,state='pending',code='',observation_started_at=NULL,next_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2`, tenant, id)
		return err
	})
}
