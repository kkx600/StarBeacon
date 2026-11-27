package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/gatewayblock"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/playbook"
	responseapi "github.com/kkx600/StarBeacon/internal/response"
	"github.com/kkx600/StarBeacon/internal/watchlist"
)

const playbookRunColumns = `r.id,r.playbook_id,r.revision,v.sha256,v.definition,r.alert,r.results,r.created_at
 FROM playbook_runs r JOIN playbook_revisions v ON (v.tenant_id,v.playbook_id,v.revision)=(r.tenant_id,r.playbook_id,r.revision)`
const playbookRunOwner = ` WHERE r.tenant_id=$1 AND r.owner_id=$2 AND r.expires_at>now()`

func readPlaybookRun(row pgx.Row) (playbook.Run, error) {
	var r playbook.Run
	var definition, alert, results []byte
	if err := row.Scan(&r.ID, &r.PlaybookID, &r.Revision.Revision, &r.SHA256, &definition, &alert, &results, &r.CreatedAt); err != nil {
		return r, err
	}
	if json.Unmarshal(definition, &r.Definition) != nil || !r.Definition.ValidDraft() || len(r.Definition.Issues()) != 0 || playbook.Digest(r.Definition) != r.SHA256 ||
		json.Unmarshal(alert, &r.Alert) != nil || json.Unmarshal(results, &r.Results) != nil || len(r.Results) == 0 || len(r.Results) > len(r.Definition.Steps) {
		return r, playbook.ErrSource
	}
	for i, result := range r.Results {
		if result.Kind != r.Definition.Steps[i].Kind || result.At.Before(r.CreatedAt) {
			return r, playbook.ErrSource
		}
	}
	r.RefreshState()
	return r, nil
}

func (p *Postgres) PlaybookRuns(ctx context.Context, u model.Principal, cursor string, limit int) (playbook.Page[playbook.Run], error) {
	out := playbook.Page[playbook.Run]{Items: []playbook.Run{}}
	if !playbookPageValid(cursor, limit) {
		return out, playbook.ErrInput
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := playbookActor(ctx, tx, u); err != nil {
			return err
		}
		var before *time.Time
		if cursor != "" {
			if err := tx.QueryRow(ctx, `SELECT created_at FROM playbook_runs WHERE tenant_id=$1 AND owner_id=$2 AND id=$3 AND expires_at>now()`,
				u.TenantID, u.ID, cursor).Scan(&before); err != nil {
				return err
			}
		}
		rows, err := tx.Query(ctx, `SELECT `+playbookRunColumns+playbookRunOwner+`
			AND ($3::timestamptz IS NULL OR (r.created_at,r.id)<($3,$4)) ORDER BY r.created_at DESC,r.id DESC LIMIT $5`,
			u.TenantID, u.ID, before, cursor, limit+1)
		if err != nil {
			return err
		}
		out.Items, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (playbook.Run, error) { return readPlaybookRun(row) })
		return err
	})
	if len(out.Items) > limit {
		out.Items = out.Items[:limit]
		out.NextCursor = out.Items[limit-1].ID
	}
	return out, err
}

func (p *Postgres) PlaybookRun(ctx context.Context, u model.Principal, id string) (playbook.Run, error) {
	var out playbook.Run
	if !contract.ValidID(id) {
		return out, playbook.ErrInput
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := playbookActor(ctx, tx, u); err != nil {
			return err
		}
		var err error
		out, err = readPlaybookRun(tx.QueryRow(ctx, `SELECT `+playbookRunColumns+playbookRunOwner+` AND r.id=$3`, u.TenantID, u.ID, id))
		return err
	})
	return out, err
}

func (p *Postgres) StartPlaybookRun(ctx context.Context, u model.Principal, id, key string, input playbook.Start, event model.Alert) (playbook.Run, error) {
	var out playbook.Run
	if !contract.ValidID(id) || !contract.ValidID(key) || len(key) < 8 || !input.Valid() || event.TenantID != u.TenantID ||
		input.EventID != event.EventID || input.RawSHA256 != event.RawSHA256 {
		return out, playbook.ErrInput
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := playbookActor(ctx, tx, u); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, u.TenantID+"/playbook-runs"); err != nil {
			return err
		}
		prior, err := readPlaybookRun(tx.QueryRow(ctx, `SELECT `+playbookRunColumns+playbookRunOwner+` AND r.key_hash=$3`, u.TenantID, u.ID, Hash(key)))
		if err == nil {
			if prior.PlaybookID != id || prior.Revision != input.Revision || prior.Alert.EventID != input.EventID || prior.Alert.RawSHA256 != input.RawSHA256 {
				return ErrConflict
			}
			out = prior
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		var raw []byte
		err = tx.QueryRow(ctx, `SELECT v.definition FROM playbooks h JOIN playbook_revisions v ON (v.tenant_id,v.playbook_id,v.revision)=(h.tenant_id,h.id,h.published_revision)
			WHERE h.tenant_id=$1 AND h.id=$2 AND v.revision=$3 AND v.sha256=$4 FOR SHARE OF h`, u.TenantID, id, input.Revision.Revision, input.SHA256).Scan(&raw)
		if err != nil {
			return err
		}
		if json.Unmarshal(raw, &out.Definition) != nil || !out.Definition.ValidDraft() || playbook.Digest(out.Definition) != input.SHA256 {
			return playbook.ErrSource
		}
		issues, err := playbookIssues(ctx, tx, u.TenantID, out.Definition)
		if err != nil {
			return err
		}
		if len(issues) > 0 {
			return playbook.ErrSource
		}
		out.Alert, err = playbook.BindAlert(out.Definition, event)
		if err != nil {
			return err
		}
		var count int
		if err = tx.QueryRow(ctx, `SELECT count(*) FROM playbook_runs WHERE tenant_id=$1 AND created_at>now()-interval '24 hours'`, u.TenantID).Scan(&count); err != nil {
			return err
		}
		if count >= 200 {
			return playbook.ErrLimit
		}
		out.ID, out.PlaybookID, out.Revision = RandomID("pbr_"), id, input.Revision
		out.CreatedAt = time.Now().UTC().Truncate(time.Microsecond)
		out.Results = []playbook.Result{{Kind: "trigger", At: out.CreatedAt, Reference: input.EventID, Outcome: "alert_verified"}}
		out.RefreshState()
		alert, _ := json.Marshal(out.Alert)
		results, _ := json.Marshal(out.Results)
		if _, err = tx.Exec(ctx, `INSERT INTO playbook_runs(tenant_id,id,owner_id,playbook_id,revision,key_hash,alert,results,created_at,expires_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$9::timestamptz+make_interval(days=>COALESCE((SELECT days FROM retention_policies WHERE tenant_id=$1 AND category='operations'),180)))`,
			u.TenantID, out.ID, u.ID, id, input.Revision.Revision, Hash(key), alert, results, out.CreatedAt); err != nil {
			return err
		}
		return insertOperationAudit(ctx, tx, u, "playbook.run.start", out.ID, model.RequestMetadataFrom(ctx).RequestID)
	})
	return out, err
}

func (p *Postgres) AcknowledgePlaybookStep(ctx context.Context, u model.Principal, id string, input playbook.Acknowledge) (playbook.Run, error) {
	var out playbook.Run
	if !contract.ValidID(id) || !input.Confirmed || input.Step < 1 || input.Step >= playbook.MaxSteps {
		return out, playbook.ErrInput
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := playbookActor(ctx, tx, u); err != nil {
			return err
		}
		var err error
		out, err = readPlaybookRun(tx.QueryRow(ctx, `SELECT `+playbookRunColumns+playbookRunOwner+` AND r.id=$3 FOR UPDATE OF r`, u.TenantID, u.ID, id))
		if err != nil {
			return err
		}
		if input.Step < len(out.Results) {
			return nil
		}
		step, ok := out.Current()
		if !ok || input.Step != len(out.Results) {
			return ErrConflict
		}
		result, err := playbookStepResult(ctx, tx, u, out, step)
		if errors.Is(err, pgx.ErrNoRows) {
			return playbook.ErrNotReady
		}
		if err != nil {
			return err
		}
		out.Results = append(out.Results, result)
		out.RefreshState()
		raw, _ := json.Marshal(out.Results)
		if _, err = tx.Exec(ctx, `UPDATE playbook_runs SET results=$4 WHERE tenant_id=$1 AND owner_id=$2 AND id=$3`, u.TenantID, u.ID, id, raw); err != nil {
			return err
		}
		return insertOperationAudit(ctx, tx, u, "playbook.step."+step.Kind, id, model.RequestMetadataFrom(ctx).RequestID)
	})
	return out, err
}

func playbookStepResult(ctx context.Context, tx pgx.Tx, u model.Principal, r playbook.Run, step playbook.Step) (playbook.Result, error) {
	out := playbook.Result{Kind: step.Kind, At: time.Now().UTC().Truncate(time.Microsecond)}
	last := r.Results[len(r.Results)-1]
	switch step.Kind {
	case "triage":
		job, err := scanTriage(tx.QueryRow(ctx, `SELECT `+triageJSON+` FROM alert_triage_jobs WHERE tenant_id=$1 AND created_by=$2 AND idempotency_key_hash=$3 AND expires_at>now()`, u.TenantID, u.ID, Hash(r.StepKey)))
		if err != nil {
			return out, err
		}
		if job.State == "queued" || job.State == "running" {
			return out, playbook.ErrNotReady
		}
		out.Reference, out.Outcome = job.ID, "triage_observed"
		switch {
		case job.State != "succeeded" || job.Result.State != "succeeded" || job.Answer == nil || job.CancelRequested:
			out.Outcome = "triage_failed"
		case job.Answer.Confidence < step.Model.MinimumConfidence:
			out.Outcome = "below_threshold"
		case job.Answer.Verdict == "confirmed":
			out.Outcome = "triage_confirmed"
		}
	case "condition":
		out.Outcome = "condition_unmet"
		if triageResult(r).Outcome == "triage_confirmed" {
			out.Outcome = "condition_met"
		}
	case "protection":
		proof, err := playbookProtection(ctx, tx, u.TenantID, r, r.Definition.Steps[len(r.Results)+2], out.At)
		if errors.Is(err, watchlist.ErrProtected) {
			out.Outcome = "protected"
			return out, nil
		}
		out.Reference, out.Outcome = proof, "protection_checked"
		return out, err
	case "approval":
		out.Reference, out.Outcome = u.ID, "approved"
	case "plugin":
		receipt, err := readDecisionResponse(tx.QueryRow(ctx, `SELECT `+decisionResponseColumns+` FROM decision_responses v
			WHERE v.tenant_id=$1 AND v.created_by=$2 AND v.key_hash=$3 AND v.expires_at>now()`, u.TenantID, u.ID, Hash(r.StepKey)))
		if err != nil {
			return out, err
		}
		out.Reference, out.TaskID, out.Outcome = receipt.ID, receipt.TaskID, "authorized"
	case "gateway":
		item, err := scanGatewayRequest(tx.QueryRow(ctx, `SELECT `+gatewayRequestColumns+` FROM gateway_block_requests
			WHERE tenant_id=$1 AND actor_id=$2 AND client_key_hash=$3 AND expires_at>now()`, u.TenantID, u.ID, Hash(r.StepKey)))
		if err != nil {
			return out, err
		}
		out.Reference, out.TaskID, out.Outcome = item.ID, item.TaskID, "requested"
		if gatewayRequestResult(item).State == "denied" {
			out.Outcome = "authorization_denied"
		}
	case "verify":
		return verifyPlaybookAction(ctx, tx, u, out, last)
	case "compensate":
		out.Reference, out.TaskID, out.LeaseUntil, out.Outcome = last.Reference, last.TaskID, last.LeaseUntil, "expiry_recorded"
	case "notify":
		out.Reference, out.Outcome = u.ID, "operator_notified"
	default:
		return out, playbook.ErrInput
	}
	return out, nil
}

func triageResult(r playbook.Run) playbook.Result {
	for _, step := range r.Results {
		if step.Kind == "triage" {
			return step
		}
	}
	return playbook.Result{}
}

func playbookProtection(ctx context.Context, tx pgx.Tx, tenant string, r playbook.Run, action playbook.Step, now time.Time) (string, error) {
	source, destination, err := r.Alert.Endpoints()
	if err != nil {
		return "", err
	}
	scopes := [][2]string{{r.Alert.SensorID, r.Alert.RegistrationID}}
	if b := action.Plugin; b != nil && (b.SensorID != r.Alert.SensorID || b.RegistrationID != r.Alert.RegistrationID) {
		scopes = append(scopes, [2]string{b.SensorID, b.RegistrationID})
	}
	proofs := make([]string, 0, 2*len(scopes))
	for _, pair := range scopes {
		for _, ip := range []string{source, destination} {
			check, err := CheckWatchlistResponseTx(ctx, tx, tenant, pair[0], pair[1], ip, now)
			if err != nil {
				return "", err
			}
			proofs = append(proofs, check.StateSHA256)
		}
	}
	return playbook.Digest(proofs), nil
}

func verifyPlaybookAction(ctx context.Context, tx pgx.Tx, u model.Principal, out, last playbook.Result) (playbook.Result, error) {
	out.Reference, out.TaskID = last.Reference, last.TaskID
	if last.Kind == "gateway" {
		r, err := scanGatewayRequest(tx.QueryRow(ctx, `SELECT `+gatewayRequestColumns+` FROM gateway_block_requests
			WHERE tenant_id=$1 AND actor_id=$2 AND id=$3 AND expires_at>now()`, u.TenantID, u.ID, last.Reference))
		if err != nil {
			return out, err
		}
		out.TaskID, out.LeaseUntil = r.TaskID, r.LeaseUntil
		if gatewayRequestResult(r).State == "denied" {
			out.Outcome = "authorization_denied"
			return out, nil
		}
		if pendingPlaybookReceipt(r.TaskState) {
			return out, playbook.ErrNotReady
		}
		if r.TaskState != "succeeded" || r.GatewayResult == nil {
			out.Outcome = "receipt_unknown"
			return out, nil
		}
		out.LeaseUntil = &r.GatewayResult.LeaseUntil
		out.Outcome = "gateway_readback"
		if obs := r.GatewayResult.Observation; obs != nil {
			switch obs.State {
			case gatewayblock.FlowPaused:
				out.Outcome = "gateway_flow_paused"
			case gatewayblock.FlowContinued:
				out.Outcome = "gateway_traffic_continued"
			default:
				out.Outcome = "gateway_effect_unknown"
			}
		}
		return out, nil
	}
	var state string
	var commandRaw, result []byte
	var finish *time.Time
	err := tx.QueryRow(ctx, `SELECT state,command,receipt->'result',(receipt->>'finished_at')::timestamptz FROM sensor_tasks
		WHERE tenant_id=$1 AND created_by=$2 AND id=$3 AND kind='response.block' AND retain_until>now()`, u.TenantID, u.ID, last.TaskID).Scan(&state, &commandRaw, &result, &finish)
	if err != nil {
		return out, err
	}
	if pendingPlaybookReceipt(state) {
		return out, playbook.ErrNotReady
	}
	out.Outcome = "receipt_unknown"
	if state != "succeeded" || finish == nil {
		return out, nil
	}
	var command control.Command
	if json.Unmarshal(commandRaw, &command) != nil || command.ID != last.TaskID {
		return out, playbook.ErrSource
	}
	action, err := responseapi.ReadAction(command.Payload)
	if err != nil {
		return out, playbook.ErrSource
	}
	reply, err := responseapi.ReadResult(result, action, "response.block", *finish)
	if err != nil {
		return out, playbook.ErrSource
	}
	out.LeaseUntil, out.Outcome = &reply.Observation.ExpiresAt, "plugin_readback"
	return out, nil
}

func pendingPlaybookReceipt(state string) bool {
	return state == "" || state == "queued" || state == "delivered" || state == "running"
}
