package store

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/model"
	responseapi "github.com/kkx600/StarBeacon/internal/response"
	"github.com/kkx600/StarBeacon/internal/transport"
)

func readPluginDeployments(ctx context.Context, tx pgx.Tx, tenant string, ids []string) ([]responseapi.PluginDeployment, error) {
	rows, err := tx.Query(ctx, `SELECT p.plugin_id,p.sensor_id,s.name,p.generation,
		COALESCE((p.current_artifact->'version'->>'version')::int,0),COALESCE((p.previous_artifact->'version'->>'version')::int,0),p.updated_at,
		COALESCE((s.health->'errors') ? ('plugin_' || p.plugin_id || '_unavailable'),false)
		FROM response_plugin_assignments p JOIN sensors s
		 ON s.tenant_id=p.tenant_id AND s.id=p.sensor_id AND s.registration_id=p.registration_id
		WHERE p.tenant_id=$1 AND p.plugin_id=ANY($2) AND s.active
		ORDER BY p.plugin_id,p.sensor_id LIMIT 512`, tenant, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []responseapi.PluginDeployment
	for rows.Next() {
		var v responseapi.PluginDeployment
		if err = rows.Scan(&v.PluginID, &v.SensorID, &v.SensorName, &v.Generation, &v.Version, &v.PreviousVersion, &v.UpdatedAt, &v.Unavailable); err != nil {
			return nil, err
		}
		items = append(items, v)
	}
	return items, rows.Err()
}

func readPluginExecutions(ctx context.Context, tx pgx.Tx, tenant string, ids []string) ([]responseapi.PluginExecution, error) {
	rows, err := tx.Query(ctx, `SELECT j.plugin_id,max(t.updated_at)
		FROM response_plugin_jobs j JOIN sensor_tasks t ON (t.tenant_id,t.id)=(j.tenant_id,j.task_id)
		WHERE j.tenant_id=$1 AND j.plugin_id=ANY($2)
		GROUP BY j.plugin_id ORDER BY j.plugin_id`, tenant, ids)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[responseapi.PluginExecution])
}

func pluginAssignment(ctx context.Context, tx pgx.Tx, sensor transport.SensorIdentity, plugin string) (responseapi.PluginAssignment, time.Time, error) {
	var out responseapi.PluginAssignment
	var at time.Time
	var current, previous []byte
	err := tx.QueryRow(ctx, `SELECT generation,current_artifact,previous_artifact,updated_at
			FROM response_plugin_assignments WHERE tenant_id=$1 AND sensor_id=$2 AND registration_id=$3 AND plugin_id=$4`,
		sensor.TenantID, sensor.SensorID, sensor.RegistrationID, plugin).Scan(&out.Generation, &current, &previous, &at)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, at, nil
	}
	if err != nil {
		return out, at, err
	}
	for _, item := range []struct {
		raw []byte
		ref **responseapi.PluginArtifact
	}{{current, &out.Current}, {previous, &out.Previous}} {
		if len(item.raw) == 0 {
			continue
		}
		if json.Unmarshal(item.raw, item.ref) != nil || *item.ref == nil || (*item.ref).Validate() != nil ||
			(*item.ref).Version.ID != plugin {
			return out, at, errors.New("联动插件已下发档案无效")
		}
	}
	return out, at, nil
}

func selectPluginBinding(h model.HostHealth, plugin string) *responseapi.PluginBinding {
	if len(h.PluginBindings) > 8 {
		return nil
	}
	var found *responseapi.PluginBinding
	for _, binding := range h.PluginBindings {
		if binding.PluginID == plugin {
			if found != nil || binding.Validate() != nil {
				return nil
			}
			found = &binding
		}
	}
	return found
}

func (p *Postgres) ListPluginOperations(ctx context.Context, u model.Principal, plugin, sensor string) (responseapi.PluginOperations, error) {
	var out responseapi.PluginOperations
	if !contract.ValidID(plugin) || !contract.ValidID(sensor) {
		return out, responseapi.ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := configurationActor(ctx, tx, u, true, responseapi.ErrPermission); err != nil {
			return err
		}
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM response_plugin_versions WHERE tenant_id=$1 AND plugin_id=$2)`, u.TenantID, plugin).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return pgx.ErrNoRows
		}
		id := transport.SensorIdentity{TenantID: u.TenantID, SensorID: sensor}
		out.Deployment.PluginID, out.Deployment.SensorID = plugin, sensor
		var health []byte
		if err := tx.QueryRow(ctx, `SELECT registration_id,name,health FROM sensors WHERE tenant_id=$1 AND id=$2`,
			u.TenantID, sensor).Scan(&id.RegistrationID, &out.Deployment.SensorName, &health); err != nil {
			return err
		}
		var h model.HostHealth
		if json.Unmarshal(health, &h) == nil {
			out.Binding = selectPluginBinding(h, plugin)
			out.Deployment.Unavailable = slices.Contains(h.Errors, "plugin_"+plugin+"_unavailable")
		}
		assignment, at, err := pluginAssignment(ctx, tx, id, plugin)
		if err != nil {
			return err
		}
		out.Deployment.Generation, out.Deployment.UpdatedAt = assignment.Generation, at
		if assignment.Current != nil {
			out.Deployment.Version = assignment.Current.Version.Version
		}
		if assignment.Previous != nil {
			out.Deployment.PreviousVersion = assignment.Previous.Version.Version
		}
		out.Operations = []responseapi.PluginOperationResult{}
		rows, err := tx.Query(ctx, `SELECT j.task_id,j.operation,j.version,t.state,t.updated_at,t.receipt
			FROM response_plugin_jobs j JOIN sensor_tasks t ON (t.tenant_id,t.id)=(j.tenant_id,j.task_id)
			WHERE j.tenant_id=$1 AND j.sensor_id=$2 AND j.registration_id=$3 AND j.plugin_id=$4
			ORDER BY t.created_at DESC,t.id DESC LIMIT 24`, id.TenantID, id.SensorID, id.RegistrationID, plugin)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var item responseapi.PluginOperationResult
			var raw []byte
			if err = rows.Scan(&item.TaskID, &item.Action, &item.Version, &item.State, &item.UpdatedAt, &raw); err != nil {
				return err
			}
			if len(raw) > 0 {
				var receipt control.Receipt
				if json.Unmarshal(raw, &receipt) != nil {
					return errors.New("联动试运行回执损坏")
				}
				item.Code = receipt.Code
				if responseapi.StageIndex(item.Action) >= 0 && slices.Contains([]string{"succeeded", "failed", "unknown"}, item.State) {
					var report responseapi.PluginTrialResult
					if json.Unmarshal(receipt.Result, &report) == nil && report.PluginID == plugin && report.Version == item.Version && report.Stage == item.Action {
						item.Trial = &report
					}
				}
			}
			out.Operations = append(out.Operations, item)
		}
		return rows.Err()
	})
	return out, err
}

func (p *Postgres) SubmitPluginOperation(ctx context.Context, u model.Principal, plugin, key string, op responseapi.PluginOperation, signer ed25519.PrivateKey) (string, error) {
	if !contract.ValidID(plugin) || len(key) < 8 || !contract.ValidID(key) || op.Validate() != nil {
		return "", responseapi.ErrInput
	}
	if len(signer) != ed25519.PrivateKeySize {
		return "", responseapi.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	raw, _ := json.Marshal(op)
	fingerprint := control.Digest(append([]byte(u.ID+"\x00"+plugin+"\x00"), raw...))
	var task string
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := configurationActor(ctx, tx, u, true, responseapi.ErrPermission); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, u.TenantID+"/plugin-jobs"); err != nil {
			return err
		}
		var oldSHA string
		err := tx.QueryRow(ctx, `SELECT t.id,COALESCE(j.request_sha256,'') FROM sensor_tasks t
			LEFT JOIN response_plugin_jobs j ON (t.tenant_id,t.id)=(j.tenant_id,j.task_id)
			WHERE t.tenant_id=$1 AND t.idempotency_key=$2`, u.TenantID, key).Scan(&task, &oldSHA)
		if err == nil {
			if oldSHA != fingerprint {
				return ErrConflict
			}
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		var recent int
		if err = tx.QueryRow(ctx, `SELECT count(*) FROM sensor_tasks WHERE tenant_id=$1 AND kind IN ('plugin.trial','plugin.apply')
			 AND created_at>now()-interval '24 hours'`, u.TenantID).Scan(&recent); err != nil {
			return err
		}
		if recent >= 512 {
			return responseapi.ErrPluginQuota
		}
		id := transport.SensorIdentity{TenantID: u.TenantID, SensorID: op.SensorID}
		var health []byte
		var seen *time.Time
		if err = tx.QueryRow(ctx, `SELECT registration_id,health,last_seen FROM sensors WHERE tenant_id=$1 AND id=$2 AND active FOR UPDATE`,
			id.TenantID, id.SensorID).Scan(&id.RegistrationID, &health, &seen); err != nil {
			return err
		}
		var h model.HostHealth
		now := time.Now()
		stage := responseapi.StageIndex(op.Action)
		kind := responseapi.PluginApplyCommand
		if stage >= 0 {
			kind = responseapi.PluginTrialCommand
		}
		pub := signer.Public().(ed25519.PublicKey)
		if seen == nil || now.Sub(*seen) > 35*time.Second || seen.After(now.Add(30*time.Second)) ||
			json.Unmarshal(health, &h) != nil || now.Sub(h.ObservedAt) > 35*time.Second || h.ObservedAt.After(now.Add(30*time.Second)) ||
			h.CommandSignerSHA256 != control.Digest(pub) || !slices.Contains(h.TaskCapabilities, kind) {
			return responseapi.ErrUnavailable
		}
		binding := selectPluginBinding(h, plugin)
		if binding == nil {
			return responseapi.ErrUnavailable
		}
		version, err := responsePluginVersion(ctx, tx, u.TenantID, plugin, op.Version)
		if err != nil {
			return err
		}
		assignment, _, err := pluginAssignment(ctx, tx, id, plugin)
		if err != nil {
			return err
		}
		if assignment.Generation != op.ExpectedGeneration {
			return ErrConflict
		}
		payload, err := qualifyPluginOperation(ctx, tx, id, op, version, *binding, assignment, signer)
		if err != nil {
			return err
		}
		task, err = createTaskTx(ctx, tx, u, id.SensorID, kind, key, payload, signer, true)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO response_plugin_jobs (tenant_id,task_id,plugin_id,version,sensor_id,registration_id,operation,binding_sha256,request_sha256)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, id.TenantID, task, plugin, op.Version, id.SensorID, id.RegistrationID, op.Action, binding.BindingSHA256, fingerprint)
		return err
	})
	return task, err
}

func qualifyPluginOperation(ctx context.Context, tx pgx.Tx, id transport.SensorIdentity, op responseapi.PluginOperation, v responseapi.PluginVersion, binding responseapi.PluginBinding, old responseapi.PluginAssignment, signer ed25519.PrivateKey) ([]byte, error) {
	stage := responseapi.StageIndex(op.Action)
	limit := stage
	if op.Action == responseapi.PluginPublish {
		limit = len(responseapi.PluginStages)
	}
	var hashes [3]string
	if limit > 0 {
		var err error
		hashes, err = pluginTrialEvidence(ctx, tx, id, v, binding, limit, signer.Public().(ed25519.PublicKey))
		if err != nil {
			return nil, err
		}
	}
	if stage >= 0 {
		trial := responseapi.PluginTrial{Version: v, Binding: binding, Stage: op.Action}
		if len(trial.Checks()) == 0 || op.Action == responseapi.PluginSimulate && len(v.Examples) == 0 {
			return nil, responseapi.ErrInput
		}
		return json.Marshal(trial)
	}
	a := responseapi.PluginActivation{PluginID: v.ID, Action: op.Action, ExpectedGeneration: op.ExpectedGeneration}
	switch op.Action {
	case responseapi.PluginPublish:
		grant := responseapi.PluginGrant{TenantID: id.TenantID, SensorID: id.SensorID, RegistrationID: id.RegistrationID,
			Version: v.Version, Binding: binding, DefinitionSHA256: v.DefinitionSHA256(), TrialSHA256: hashes}
		signed, err := responseapi.SignPlugin(grant, signer)
		if err != nil {
			return nil, err
		}
		a.Artifact = &responseapi.PluginArtifact{Version: v, Release: signed}
	case responseapi.PluginRollback:
		if old.Previous == nil || old.Previous.Version.Version != v.Version || old.Previous.Release.Grant.Binding != binding ||
			old.Previous.Release.Verify(signer.Public().(ed25519.PublicKey), id.TenantID, id.SensorID, id.RegistrationID) != nil {
			return nil, ErrConflict
		}
		a.Artifact = old.Previous
	case responseapi.PluginDisable:
		if old.Current == nil || old.Current.Version.Version != v.Version {
			return nil, ErrConflict
		}
	}
	if _, err := a.Apply(old); err != nil {
		return nil, ErrConflict
	}
	return json.Marshal(a)
}

func pluginTrialEvidence(ctx context.Context, tx pgx.Tx, id transport.SensorIdentity, version responseapi.PluginVersion, binding responseapi.PluginBinding, count int, pub ed25519.PublicKey) ([3]string, error) {
	var out [3]string
	var lastFinished time.Time
	for i, stage := range responseapi.PluginStages[:count] {
		var created time.Time
		var state string
		var bytes, signature, receipt []byte
		err := tx.QueryRow(ctx, `SELECT t.command,t.signature,t.receipt,t.state,t.created_at
			FROM response_plugin_jobs j JOIN sensor_tasks t ON (t.tenant_id,t.id)=(j.tenant_id,j.task_id)
			WHERE j.tenant_id=$1 AND j.sensor_id=$2 AND j.registration_id=$3 AND j.plugin_id=$4 AND j.version=$5 AND j.operation=$6 AND j.binding_sha256=$7
			 AND t.created_at>now()-interval '24 hours'
			ORDER BY t.created_at DESC,t.id DESC LIMIT 1`, id.TenantID, id.SensorID, id.RegistrationID,
			version.ID, version.Version, stage, binding.BindingSHA256).Scan(&bytes, &signature, &receipt, &state, &created)
		if errors.Is(err, pgx.ErrNoRows) {
			return out, ErrConflict
		}
		if err != nil {
			return out, err
		}
		command, err := control.Decode(bytes, signature, pub, id.TenantID, id.SensorID, id.RegistrationID, created)
		if state != "succeeded" || err != nil || command.Kind != responseapi.PluginTrialCommand || command.IssuedAt.Before(lastFinished) {
			return out, ErrConflict
		}
		trial, err := responseapi.ReadPluginTrial(command.Payload)
		var r control.Receipt
		if err != nil || trial.Binding != binding || trial.Stage != stage || trial.Version.DefinitionSHA256() != version.DefinitionSHA256() ||
			json.Unmarshal(receipt, &r) != nil || r.CommandID != command.ID || r.CommandSHA256 != control.Digest(bytes) ||
			r.State != "succeeded" || r.Code != "" || r.FinishedAt == nil || r.StartedAt.Before(command.IssuedAt.Add(-30*time.Second)) ||
			r.StartedAt.After(command.ExpiresAt) || r.FinishedAt.Before(r.StartedAt) || r.FinishedAt.After(time.Now().Add(30*time.Second)) {
			return out, ErrConflict
		}
		proof, err := responseapi.ReadPluginTrialResult(r.Result, trial)
		if err != nil {
			return out, ErrConflict
		}
		out[i] = proof.SHA256()
		lastFinished = *r.FinishedAt
	}
	return out, nil
}

func savePluginReceipt(ctx context.Context, tx pgx.Tx, id transport.SensorIdentity, kind string, command []byte, r control.Receipt) error {
	var c control.Command
	if r.Code != "" || json.Unmarshal(command, &c) != nil || c.ID != r.CommandID || c.Kind != kind ||
		c.TenantID != id.TenantID || c.SensorID != id.SensorID || c.RegistrationID != id.RegistrationID || control.Validate(c) != nil {
		return responseapi.ErrInput
	}
	var plugin, stage, binding string
	var version int
	if err := tx.QueryRow(ctx, `SELECT plugin_id,operation,version,binding_sha256 FROM response_plugin_jobs
		WHERE tenant_id=$1 AND task_id=$2 AND sensor_id=$3 AND registration_id=$4`,
		id.TenantID, c.ID, id.SensorID, id.RegistrationID).Scan(&plugin, &stage, &version, &binding); err != nil {
		return err
	}
	if kind == responseapi.PluginTrialCommand {
		t, err := responseapi.ReadPluginTrial(c.Payload)
		if err != nil || t.Version.ID != plugin || t.Version.Version != version || t.Stage != stage || t.Binding.BindingSHA256 != binding {
			return responseapi.ErrInput
		}
		_, err = responseapi.ReadPluginTrialResult(r.Result, t)
		return err
	}
	a, err := responseapi.ReadPluginActivation(c.Payload)
	if err != nil || a.PluginID != plugin || a.Action != stage || responseapi.ReadPluginActivationResult(r.Result, a) != nil ||
		a.Artifact != nil && (a.Artifact.Version.Version != version || a.Artifact.Release.Grant.Binding.BindingSHA256 != binding) {
		return responseapi.ErrInput
	}
	old, _, err := pluginAssignment(ctx, tx, id, plugin)
	if err != nil {
		return err
	}
	next, err := a.Apply(old)
	if err != nil {
		return ErrConflict
	}
	var current, previous []byte
	if next.Current != nil {
		current, _ = json.Marshal(next.Current)
	}
	if next.Previous != nil {
		previous, _ = json.Marshal(next.Previous)
	}
	changed, err := tx.Exec(ctx, `INSERT INTO response_plugin_assignments AS p
		(tenant_id,plugin_id,sensor_id,registration_id,generation,current_artifact,previous_artifact) VALUES($1,$2,$3,$4,$5,$6,$7)
		ON CONFLICT(tenant_id,plugin_id,sensor_id,registration_id) DO UPDATE
		SET generation=EXCLUDED.generation,current_artifact=EXCLUDED.current_artifact,previous_artifact=EXCLUDED.previous_artifact,updated_at=now()
		WHERE p.generation=$8`, id.TenantID, plugin, id.SensorID, id.RegistrationID, next.Generation, current, previous, old.Generation)
	if err == nil && changed.RowsAffected() != 1 {
		return ErrConflict
	}
	return err
}
