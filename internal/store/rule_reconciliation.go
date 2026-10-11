package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/rulerelease"
	"github.com/kkx600/StarBeacon/internal/transport"
)

func reconcileRuleTask(ctx context.Context, tx pgx.Tx, tenant, sensor, registration string, payload json.RawMessage, signer ed25519.PrivateKey) (json.RawMessage, error) {
	var input control.RuleReconcile
	d := json.NewDecoder(bytes.NewReader(payload))
	d.DisallowUnknownFields()
	if d.Decode(&input) != nil || d.Decode(new(any)) != io.EOF || len(signer) != ed25519.PrivateKeySize {
		return nil, rulerelease.ErrReconciliation
	}
	var raw, signature []byte
	var commandHash, current string
	if err := tx.QueryRow(ctx, `SELECT command,signature,command_sha256 FROM sensor_tasks WHERE tenant_id=$1 AND id=$2 AND sensor_id=$3 AND registration_id=$4 AND kind='rules.apply' AND state='unknown' AND rule_resolution IS NULL FOR SHARE`, tenant, input.UnknownTaskID, sensor, registration).Scan(&raw, &signature, &commandHash); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrConflict
		}
		return nil, err
	}
	var preliminary control.Command
	if control.Digest(raw) != commandHash || json.Unmarshal(raw, &preliminary) != nil {
		return nil, rulerelease.ErrReconciliation
	}
	command, err := control.Decode(raw, signature, signer.Public().(ed25519.PublicKey), tenant, sensor, registration, preliminary.IssuedAt.Add(time.Nanosecond))
	if err != nil || command.ID != input.UnknownTaskID || command.Kind != "rules.apply" {
		return nil, rulerelease.ErrReconciliation
	}
	var p control.RulePackage
	if json.Unmarshal(command.Payload, &p) != nil || p.Authorization.Validate() != nil {
		return nil, rulerelease.ErrReconciliation
	}
	if err = tx.QueryRow(ctx, `SELECT COALESCE(health->>'registered_rules_sha256','') FROM sensors WHERE tenant_id=$1 AND id=$2 AND registration_id=$3 AND active AND last_seen>now()-interval '90 seconds'`, tenant, sensor, registration).Scan(&current); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, rulerelease.ErrReconciliation
		}
		return nil, err
	}
	if current == "" || current != input.ExpectedSHA256 {
		return nil, rulerelease.ErrReconciliation
	}
	value := control.RuleReconcile{UnknownTaskID: command.ID, UnknownCommandSHA256: commandHash, ExpectedSHA256: current, TargetSHA256: p.SHA256, PreviousSHA256: p.Authorization.ExpectedRulesSHA256, ConfigSHA256: p.Authorization.ConfigSHA256, ProfileSHA256: p.Authorization.ProfileSHA256}
	if value.Validate() != nil {
		return nil, rulerelease.ErrReconciliation
	}
	return json.Marshal(value)
}

// 原中断回执保持不变。核实证据、解除写入阻塞和审计必须一起提交。
func saveRuleResolution(ctx context.Context, tx pgx.Tx, id transport.SensorIdentity, taskID, createdBy string, commandRaw []byte, receipt control.Receipt) error {
	var command control.Command
	var p control.RuleReconcile
	var result control.RuleReconcileResult
	if receipt.Code != "" || json.Unmarshal(commandRaw, &command) != nil || command.ID != taskID || command.Kind != "rules.reconcile" || json.Unmarshal(command.Payload, &p) != nil || p.Validate() != nil || json.Unmarshal(receipt.Result, &result) != nil {
		return ErrConflict
	}
	if result.Validate(p) != nil {
		return ErrConflict
	}
	resolution, err := json.Marshal(struct {
		TaskID      string                      `json:"task_id"`
		ConfirmedAt time.Time                   `json:"confirmed_at"`
		Result      control.RuleReconcileResult `json:"result"`
	}{TaskID: taskID, ConfirmedAt: time.Now().UTC(), Result: result})
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE sensor_tasks SET rule_resolution=$6,updated_at=now() WHERE tenant_id=$1 AND id=$2 AND sensor_id=$3 AND registration_id=$4 AND command_sha256=$5 AND kind='rules.apply' AND state='unknown' AND rule_resolution IS NULL`, id.TenantID, p.UnknownTaskID, id.SensorID, id.RegistrationID, p.UnknownCommandSHA256, resolution)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrConflict
	}
	return insertOperationAudit(ctx, tx, model.Principal{TenantID: id.TenantID, ID: createdBy}, "sensor.rules.reconcile", p.UnknownTaskID, taskID)
}
