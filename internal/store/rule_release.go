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
	"github.com/kkx600/StarBeacon/internal/rulerelease"
)

// 与目标探针锁及任务审计处于同一事务，不能通过绕过 HTTP 检查取得发布资格。
func qualifyRuleTask(ctx context.Context, tx pgx.Tx, tenant, sensor, registration string, payload json.RawMessage, signer ed25519.PrivateKey) (json.RawMessage, error) {
	var p control.RulePackage
	d := json.NewDecoder(bytes.NewReader(payload))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil || d.Decode(new(any)) != io.EOF || p.Authorization == nil {
		return nil, rulerelease.ErrQualification
	}
	var expected string
	if err := tx.QueryRow(ctx, `SELECT COALESCE(health->>'registered_rules_sha256','') FROM sensors WHERE tenant_id=$1 AND id=$2 AND registration_id=$3 AND active AND last_seen>now()-interval '90 seconds'`, tenant, sensor, registration).Scan(&expected); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, rulerelease.ErrQualification
		}
		return nil, err
	}
	if expected == "" || expected != p.Authorization.ExpectedRulesSHA256 {
		return nil, rulerelease.ErrQualification
	}
	var text, hash, version string
	// 规则修订不可变且在线角色没有 UPDATE 权限，不为只读快照扩大表权限。
	if err := tx.QueryRow(ctx, `SELECT rules_text,sha256,engine_version FROM rule_packages WHERE tenant_id=$1 AND id=$2 AND revision=$3`, tenant, p.PackageID, p.Revision).Scan(&text, &hash, &version); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, rulerelease.ErrQualification
		}
		return nil, err
	}
	if text != p.Text || hash != p.SHA256 || version != p.EngineVersion {
		return nil, rulerelease.ErrQualification
	}
	ids := [3]string{p.Authorization.ValidationTaskID, p.Authorization.PositiveReplayTaskID, p.Authorization.NegativeReplayTaskID}
	var facts [3]rulerelease.Evidence
	for i, id := range ids {
		var raw, signature, receipt []byte
		var commandHash string
		if err := tx.QueryRow(ctx, `SELECT command,signature,command_sha256,receipt FROM sensor_tasks WHERE tenant_id=$1 AND id=$2 AND sensor_id=$3 AND registration_id=$4 AND state='succeeded' AND retain_until>now() FOR SHARE`, tenant, id, sensor, registration).Scan(&raw, &signature, &commandHash, &receipt); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, rulerelease.ErrQualification
			}
			return nil, err
		}
		var preliminary control.Command
		if commandHash != control.Digest(raw) || json.Unmarshal(raw, &preliminary) != nil || len(signer) != ed25519.PrivateKeySize {
			return nil, rulerelease.ErrQualification
		}
		// 历史命令可以超过投递期限，但签名与原始投递身份仍须有效；业务资格另核对回执时间。
		command, err := control.Decode(raw, signature, signer.Public().(ed25519.PublicKey), tenant, sensor, registration, preliminary.IssuedAt.Add(time.Nanosecond))
		if err != nil || command.ID != id || json.Unmarshal(receipt, &facts[i].Receipt) != nil || facts[i].Receipt.CommandSHA256 != commandHash {
			return nil, rulerelease.ErrQualification
		}
		facts[i].Command = command
	}
	grant, err := rulerelease.Qualify(p, facts, p.Authorization.ExpectedRulesSHA256, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	p.Authorization = grant
	return control.RulePayload(p)
}
