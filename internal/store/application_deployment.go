package store

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/application"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/model"
)

var ErrApplicationState = errors.New("探针应用规则状态、目录快照或任务信任已变化")
var ErrApplicationProvenance = errors.New("应用分类的原始部署依据不可用")

func applicationSnapshotTx(ctx context.Context, tx pgx.Tx, tenant string) (application.Snapshot, error) {
	s := application.Snapshot{Versions: []application.Version{}}
	rows, err := tx.Query(ctx, `SELECT `+applicationRuleColumns+` FROM application_rules h JOIN application_rule_revisions v ON v.tenant_id=h.tenant_id AND v.rule_id=h.id AND v.revision=h.revision WHERE h.tenant_id=$1 AND h.active ORDER BY h.id LIMIT $2`, tenant, application.MaxRules+1)
	if err != nil {
		return s, err
	}
	defer rows.Close()
	for rows.Next() {
		r, err := readApplicationRule(rows)
		if err != nil {
			return s, err
		}
		s.Versions = append(s.Versions, application.Version{ID: r.ID, Revision: r.Revision, Definition: r.Definition})
	}
	if err := rows.Err(); err != nil {
		return s, err
	}
	if _, err := application.Compile(s.Versions); err != nil {
		return s, err
	}
	s.RulesSHA256 = application.Digest(s.Versions)
	return s, nil
}

func (p *Postgres) ApplicationSnapshot(ctx context.Context, u model.Principal) (application.Snapshot, error) {
	var s application.Snapshot
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := applicationRuleUser(ctx, tx, u, false); err != nil {
			return err
		}
		var err error
		s, err = applicationSnapshotTx(ctx, tx, u.TenantID)
		return err
	})
	return s, err
}

func (p *Postgres) CreateApplicationDeployment(ctx context.Context, u model.Principal, sensor, key string, input application.DeploymentInput, signer ed25519.PrivateKey) (string, error) {
	if input.Validate() != nil || !contract.ValidID(sensor) || !contract.ValidID(key) {
		return "", application.ErrInput
	}
	raw, err := json.Marshal(input)
	if err != nil {
		return "", err
	}
	return p.CreateTask(ctx, u, sensor, "applications.apply", key, raw, signer)
}

// 目录快照、在线观测、操作者与任务冻结在同一事务；执行端再次核对状态摘要。
func qualifyApplicationTask(ctx context.Context, tx pgx.Tx, u model.Principal, sensor, registration string, raw json.RawMessage, signer ed25519.PrivateKey) (json.RawMessage, error) {
	var input application.DeploymentInput
	if json.Unmarshal(raw, &input) != nil || input.Validate() != nil || len(signer) != ed25519.PrivateKeySize {
		return nil, application.ErrInput
	}
	if input.ExpectedRegistrationID != registration {
		return nil, ErrApplicationState
	}
	var healthJSON json.RawMessage
	if err := tx.QueryRow(ctx, `SELECT health FROM sensors WHERE tenant_id=$1 AND id=$2 AND registration_id=$3 AND active AND last_seen>now()-interval '35 seconds'`, u.TenantID, sensor, registration).Scan(&healthJSON); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrApplicationState
		}
		return nil, err
	}
	var h model.HostHealth
	var state application.State
	now := time.Now().UTC()
	if json.Unmarshal(healthJSON, &h) != nil || json.Unmarshal(h.ApplicationRules, &state) != nil || state.Validate() != nil || h.ObservedAt.IsZero() || now.Sub(h.ObservedAt) > 35*time.Second || h.ObservedAt.After(now.Add(time.Minute)) || h.CommandSignerSHA256 != control.Digest(signer.Public().(ed25519.PublicKey)) || !slices.Contains(h.TaskCapabilities, "applications.apply") || state.StateSHA256 != input.ExpectedStateSHA256 {
		return nil, ErrApplicationState
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared(hashtextextended($1,0))`, u.TenantID+"/application-rules"); err != nil {
		return nil, err
	}
	snapshot, err := applicationSnapshotTx(ctx, tx, u.TenantID)
	if err != nil {
		return nil, err
	}
	if snapshot.RulesSHA256 != input.RulesSHA256 {
		return nil, ErrApplicationState
	}
	var count int
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, u.TenantID+"/application-deployment-budget"); err != nil {
		return nil, err
	}
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM sensor_tasks WHERE tenant_id=$1 AND kind='applications.apply' AND created_at>now()-interval '24 hours'`, u.TenantID).Scan(&count); err != nil {
		return nil, err
	}
	if count >= application.MaxDailyChanges {
		return nil, application.ErrQuota
	}
	p := application.Package{SchemaVersion: application.PackageSchema, DeploymentInput: input, Versions: snapshot.Versions}
	encoded, err := json.Marshal(p)
	if err != nil || len(encoded) > application.MaxPackageBytes {
		return nil, application.ErrInput
	}
	return encoded, nil
}

// 原始命令档案构成不可变复算依据，当前目录和当前设备状态不会改变历史分类。
// 回执可先于或晚于事件到达；只有已经实际投递的签名任务能提供分类依据。
func (p *Postgres) ApplicationDeployment(ctx context.Context, tenant, sensor, registration, id string) (*application.Matcher, error) {
	if !contract.ValidID(id) {
		return nil, ErrApplicationProvenance
	}
	var matcher *application.Matcher
	err := p.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		var raw []byte
		var digest, state string
		var delivered int
		err := tx.QueryRow(ctx, `SELECT command,command_sha256,state,delivery_count FROM sensor_tasks WHERE tenant_id=$1 AND id=$2 AND sensor_id=$3 AND registration_id=$4 AND kind='applications.apply'`, tenant, id, sensor, registration).Scan(&raw, &digest, &state, &delivered)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrApplicationProvenance
		}
		if err != nil {
			return err
		}
		var c control.Command
		if control.Digest(raw) != digest || json.Unmarshal(raw, &c) != nil || control.Validate(c) != nil || c.Kind != "applications.apply" || c.ID != id || c.TenantID != tenant || c.SensorID != sensor || c.RegistrationID != registration || delivered < 1 || !slices.Contains([]string{"delivered", "running", "succeeded", "unknown"}, state) {
			return ErrApplicationProvenance
		}
		p, err := application.ReadPackage(c.Payload)
		if err != nil {
			return ErrApplicationProvenance
		}
		matcher, err = application.Compile(p.Versions)
		return err
	})
	return matcher, err
}

func validateApplicationReceipt(c control.Command, receipt control.Receipt) error {
	p, err := application.ReadPackage(c.Payload)
	var state application.State
	if err != nil || receipt.Code != "" || json.Unmarshal(receipt.Result, &state) != nil || state.Validate() != nil || state.DeploymentID != c.ID || state.RulesSHA256 != p.RulesSHA256 || state.RuleCount != len(p.Versions) || state.InstalledAt.Before(c.IssuedAt.Add(-time.Minute)) || receipt.FinishedAt == nil || state.InstalledAt.After(receipt.FinishedAt.Add(time.Minute)) {
		return application.ErrInput
	}
	return nil
}
