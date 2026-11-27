package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/decision"
	"github.com/kkx600/StarBeacon/internal/gatewayblock"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/playbook"
)

const playbookHeaders = ` FROM playbooks h JOIN playbook_revisions v ON (v.tenant_id,v.playbook_id,v.revision)=(h.tenant_id,h.id,h.revision)
	LEFT JOIN playbook_revisions p ON (p.tenant_id,p.playbook_id,p.revision)=(h.tenant_id,h.id,h.published_revision)`
const playbookColumns = `h.id,h.owner_id,v.revision,h.published_revision,COALESCE(p.sha256,''),v.definition,v.sha256,h.updated_at`

func readPlaybook(row pgx.Row) (playbook.Record, error) {
	var item playbook.Record
	var raw []byte
	if err := row.Scan(&item.ID, &item.OwnerID, &item.Revision, &item.PublishedRevision, &item.PublishedSHA256, &raw, &item.SHA256, &item.UpdatedAt); err != nil {
		return item, err
	}
	if json.Unmarshal(raw, &item.Definition) != nil || !item.Definition.ValidDraft() || playbook.Digest(item.Definition) != item.SHA256 {
		return item, playbook.ErrSource
	}
	return item, nil
}

func playbookActor(ctx context.Context, tx pgx.Tx, u model.Principal) error {
	return configurationActor(ctx, tx, u, true, playbook.ErrPermission)
}

func playbookPageValid(cursor string, limit int) bool {
	return (cursor == "" || contract.ValidID(cursor)) && limit >= 1 && limit <= 100
}

func (p *Postgres) Playbooks(ctx context.Context, u model.Principal, cursor string, limit int) (playbook.Page[playbook.Record], error) {
	out := playbook.Page[playbook.Record]{Items: []playbook.Record{}}
	if !playbookPageValid(cursor, limit) {
		return out, playbook.ErrInput
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := playbookActor(ctx, tx, u); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT `+playbookColumns+playbookHeaders+` WHERE h.tenant_id=$1 AND h.id>$2 ORDER BY h.id LIMIT $3`, u.TenantID, cursor, limit+1)
		if err != nil {
			return err
		}
		out.Items, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (playbook.Record, error) { return readPlaybook(row) })
		return err
	})
	if len(out.Items) > limit {
		out.Items = out.Items[:limit]
		out.NextCursor = out.Items[limit-1].ID
	}
	return out, err
}

func (p *Postgres) Playbook(ctx context.Context, u model.Principal, id string) (playbook.Record, error) {
	var out playbook.Record
	if !contract.ValidID(id) {
		return out, playbook.ErrInput
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := playbookActor(ctx, tx, u); err != nil {
			return err
		}
		var err error
		out, err = readPlaybook(tx.QueryRow(ctx, `SELECT `+playbookColumns+playbookHeaders+` WHERE h.tenant_id=$1 AND h.id=$2`, u.TenantID, id))
		return err
	})
	return out, err
}

func (p *Postgres) SavePlaybook(ctx context.Context, u model.Principal, id, key string, change playbook.Change) (playbook.Record, error) {
	var out playbook.Record
	if !change.Definition.ValidDraft() || !contract.ValidID(key) || len(key) < 8 || change.ExpectedRevision < 0 || change.ExpectedRevision >= playbook.MaxRevision ||
		id == "" && change.ExpectedRevision != 0 || id != "" && (!contract.ValidID(id) || change.ExpectedRevision == 0) {
		return out, playbook.ErrInput
	}
	digest := playbook.Digest(change.Definition)
	raw, err := json.Marshal(change.Definition)
	if err != nil {
		return out, playbook.ErrInput
	}
	err = p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := playbookActor(ctx, tx, u); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, u.TenantID+"/playbooks"); err != nil {
			return err
		}
		prior, err := readPlaybook(tx.QueryRow(ctx, `SELECT h.id,v.owner_id,v.revision,h.published_revision,COALESCE(b.sha256,''),v.definition,v.sha256,v.created_at
			FROM playbook_revisions v JOIN playbooks h ON (h.tenant_id,h.id)=(v.tenant_id,v.playbook_id)
			LEFT JOIN playbook_revisions b ON (b.tenant_id,b.playbook_id,b.revision)=(h.tenant_id,h.id,h.published_revision)
			WHERE v.tenant_id=$1 AND v.owner_id=$2 AND v.key_hash=$3`, u.TenantID, u.ID, Hash(key)))
		if err == nil {
			if id != "" && prior.ID != id || prior.Revision != change.ExpectedRevision+1 || prior.SHA256 != digest {
				return ErrConflict
			}
			out = prior
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if id == "" {
			var count int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM playbooks WHERE tenant_id=$1`, u.TenantID).Scan(&count); err != nil {
				return err
			}
			if count >= 100 {
				return playbook.ErrLimit
			}
			id = RandomID("pb_")
			if _, err := tx.Exec(ctx, `INSERT INTO playbooks(tenant_id,id,owner_id,revision) VALUES($1,$2,$3,1)`, u.TenantID, id, u.ID); err != nil {
				return err
			}
		} else {
			result, err := tx.Exec(ctx, `UPDATE playbooks SET revision=revision+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND owner_id=$3 AND revision=$4`, u.TenantID, id, u.ID, change.ExpectedRevision)
			if err != nil {
				return err
			}
			if result.RowsAffected() != 1 {
				return ErrConflict
			}
		}
		if _, err := tx.Exec(ctx, `INSERT INTO playbook_revisions(tenant_id,playbook_id,revision,owner_id,key_hash,definition,sha256) VALUES($1,$2,$3,$4,$5,$6,$7)`, u.TenantID, id, change.ExpectedRevision+1, u.ID, Hash(key), raw, digest); err != nil {
			return err
		}
		out, err = readPlaybook(tx.QueryRow(ctx, `SELECT `+playbookColumns+playbookHeaders+` WHERE h.tenant_id=$1 AND h.id=$2`, u.TenantID, id))
		if err != nil {
			return err
		}
		return insertOperationAudit(ctx, tx, u, "playbook.save", id, model.RequestMetadataFrom(ctx).RequestID)
	})
	return out, err
}

func (p *Postgres) ValidatePlaybook(ctx context.Context, u model.Principal, d playbook.Definition) ([]playbook.Issue, error) {
	if !d.ValidDraft() {
		return nil, playbook.ErrInput
	}
	var issues []playbook.Issue
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := playbookActor(ctx, tx, u); err != nil {
			return err
		}
		var err error
		issues, err = playbookIssues(ctx, tx, u.TenantID, d)
		return err
	})
	return issues, err
}

func (p *Postgres) PublishPlaybook(ctx context.Context, u model.Principal, id string, rev playbook.Revision) (playbook.Record, []playbook.Issue, error) {
	var out playbook.Record
	issues := []playbook.Issue{}
	if !contract.ValidID(id) || !rev.Valid() {
		return out, issues, playbook.ErrInput
	}
	err := p.TenantTx(ctx, u.TenantID, func(tx pgx.Tx) error {
		if err := playbookActor(ctx, tx, u); err != nil {
			return err
		}
		var err error
		out, err = readPlaybook(tx.QueryRow(ctx, `SELECT `+playbookColumns+playbookHeaders+` WHERE h.tenant_id=$1 AND h.id=$2 AND h.owner_id=$3 FOR UPDATE OF h`, u.TenantID, id, u.ID))
		if err != nil {
			return err
		}
		if out.Revision != rev.Revision || out.SHA256 != rev.SHA256 {
			return ErrConflict
		}
		if out.PublishedRevision == rev.Revision {
			return nil
		}
		issues, err = playbookIssues(ctx, tx, u.TenantID, out.Definition)
		if err != nil || len(issues) > 0 {
			return err
		}
		if err := tx.QueryRow(ctx, `UPDATE playbooks SET published_revision=$3,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 RETURNING updated_at`, u.TenantID, id, rev.Revision).Scan(&out.UpdatedAt); err != nil {
			return err
		}
		out.PublishedRevision, out.PublishedSHA256 = rev.Revision, rev.SHA256
		return insertOperationAudit(ctx, tx, u, "playbook.publish", id, model.RequestMetadataFrom(ctx).RequestID)
	})
	return out, issues, err
}

func playbookIssues(ctx context.Context, tx pgx.Tx, tenant string, d playbook.Definition) ([]playbook.Issue, error) {
	issues := d.Issues()
	if len(issues) > 0 {
		return issues, nil
	}
	var provider *playbook.ModelBinding
	for i, s := range d.Steps {
		var ok bool
		var err error
		var code string
		switch s.Kind {
		case "triage":
			provider = s.Model
			code = "model_current"
			err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM model_providers WHERE tenant_id=$1 AND id=$2 AND revision=$3 AND public->>'enabled'='true')`, tenant, provider.ID, provider.Revision).Scan(&ok)
		case "plugin":
			code = "plugin_current"
			ok, err = playbookPluginQualified(ctx, tx, tenant, *s.Plugin, *provider)
		case "gateway":
			code = "gateway_current"
			var policy gatewayblock.Policy
			policy, err = gatewayPolicy(ctx, tx, tenant, s.Gateway.ID)
			ok = err == nil && policy.Revision == s.Gateway.Revision && policy.Definition.Enabled && policy.Definition.ValidUntil.After(time.Now()) && policy.Definition.Trigger == gatewayblock.Review && policy.Definition.FollowUp == nil
		default:
			continue
		}
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
		if !ok {
			issues = append(issues, playbook.Issue{Step: i, Code: code})
		}
	}
	return issues, nil
}

func playbookPluginQualified(ctx context.Context, tx pgx.Tx, tenant string, b playbook.PluginBinding, provider playbook.ModelBinding) (bool, error) {
	policy, err := readDecisionPolicy(tx.QueryRow(ctx, `SELECT `+decisionPolicyColumns+` FROM decision_policies h JOIN decision_policy_revisions v
		ON (v.tenant_id,v.policy_id,v.revision)=(h.tenant_id,h.id,h.revision) WHERE h.tenant_id=$1 AND h.id=$2`, tenant, b.Policy.ID))
	if err != nil {
		return false, err
	}
	d := policy.Definition
	if !policy.Active || policy.Revision != b.Policy.Revision || d.Mode != "approval" || d.Level() != decision.Approval || d.CandidateAction != "block_source" ||
		d.Continuous.ProviderID != provider.ID || d.Continuous.ProviderRevision != provider.Revision {
		return false, nil
	}
	var ok bool
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM sensors s CROSS JOIN LATERAL jsonb_to_recordset(COALESCE(s.health->'response_connectors','[]'))
		AS c(connector_id text,config_sha256 text,max_ttl_seconds int) WHERE s.tenant_id=$1 AND s.id=$2 AND s.registration_id=$3 AND s.active
		AND c.connector_id=$4 AND c.config_sha256=$5 AND c.max_ttl_seconds>=$6)`, tenant, b.SensorID, b.RegistrationID, b.ConnectorID, b.ConfigSHA256, b.TTLSeconds).Scan(&ok)
	return ok, err
}
