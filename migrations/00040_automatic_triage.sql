-- +goose Up
CREATE TABLE decision_triage_triggers (
 tenant_id text NOT NULL REFERENCES tenants(id), id text NOT NULL,
 created_by text NOT NULL REFERENCES users(id), policy_id text NOT NULL,
 policy_revision bigint NOT NULL CHECK(policy_revision>0), definition_sha256 text NOT NULL,
 event_id text NOT NULL, raw_sha256 text NOT NULL, sensor_id text NOT NULL, registration_id text NOT NULL,
 observed_at timestamptz NOT NULL, received_at timestamptz NOT NULL,
 evidence_sha256 text NOT NULL, state text NOT NULL CHECK(state IN ('pending','submitted','skipped')),
 code text NOT NULL, triage_id text NOT NULL DEFAULT '', created_at timestamptz NOT NULL DEFAULT now(),
 expires_at timestamptz NOT NULL CHECK(expires_at>created_at),
 PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,policy_id,policy_revision,event_id,raw_sha256),
 CHECK((state='submitted')=(triage_id<>''))
);
CREATE INDEX decision_triage_pending ON decision_triage_triggers(tenant_id,created_at,id) WHERE state='pending';
CREATE INDEX decision_triage_daily ON decision_triage_triggers(tenant_id,policy_id,created_at);
CREATE INDEX decision_triage_expiry ON decision_triage_triggers(tenant_id,expires_at);
ALTER TABLE decision_triage_triggers ENABLE ROW LEVEL SECURITY;
ALTER TABLE decision_triage_triggers FORCE ROW LEVEL SECURITY;
CREATE POLICY decision_triage_scope ON decision_triage_triggers USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
CREATE POLICY decision_triage_expiry_delete ON decision_triage_triggers AS RESTRICTIVE FOR DELETE USING(expires_at<=now() AND state<>'pending');
ALTER TABLE retention_maintenance DROP CONSTRAINT retention_maintenance_next_category_check;
ALTER TABLE retention_maintenance ADD CONSTRAINT retention_maintenance_next_category_check CHECK(next_category BETWEEN 0 AND 31);
-- +goose Down
UPDATE retention_maintenance SET next_category=0 WHERE next_category>30;
ALTER TABLE retention_maintenance DROP CONSTRAINT retention_maintenance_next_category_check;
ALTER TABLE retention_maintenance ADD CONSTRAINT retention_maintenance_next_category_check CHECK(next_category BETWEEN 0 AND 30);
DROP TABLE decision_triage_triggers;
