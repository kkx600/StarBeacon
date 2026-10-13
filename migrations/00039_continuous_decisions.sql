-- +goose Up
CREATE TABLE decision_continuous_runs (
 tenant_id text NOT NULL REFERENCES tenants(id), id text NOT NULL,
 created_by text NOT NULL REFERENCES users(id), evaluation_id text NOT NULL,
 policy_id text NOT NULL, policy_revision bigint NOT NULL CHECK(policy_revision>0), triage_id text NOT NULL,
 event_id text NOT NULL, raw_sha256 text NOT NULL, sensor_id text NOT NULL, connector_id text NOT NULL,
 state text NOT NULL CHECK(state IN ('queued','awaiting_confirmation','skipped')),
 task_id text NOT NULL, created_at timestamptz NOT NULL, expires_at timestamptz NOT NULL CHECK(expires_at>created_at),
 record jsonb NOT NULL CHECK(jsonb_typeof(record)='object' AND octet_length(record::text)<=16384),
 PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,evaluation_id), UNIQUE(tenant_id,policy_id,policy_revision,triage_id)
);
CREATE UNIQUE INDEX decision_continuous_event_once ON decision_continuous_runs(tenant_id,event_id,raw_sha256,sensor_id,connector_id) WHERE state='queued';
CREATE INDEX decision_continuous_quota ON decision_continuous_runs(tenant_id,policy_id,created_at) WHERE state='queued';
CREATE INDEX decision_continuous_expiry ON decision_continuous_runs(tenant_id,expires_at);
CREATE INDEX decision_triage_continuous ON alert_triage_jobs(tenant_id,created_by,provider_id,provider_revision,created_at,id) WHERE state='succeeded' AND NOT cancel_requested;
CREATE INDEX response_task_cooldown ON sensor_tasks(tenant_id,sensor_id,created_at) WHERE kind='response.block';
ALTER TABLE decision_continuous_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE decision_continuous_runs FORCE ROW LEVEL SECURITY;
CREATE POLICY decision_continuous_scope ON decision_continuous_runs USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
CREATE POLICY decision_continuous_expiry_delete ON decision_continuous_runs AS RESTRICTIVE FOR DELETE USING(expires_at<=now());
ALTER TABLE retention_maintenance DROP CONSTRAINT retention_maintenance_next_category_check;
ALTER TABLE retention_maintenance ADD CONSTRAINT retention_maintenance_next_category_check CHECK(next_category BETWEEN 0 AND 30);
-- +goose Down
UPDATE retention_maintenance SET next_category=0 WHERE next_category>29;
ALTER TABLE retention_maintenance DROP CONSTRAINT retention_maintenance_next_category_check;
ALTER TABLE retention_maintenance ADD CONSTRAINT retention_maintenance_next_category_check CHECK(next_category BETWEEN 0 AND 29);
DROP INDEX decision_triage_continuous;
DROP INDEX response_task_cooldown;
DROP TABLE decision_continuous_runs;
