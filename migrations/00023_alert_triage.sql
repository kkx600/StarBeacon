-- +goose Up
CREATE TABLE alert_triage_jobs (
 tenant_id text NOT NULL REFERENCES tenants(id), id text NOT NULL, created_by text NOT NULL,
 event_id text NOT NULL, raw_sha256 text NOT NULL,
 provider_id text NOT NULL, provider_revision bigint NOT NULL,
 request jsonb NOT NULL, request_hash text NOT NULL, idempotency_key_hash text NOT NULL,
 template text NOT NULL, evidence jsonb NOT NULL, prompt text NOT NULL, prompt_hash text NOT NULL,
 answer jsonb, result jsonb NOT NULL DEFAULT '{"state":"queued","code":"awaiting_execution","usage":null,"duration_ms":null}',
 state text NOT NULL CHECK(state IN ('queued','running','succeeded','failed','refused','incomplete','uncertain','cancelled')),
 cancel_requested boolean NOT NULL DEFAULT false, river_job_id bigint,
 lease_token text, deadline timestamptz NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(), started_at timestamptz, finished_at timestamptz,
 expires_at timestamptz NOT NULL DEFAULT now()+interval '180 days',
 PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,created_by,idempotency_key_hash),
 FOREIGN KEY(tenant_id,provider_id,provider_revision) REFERENCES model_provider_versions(tenant_id,provider_id,revision)
);
CREATE INDEX alert_triage_owner ON alert_triage_jobs(tenant_id,created_by,event_id,created_at DESC,id DESC);
CREATE INDEX alert_triage_quota ON alert_triage_jobs(tenant_id,provider_id,created_at);
CREATE INDEX alert_triage_cleanup ON alert_triage_jobs(tenant_id,expires_at,id) WHERE state NOT IN ('queued','running');
ALTER TABLE alert_triage_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE alert_triage_jobs FORCE ROW LEVEL SECURITY;
CREATE POLICY alert_triage_scope ON alert_triage_jobs USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
CREATE POLICY alert_triage_expiry_delete ON alert_triage_jobs AS RESTRICTIVE FOR DELETE USING(expires_at<=now() AND state NOT IN ('queued','running') AND NOT EXISTS(SELECT 1 FROM starbeacon_jobs.river_job j WHERE j.id=river_job_id AND j.state NOT IN ('completed','cancelled','discarded')));
ALTER TABLE retention_maintenance DROP CONSTRAINT retention_maintenance_next_category_check;
ALTER TABLE retention_maintenance ADD CONSTRAINT retention_maintenance_next_category_check CHECK(next_category BETWEEN 0 AND 19);
-- +goose Down
ALTER TABLE retention_maintenance DROP CONSTRAINT retention_maintenance_next_category_check;
UPDATE retention_maintenance SET next_category=0 WHERE next_category>18;
ALTER TABLE retention_maintenance ADD CONSTRAINT retention_maintenance_next_category_check CHECK(next_category BETWEEN 0 AND 18);
DROP TABLE alert_triage_jobs;
