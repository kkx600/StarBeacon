-- +goose Up
CREATE TABLE response_plugin_generations (
 tenant_id text NOT NULL REFERENCES tenants(id), id text NOT NULL, created_by text NOT NULL,
 provider_id text NOT NULL, provider_revision bigint NOT NULL, model_name text NOT NULL,
 input jsonb NOT NULL CHECK(jsonb_typeof(input)='object'), request_sha256 text NOT NULL CHECK(request_sha256 ~ '^[a-f0-9]{64}$'),
 document_sha256 text NOT NULL CHECK(document_sha256 ~ '^[a-f0-9]{64}$'), idempotency_hash text NOT NULL,
 prompt_version text NOT NULL,
 state text NOT NULL CHECK(state IN ('queued','running','succeeded','failed','refused','incomplete','uncertain','cancelled')),
 candidate jsonb CHECK(jsonb_typeof(candidate)='object' AND octet_length(candidate::text)<=262144),
 result jsonb NOT NULL CHECK(jsonb_typeof(result)='object' AND NOT (result ? 'text')),
 river_job_id bigint, lease_token text, deadline timestamptz NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(), finished_at timestamptz, expires_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,created_by,idempotency_hash),
 FOREIGN KEY(tenant_id,provider_id,provider_revision) REFERENCES model_provider_versions(tenant_id,provider_id,revision),
 CHECK((state='queued')=(input ? 'documentation')),
 CHECK(result->>'state'=state),
 CHECK((state='succeeded')=(candidate IS NOT NULL))
);
CREATE INDEX response_plugin_generation_owner ON response_plugin_generations(tenant_id,created_by,created_at DESC,id DESC);
CREATE INDEX response_plugin_generation_budget ON response_plugin_generations(tenant_id,provider_id,created_at);
CREATE INDEX response_plugin_generation_pending ON response_plugin_generations(tenant_id,deadline) WHERE state IN ('queued','running');
CREATE INDEX response_plugin_generation_expiry ON response_plugin_generations(tenant_id,expires_at,id) WHERE state NOT IN ('queued','running');

ALTER TABLE response_plugin_generations ENABLE ROW LEVEL SECURITY;
ALTER TABLE response_plugin_generations FORCE ROW LEVEL SECURITY;
CREATE POLICY response_plugin_generation_scope ON response_plugin_generations
 USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
CREATE POLICY response_plugin_generation_expired ON response_plugin_generations AS RESTRICTIVE FOR DELETE
 USING(expires_at<=now() AND state NOT IN ('queued','running') AND NOT EXISTS(
  SELECT 1 FROM starbeacon_jobs.river_job j WHERE j.id=river_job_id AND j.state NOT IN ('completed','cancelled','discarded')
 ));

-- +goose Down
DROP TABLE response_plugin_generations;
