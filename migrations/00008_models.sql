-- +goose Up
CREATE TABLE model_providers (
 tenant_id text NOT NULL REFERENCES tenants(id), id text NOT NULL,
 revision bigint NOT NULL CHECK(revision>0), public jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(tenant_id,id)
);
CREATE TABLE model_provider_versions (
 tenant_id text NOT NULL, provider_id text NOT NULL, revision bigint NOT NULL,
 ciphertext text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(tenant_id,provider_id,revision),
 FOREIGN KEY(tenant_id,provider_id) REFERENCES model_providers(tenant_id,id)
);
CREATE TABLE model_capability_checks (
 tenant_id text NOT NULL, id text NOT NULL, provider_id text NOT NULL, provider_revision bigint NOT NULL,
 created_by text NOT NULL, idempotency_key_hash text NOT NULL,
 state text NOT NULL CHECK(state IN ('running','succeeded','failed','refused','incomplete','uncertain')),
 result jsonb NOT NULL DEFAULT '{}', created_at timestamptz NOT NULL DEFAULT now(),
 finished_at timestamptz, deadline timestamptz NOT NULL,
 expires_at timestamptz NOT NULL DEFAULT now()+interval '180 days',
 PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,provider_id,created_by,idempotency_key_hash),
 FOREIGN KEY(tenant_id,provider_id,provider_revision) REFERENCES model_provider_versions(tenant_id,provider_id,revision)
);
CREATE INDEX model_check_latest ON model_capability_checks(tenant_id,provider_id,created_at DESC,id DESC);
CREATE INDEX model_check_quota ON model_capability_checks(tenant_id,provider_id,created_at);
ALTER TABLE model_providers ENABLE ROW LEVEL SECURITY;
ALTER TABLE model_providers FORCE ROW LEVEL SECURITY;
CREATE POLICY model_provider_scope ON model_providers USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
ALTER TABLE model_provider_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE model_provider_versions FORCE ROW LEVEL SECURITY;
CREATE POLICY model_version_scope ON model_provider_versions USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
ALTER TABLE model_capability_checks ENABLE ROW LEVEL SECURITY;
ALTER TABLE model_capability_checks FORCE ROW LEVEL SECURITY;
CREATE POLICY model_check_scope ON model_capability_checks USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
-- +goose Down
DROP TABLE model_capability_checks,model_provider_versions,model_providers;
