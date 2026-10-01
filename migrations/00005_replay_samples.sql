-- +goose Up
CREATE TABLE replay_samples (
 tenant_id text NOT NULL REFERENCES tenants(id), id text NOT NULL, name text NOT NULL,
 size bigint NOT NULL CHECK(size BETWEEN 24 AND 104857600), sha256 text NOT NULL DEFAULT '',
 format text NOT NULL DEFAULT '', state text NOT NULL CHECK(state IN ('uploading','ready','failed')),
 created_by text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
 expires_at timestamptz NOT NULL DEFAULT now()+interval '180 days',
 PRIMARY KEY(tenant_id,id)
);
CREATE INDEX replay_samples_expiry ON replay_samples(tenant_id,expires_at);
ALTER TABLE replay_samples ENABLE ROW LEVEL SECURITY;
ALTER TABLE replay_samples FORCE ROW LEVEL SECURITY;
CREATE POLICY replay_scope ON replay_samples USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
-- +goose Down
DROP TABLE replay_samples;
