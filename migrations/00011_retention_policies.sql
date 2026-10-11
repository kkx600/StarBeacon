-- +goose Up
ALTER TABLE retention_policies ADD COLUMN revision bigint NOT NULL DEFAULT 1 CHECK(revision>0);
ALTER TABLE retention_policies ADD COLUMN updated_at timestamptz NOT NULL DEFAULT now();
CREATE TABLE retention_previews (
 tenant_id text NOT NULL REFERENCES tenants(id), id text NOT NULL, created_by text NOT NULL,
 candidate jsonb NOT NULL, current_days integer NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
 expires_at timestamptz NOT NULL DEFAULT now()+interval '5 minutes',
 PRIMARY KEY(tenant_id,id)
);
CREATE INDEX retention_preview_expiry ON retention_previews(tenant_id,expires_at);
CREATE TABLE retention_changes (
 tenant_id text NOT NULL REFERENCES tenants(id), id text NOT NULL, created_by text NOT NULL,
 category text NOT NULL, days integer NOT NULL CHECK(days BETWEEN 1 AND 3650), revision bigint NOT NULL,
 request_hash text NOT NULL, idempotency_key_hash text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,created_by,idempotency_key_hash)
);
ALTER TABLE retention_previews ENABLE ROW LEVEL SECURITY;
ALTER TABLE retention_previews FORCE ROW LEVEL SECURITY;
CREATE POLICY retention_preview_scope ON retention_previews USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
ALTER TABLE retention_changes ENABLE ROW LEVEL SECURITY;
ALTER TABLE retention_changes FORCE ROW LEVEL SECURITY;
CREATE POLICY retention_change_scope ON retention_changes USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
ALTER TABLE notification_channel_versions ADD COLUMN expires_at timestamptz NOT NULL DEFAULT now()+interval '180 days';
UPDATE notification_channel_versions v SET expires_at=created_at+make_interval(days=>COALESCE((SELECT days FROM retention_policies WHERE tenant_id=v.tenant_id AND category='notifications'),180));
ALTER TABLE model_provider_versions ADD COLUMN expires_at timestamptz NOT NULL DEFAULT now()+interval '180 days';
UPDATE model_provider_versions v SET expires_at=created_at+make_interval(days=>COALESCE((SELECT days FROM retention_policies WHERE tenant_id=v.tenant_id AND category='models'),180));
-- +goose Down
ALTER TABLE model_provider_versions DROP COLUMN expires_at;
ALTER TABLE notification_channel_versions DROP COLUMN expires_at;
DROP TABLE retention_changes,retention_previews;
ALTER TABLE retention_policies DROP COLUMN updated_at,DROP COLUMN revision;
