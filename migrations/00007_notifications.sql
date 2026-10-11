-- +goose Up
CREATE TABLE notification_channels (
 tenant_id text NOT NULL REFERENCES tenants(id), id text NOT NULL,
 revision bigint NOT NULL CHECK(revision>0), name text NOT NULL,
 kind text NOT NULL CHECK(kind IN ('email','webhook','wecom','dingtalk','feishu','syslog_tls','syslog_tcp')),
 enabled boolean NOT NULL, severities jsonb NOT NULL, target text NOT NULL,
 muted_until timestamptz, next_delivery_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(tenant_id,id)
);
CREATE TABLE notification_channel_versions (
 tenant_id text NOT NULL, channel_id text NOT NULL, revision bigint NOT NULL,
 ciphertext text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(tenant_id,channel_id,revision),
 FOREIGN KEY(tenant_id,channel_id) REFERENCES notification_channels(tenant_id,id)
);
CREATE TABLE notification_batches (
 tenant_id text NOT NULL, id text NOT NULL, upstream_batch_id text NOT NULL,
 channel_id text NOT NULL, channel_revision bigint NOT NULL, message jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL DEFAULT now()+interval '180 days',
 PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,upstream_batch_id,channel_id),
 FOREIGN KEY(tenant_id,channel_id,channel_revision) REFERENCES notification_channel_versions(tenant_id,channel_id,revision)
);
CREATE TABLE notification_deliveries (
 tenant_id text NOT NULL, id text NOT NULL, batch_id text NOT NULL, recipient text NOT NULL,
 state text NOT NULL CHECK(state IN ('queued','running','retry','accepted','transport_written','failed','uncertain','suppressed','cancelled')),
 version bigint NOT NULL DEFAULT 1, attempts integer NOT NULL DEFAULT 0,
 lease_token text, lease_until timestamptz, next_attempt_at timestamptz NOT NULL DEFAULT now(),
 receipt jsonb NOT NULL DEFAULT '{}', created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
 expires_at timestamptz NOT NULL DEFAULT now()+interval '180 days',
 PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,batch_id,recipient),
 FOREIGN KEY(tenant_id,batch_id) REFERENCES notification_batches(tenant_id,id)
);
CREATE INDEX notification_pending ON notification_deliveries(tenant_id,next_attempt_at,id) WHERE state IN ('queued','retry');
CREATE INDEX notification_expiry ON notification_deliveries(tenant_id,expires_at);
CREATE INDEX notification_lease ON notification_deliveries(tenant_id,lease_until) WHERE state='running';
CREATE INDEX notification_list ON notification_deliveries(tenant_id,created_at DESC,id DESC);
ALTER TABLE notification_channels ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_channels FORCE ROW LEVEL SECURITY;
CREATE POLICY notification_channel_scope ON notification_channels USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
ALTER TABLE notification_channel_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_channel_versions FORCE ROW LEVEL SECURITY;
CREATE POLICY notification_version_scope ON notification_channel_versions USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
ALTER TABLE notification_batches ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_batches FORCE ROW LEVEL SECURITY;
CREATE POLICY notification_batch_scope ON notification_batches USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
ALTER TABLE notification_deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_deliveries FORCE ROW LEVEL SECURITY;
CREATE POLICY notification_delivery_scope ON notification_deliveries USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
-- +goose Down
DROP TABLE notification_deliveries,notification_batches,notification_channel_versions,notification_channels;
