-- +goose Up
CREATE TABLE packet_archives (
 tenant_id text NOT NULL REFERENCES tenants(id), id text NOT NULL,
 sensor_id text NOT NULL, registration_id text NOT NULL,
 manifest jsonb NOT NULL, manifest_sha256 text NOT NULL,
 object_key text NOT NULL, object_version text NOT NULL DEFAULT '',
 stored_bytes bigint NOT NULL CHECK(stored_bytes BETWEEN 1 AND 134217728),
 state text NOT NULL CHECK(state IN ('uploading','stored','ready','deleting')),
 lease_token text NOT NULL, lease_until timestamptz NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 expires_at timestamptz NOT NULL DEFAULT now()+interval '180 days',
 PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,object_key),
 CHECK(state NOT IN ('stored','ready') OR object_version<>''),
 FOREIGN KEY(tenant_id,sensor_id) REFERENCES sensors(tenant_id,id)
);
CREATE INDEX packet_archive_sensor ON packet_archives(tenant_id,sensor_id,created_at DESC,id DESC);
CREATE INDEX packet_archive_cleanup ON packet_archives(tenant_id,expires_at,id);
CREATE TABLE packet_archive_capacity(tenant_id text PRIMARY KEY REFERENCES tenants(id),reserved_bytes bigint NOT NULL DEFAULT 0 CHECK(reserved_bytes>=0));
ALTER TABLE packet_archive_capacity ENABLE ROW LEVEL SECURITY;
ALTER TABLE packet_archive_capacity FORCE ROW LEVEL SECURITY;
CREATE POLICY packet_archive_capacity_scope ON packet_archive_capacity USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
ALTER TABLE packet_archives ENABLE ROW LEVEL SECURITY;
ALTER TABLE packet_archives FORCE ROW LEVEL SECURITY;
CREATE POLICY packet_archive_scope ON packet_archives USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
CREATE POLICY packet_archive_expiry_delete ON packet_archives AS RESTRICTIVE FOR DELETE USING(state='deleting' AND expires_at<=now() AND lease_until<=now());
-- +goose Down
DROP TABLE packet_archives;
DROP TABLE packet_archive_capacity;
