-- +goose Up
CREATE TABLE sensor_groups (
 tenant_id text NOT NULL REFERENCES tenants(id), id text NOT NULL, name text NOT NULL,
 description text NOT NULL, revision bigint NOT NULL CHECK(revision BETWEEN 1 AND 1000000),
 active boolean NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(tenant_id,id), CHECK(char_length(name) BETWEEN 1 AND 128), CHECK(char_length(description)<=1000)
);
CREATE UNIQUE INDEX sensor_groups_name ON sensor_groups(tenant_id,lower(name));
ALTER TABLE sensor_groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE sensor_groups FORCE ROW LEVEL SECURITY;
CREATE POLICY sensor_groups_scope ON sensor_groups USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
ALTER TABLE sensors ADD COLUMN metadata_revision bigint NOT NULL DEFAULT 1 CHECK(metadata_revision BETWEEN 1 AND 1000000),
 ADD COLUMN group_id text, ADD COLUMN site text NOT NULL DEFAULT '', ADD COLUMN description text NOT NULL DEFAULT '',
 ADD COLUMN metadata_updated_at timestamptz NOT NULL DEFAULT now(),
 ADD FOREIGN KEY(tenant_id,group_id) REFERENCES sensor_groups(tenant_id,id),
 ADD CHECK(char_length(site)<=128), ADD CHECK(char_length(description)<=1000);
CREATE INDEX sensors_group_members ON sensors(tenant_id,group_id,id);
CREATE TABLE sensor_management_requests (
 tenant_id text NOT NULL REFERENCES tenants(id), created_by text NOT NULL, key_hash text NOT NULL,
 operation text NOT NULL CHECK(operation IN('group','metadata')), object_id text NOT NULL,
 input_hash text NOT NULL, record jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,created_by,key_hash)
);
CREATE INDEX sensor_management_expiry ON sensor_management_requests(tenant_id,expires_at);
CREATE INDEX sensor_management_budget ON sensor_management_requests(tenant_id,created_at);
ALTER TABLE sensor_management_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE sensor_management_requests FORCE ROW LEVEL SECURITY;
CREATE POLICY sensor_management_scope ON sensor_management_requests USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
CREATE POLICY sensor_management_expiry_delete ON sensor_management_requests AS RESTRICTIVE FOR DELETE USING(expires_at<=now());
ALTER TABLE retention_maintenance DROP CONSTRAINT retention_maintenance_next_category_check;
ALTER TABLE retention_maintenance ADD CONSTRAINT retention_maintenance_next_category_check CHECK(next_category BETWEEN 0 AND 23);
-- +goose Down
UPDATE retention_maintenance SET next_category=0 WHERE next_category>22;
ALTER TABLE retention_maintenance DROP CONSTRAINT retention_maintenance_next_category_check;
ALTER TABLE retention_maintenance ADD CONSTRAINT retention_maintenance_next_category_check CHECK(next_category BETWEEN 0 AND 22);
DROP TABLE sensor_management_requests;
DROP INDEX sensors_group_members;
ALTER TABLE sensors DROP COLUMN metadata_revision, DROP COLUMN group_id, DROP COLUMN site, DROP COLUMN description, DROP COLUMN metadata_updated_at;
DROP TABLE sensor_groups;
