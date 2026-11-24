-- +goose Up
CREATE TABLE packet_archive_flow_indexes (
 tenant_id text NOT NULL,
 archive_id text NOT NULL,
 object_version text NOT NULL,
 manifest_sha256 text NOT NULL CHECK (manifest_sha256 ~ '^[0-9a-f]{64}$'),
 index_sha256 text NOT NULL CHECK (index_sha256 ~ '^[0-9a-f]{64}$'),
 data bytea NOT NULL CHECK (octet_length(data) BETWEEN 1 AND 1048576),
 PRIMARY KEY (tenant_id,archive_id),
 FOREIGN KEY (tenant_id,archive_id) REFERENCES packet_archives(tenant_id,id) ON DELETE CASCADE
);
ALTER TABLE packet_archive_flow_indexes ENABLE ROW LEVEL SECURITY;
ALTER TABLE packet_archive_flow_indexes FORCE ROW LEVEL SECURITY;
CREATE POLICY packet_archive_flow_index_scope ON packet_archive_flow_indexes
 USING (tenant_id=current_setting('starbeacon.tenant_id',true))
 WITH CHECK (tenant_id=current_setting('starbeacon.tenant_id',true));

-- +goose Down
DROP TABLE packet_archive_flow_indexes;
