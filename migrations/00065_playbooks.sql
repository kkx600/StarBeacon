-- +goose Up
CREATE TABLE playbooks (
 tenant_id text NOT NULL REFERENCES tenants(id), id text NOT NULL,
 owner_id text NOT NULL REFERENCES users(id),
 revision bigint NOT NULL CHECK(revision BETWEEN 1 AND 256),
 published_revision bigint NOT NULL DEFAULT 0 CHECK(published_revision BETWEEN 0 AND revision),
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,id)
);
CREATE TABLE playbook_revisions (
 tenant_id text NOT NULL, playbook_id text NOT NULL, revision bigint NOT NULL CHECK(revision BETWEEN 1 AND 256),
 owner_id text NOT NULL REFERENCES users(id), key_hash text NOT NULL CHECK(key_hash ~ '^[a-f0-9]{64}$'),
 definition jsonb NOT NULL CHECK(jsonb_typeof(definition)='object'), sha256 text NOT NULL CHECK(sha256 ~ '^[a-f0-9]{64}$'),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,playbook_id,revision), UNIQUE(tenant_id,owner_id,key_hash),
 FOREIGN KEY(tenant_id,playbook_id) REFERENCES playbooks(tenant_id,id)
);
CREATE TABLE playbook_runs (
 tenant_id text NOT NULL, id text NOT NULL, owner_id text NOT NULL REFERENCES users(id),
 playbook_id text NOT NULL, revision bigint NOT NULL,
 key_hash text NOT NULL CHECK(key_hash ~ '^[a-f0-9]{64}$'), alert jsonb NOT NULL CHECK(jsonb_typeof(alert)='object'),
 results jsonb NOT NULL CHECK(jsonb_typeof(results)='array' AND jsonb_array_length(results) BETWEEN 1 AND 16),
 created_at timestamptz NOT NULL, expires_at timestamptz NOT NULL CHECK(expires_at>created_at),
 PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,owner_id,key_hash),
 FOREIGN KEY(tenant_id,playbook_id,revision) REFERENCES playbook_revisions(tenant_id,playbook_id,revision)
);
CREATE INDEX playbook_run_owner ON playbook_runs(tenant_id,owner_id,created_at DESC,id DESC);
CREATE INDEX playbook_run_expiry ON playbook_runs(tenant_id,expires_at);
ALTER TABLE gateway_block_requests ADD COLUMN playbook_run_id text;

ALTER TABLE playbooks ENABLE ROW LEVEL SECURITY;
ALTER TABLE playbooks FORCE ROW LEVEL SECURITY;
CREATE POLICY playbooks_scope ON playbooks USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
ALTER TABLE playbook_revisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE playbook_revisions FORCE ROW LEVEL SECURITY;
CREATE POLICY playbook_revisions_scope ON playbook_revisions USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
ALTER TABLE playbook_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE playbook_runs FORCE ROW LEVEL SECURITY;
CREATE POLICY playbook_runs_scope ON playbook_runs USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
CREATE POLICY playbook_runs_expiry_delete ON playbook_runs AS RESTRICTIVE FOR DELETE USING(expires_at<=now());
ALTER TABLE retention_maintenance DROP CONSTRAINT retention_maintenance_next_category_check;
ALTER TABLE retention_maintenance ADD CONSTRAINT retention_maintenance_next_category_check CHECK(next_category BETWEEN 0 AND 51);

-- +goose Down
UPDATE retention_maintenance SET next_category=0 WHERE next_category>50;
ALTER TABLE retention_maintenance DROP CONSTRAINT retention_maintenance_next_category_check;
ALTER TABLE retention_maintenance ADD CONSTRAINT retention_maintenance_next_category_check CHECK(next_category BETWEEN 0 AND 50);
DROP TABLE playbook_runs;
ALTER TABLE gateway_block_requests DROP COLUMN playbook_run_id;
DROP TABLE playbook_revisions;
DROP TABLE playbooks;
