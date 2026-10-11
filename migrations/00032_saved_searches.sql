-- +goose Up
CREATE TABLE saved_searches (
 tenant_id text NOT NULL REFERENCES tenants(id), id text NOT NULL,
 generation_id text NOT NULL, owner_id text NOT NULL REFERENCES users(id),
 revision bigint NOT NULL CHECK(revision BETWEEN 1 AND 1000000), name text NOT NULL,
 description text NOT NULL, visibility text NOT NULL CHECK(visibility IN('personal','team')),
 dataset text NOT NULL CHECK(dataset IN('alerts','context')), active boolean NOT NULL,
 definition jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
 expires_at timestamptz, PRIMARY KEY(tenant_id,id),
 CHECK(char_length(name) BETWEEN 1 AND 128), CHECK(char_length(description)<=1000),
 CHECK((active AND expires_at IS NULL) OR (NOT active AND expires_at>updated_at))
);
CREATE INDEX saved_search_owner ON saved_searches(tenant_id,owner_id,dataset,id);
CREATE INDEX saved_search_team ON saved_searches(tenant_id,dataset,id) WHERE visibility='team';
CREATE INDEX saved_search_expiry ON saved_searches(tenant_id,expires_at) WHERE NOT active;
ALTER TABLE saved_searches ENABLE ROW LEVEL SECURITY;
ALTER TABLE saved_searches FORCE ROW LEVEL SECURITY;
CREATE POLICY saved_search_scope ON saved_searches USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
CREATE POLICY saved_search_expiry_delete ON saved_searches AS RESTRICTIVE FOR DELETE USING(NOT active AND expires_at<=now());
CREATE TABLE saved_search_changes (
 tenant_id text NOT NULL REFERENCES tenants(id), created_by text NOT NULL REFERENCES users(id),
 key_hash text NOT NULL, query_id text NOT NULL, generation_id text NOT NULL,
 revision bigint NOT NULL CHECK(revision BETWEEN 1 AND 1000000), input_hash text NOT NULL,
 record jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,query_id,generation_id,revision), UNIQUE(tenant_id,created_by,key_hash)
);
CREATE INDEX saved_search_change_expiry ON saved_search_changes(tenant_id,expires_at);
CREATE INDEX saved_search_change_budget ON saved_search_changes(tenant_id,created_at);
ALTER TABLE saved_search_changes ENABLE ROW LEVEL SECURITY;
ALTER TABLE saved_search_changes FORCE ROW LEVEL SECURITY;
CREATE POLICY saved_search_change_scope ON saved_search_changes USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
CREATE POLICY saved_search_change_expiry_delete ON saved_search_changes AS RESTRICTIVE FOR DELETE USING(expires_at<=now());
ALTER TABLE retention_maintenance DROP CONSTRAINT retention_maintenance_next_category_check;
ALTER TABLE retention_maintenance ADD CONSTRAINT retention_maintenance_next_category_check CHECK(next_category BETWEEN 0 AND 25);
-- +goose Down
UPDATE retention_maintenance SET next_category=0 WHERE next_category>23;
ALTER TABLE retention_maintenance DROP CONSTRAINT retention_maintenance_next_category_check;
ALTER TABLE retention_maintenance ADD CONSTRAINT retention_maintenance_next_category_check CHECK(next_category BETWEEN 0 AND 23);
DROP TABLE saved_search_changes;
DROP TABLE saved_searches;
