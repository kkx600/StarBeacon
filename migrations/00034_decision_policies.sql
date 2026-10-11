-- +goose Up
CREATE TABLE decision_policies (
 tenant_id text NOT NULL REFERENCES tenants(id), id text NOT NULL,
 revision bigint NOT NULL CHECK(revision BETWEEN 1 AND 1000000),
 name text NOT NULL CHECK(char_length(name) BETWEEN 1 AND 128), active boolean NOT NULL,
 PRIMARY KEY(tenant_id,id)
);
CREATE TABLE decision_policy_revisions (
 tenant_id text NOT NULL REFERENCES tenants(id), policy_id text NOT NULL,
 revision bigint NOT NULL CHECK(revision BETWEEN 1 AND 1000000),
 name text NOT NULL CHECK(char_length(name) BETWEEN 1 AND 128),
 description text NOT NULL CHECK(char_length(description)<=1000), active boolean NOT NULL,
 definition jsonb NOT NULL CHECK(jsonb_typeof(definition)='object' AND octet_length(definition::text)<=32768),
 definition_sha256 text NOT NULL CHECK(definition_sha256 ~ '^[a-f0-9]{64}$'),
 created_by text NOT NULL REFERENCES users(id), key_hash text NOT NULL, input_hash text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,policy_id,revision), UNIQUE(tenant_id,created_by,key_hash),
 CHECK(expires_at>created_at),
 FOREIGN KEY(tenant_id,policy_id) REFERENCES decision_policies(tenant_id,id) DEFERRABLE INITIALLY DEFERRED
);
ALTER TABLE decision_policies ADD CONSTRAINT decision_policy_current FOREIGN KEY(tenant_id,id,revision) REFERENCES decision_policy_revisions(tenant_id,policy_id,revision) DEFERRABLE INITIALLY DEFERRED;
CREATE INDEX decision_policy_expiry ON decision_policy_revisions(tenant_id,expires_at);
CREATE INDEX decision_policy_budget ON decision_policy_revisions(tenant_id,created_at);
ALTER TABLE decision_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE decision_policies FORCE ROW LEVEL SECURITY;
CREATE POLICY decision_policy_scope ON decision_policies USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
ALTER TABLE decision_policy_revisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE decision_policy_revisions FORCE ROW LEVEL SECURITY;
CREATE POLICY decision_policy_revision_scope ON decision_policy_revisions USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
CREATE POLICY decision_policy_revision_expiry_delete ON decision_policy_revisions AS RESTRICTIVE FOR DELETE USING(expires_at<=now() AND NOT EXISTS(SELECT 1 FROM decision_policies h WHERE h.tenant_id=decision_policy_revisions.tenant_id AND h.id=decision_policy_revisions.policy_id AND h.revision=decision_policy_revisions.revision));
ALTER TABLE retention_maintenance DROP CONSTRAINT retention_maintenance_next_category_check;
ALTER TABLE retention_maintenance ADD CONSTRAINT retention_maintenance_next_category_check CHECK(next_category BETWEEN 0 AND 27);
-- +goose Down
UPDATE retention_maintenance SET next_category=0 WHERE next_category>26;
ALTER TABLE retention_maintenance DROP CONSTRAINT retention_maintenance_next_category_check;
ALTER TABLE retention_maintenance ADD CONSTRAINT retention_maintenance_next_category_check CHECK(next_category BETWEEN 0 AND 26);
ALTER TABLE decision_policies DROP CONSTRAINT decision_policy_current;
DROP TABLE decision_policy_revisions;
DROP TABLE decision_policies;
