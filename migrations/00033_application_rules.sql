-- +goose Up
CREATE TABLE application_rules (
 tenant_id text NOT NULL REFERENCES tenants(id), id text NOT NULL,
 revision bigint NOT NULL CHECK(revision BETWEEN 1 AND 1000000),
 name text NOT NULL CHECK(char_length(name) BETWEEN 1 AND 128), active boolean NOT NULL,
 PRIMARY KEY(tenant_id,id)
);
CREATE TABLE application_rule_revisions (
 tenant_id text NOT NULL REFERENCES tenants(id), rule_id text NOT NULL,
 revision bigint NOT NULL CHECK(revision BETWEEN 1 AND 1000000),
 name text NOT NULL CHECK(char_length(name) BETWEEN 1 AND 128),
 description text NOT NULL CHECK(char_length(description)<=1000), active boolean NOT NULL,
 definition jsonb NOT NULL CHECK(jsonb_typeof(definition)='object' AND octet_length(definition::text)<=32768),
 definition_sha256 text NOT NULL CHECK(definition_sha256 ~ '^[a-f0-9]{64}$'),
 created_by text NOT NULL REFERENCES users(id), key_hash text NOT NULL, input_hash text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,rule_id,revision), UNIQUE(tenant_id,created_by,key_hash),
 CHECK(expires_at>created_at),
 FOREIGN KEY(tenant_id,rule_id) REFERENCES application_rules(tenant_id,id) DEFERRABLE INITIALLY DEFERRED
);
ALTER TABLE application_rules ADD CONSTRAINT application_rule_current FOREIGN KEY(tenant_id,id,revision) REFERENCES application_rule_revisions(tenant_id,rule_id,revision) DEFERRABLE INITIALLY DEFERRED;
CREATE INDEX application_rule_expiry ON application_rule_revisions(tenant_id,expires_at);
CREATE INDEX application_rule_budget ON application_rule_revisions(tenant_id,created_at);
ALTER TABLE application_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE application_rules FORCE ROW LEVEL SECURITY;
CREATE POLICY application_rule_scope ON application_rules USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
ALTER TABLE application_rule_revisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE application_rule_revisions FORCE ROW LEVEL SECURITY;
CREATE POLICY application_rule_revision_scope ON application_rule_revisions USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
CREATE POLICY application_rule_revision_expiry_delete ON application_rule_revisions AS RESTRICTIVE FOR DELETE USING(expires_at<=now() AND NOT EXISTS(SELECT 1 FROM application_rules h WHERE h.tenant_id=application_rule_revisions.tenant_id AND h.id=application_rule_revisions.rule_id AND h.revision=application_rule_revisions.revision));
ALTER TABLE retention_maintenance DROP CONSTRAINT retention_maintenance_next_category_check;
ALTER TABLE retention_maintenance ADD CONSTRAINT retention_maintenance_next_category_check CHECK(next_category BETWEEN 0 AND 26);
-- +goose Down
UPDATE retention_maintenance SET next_category=0 WHERE next_category>25;
ALTER TABLE retention_maintenance DROP CONSTRAINT retention_maintenance_next_category_check;
ALTER TABLE retention_maintenance ADD CONSTRAINT retention_maintenance_next_category_check CHECK(next_category BETWEEN 0 AND 25);
ALTER TABLE application_rules DROP CONSTRAINT application_rule_current;
DROP TABLE application_rule_revisions;
DROP TABLE application_rules;
