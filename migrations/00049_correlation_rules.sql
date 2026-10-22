-- +goose Up
CREATE TABLE correlation_rules (
 tenant_id text NOT NULL REFERENCES tenants(id), id text NOT NULL,
 revision bigint NOT NULL CHECK(revision BETWEEN 1 AND 1000000),
 name text NOT NULL CHECK(char_length(name) BETWEEN 1 AND 128), active boolean NOT NULL,
 PRIMARY KEY(tenant_id,id)
);
CREATE TABLE correlation_rule_revisions (
 tenant_id text NOT NULL REFERENCES tenants(id), rule_id text NOT NULL,
 revision bigint NOT NULL CHECK(revision BETWEEN 1 AND 1000000),
 name text NOT NULL CHECK(char_length(name) BETWEEN 1 AND 128),
 description text NOT NULL CHECK(char_length(description)<=1000), active boolean NOT NULL,
 definition jsonb NOT NULL CHECK(jsonb_typeof(definition)='object' AND octet_length(definition::text)<=32768),
 definition_sha256 text NOT NULL CHECK(definition_sha256 ~ '^[a-f0-9]{64}$'),
 created_by text NOT NULL REFERENCES users(id), key_hash text NOT NULL, input_hash text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL CHECK(expires_at>created_at),
 PRIMARY KEY(tenant_id,rule_id,revision), UNIQUE(tenant_id,created_by,key_hash),
 FOREIGN KEY(tenant_id,rule_id) REFERENCES correlation_rules(tenant_id,id) DEFERRABLE INITIALLY DEFERRED
);
ALTER TABLE correlation_rules ADD CONSTRAINT correlation_rule_current FOREIGN KEY(tenant_id,id,revision) REFERENCES correlation_rule_revisions(tenant_id,rule_id,revision) DEFERRABLE INITIALLY DEFERRED;
CREATE INDEX correlation_rule_expiry ON correlation_rule_revisions(tenant_id,expires_at);
CREATE INDEX correlation_rule_budget ON correlation_rule_revisions(tenant_id,created_at);
ALTER TABLE correlation_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE correlation_rules FORCE ROW LEVEL SECURITY;
CREATE POLICY correlation_rule_scope ON correlation_rules USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
ALTER TABLE correlation_rule_revisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE correlation_rule_revisions FORCE ROW LEVEL SECURITY;
CREATE POLICY correlation_rule_revision_scope ON correlation_rule_revisions USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
CREATE POLICY correlation_rule_revision_expiry ON correlation_rule_revisions AS RESTRICTIVE FOR DELETE USING(expires_at<=now() AND NOT EXISTS(SELECT 1 FROM correlation_rules h WHERE h.tenant_id=correlation_rule_revisions.tenant_id AND h.id=correlation_rule_revisions.rule_id AND h.revision=correlation_rule_revisions.revision));
ALTER TABLE retention_maintenance DROP CONSTRAINT retention_maintenance_next_category_check;
ALTER TABLE retention_maintenance ADD CONSTRAINT retention_maintenance_next_category_check CHECK(next_category BETWEEN 0 AND 40);
-- +goose Down
UPDATE retention_maintenance SET next_category=LEAST(next_category,39);
ALTER TABLE retention_maintenance DROP CONSTRAINT retention_maintenance_next_category_check;
ALTER TABLE retention_maintenance ADD CONSTRAINT retention_maintenance_next_category_check CHECK(next_category BETWEEN 0 AND 39);
ALTER TABLE correlation_rules DROP CONSTRAINT correlation_rule_current;
DROP TABLE correlation_rule_revisions,correlation_rules;
