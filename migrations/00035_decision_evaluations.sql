-- +goose Up
CREATE TABLE decision_evaluations (
 tenant_id text NOT NULL REFERENCES tenants(id), id text NOT NULL,
 sequence bigint NOT NULL CHECK(sequence>0), created_by text NOT NULL REFERENCES users(id),
 policy_id text NOT NULL, triage_id text NOT NULL,
 status text NOT NULL CHECK(status IN ('matched','not_matched','protected','abstained')),
 created_at timestamptz NOT NULL, expires_at timestamptz NOT NULL CHECK(expires_at>created_at),
 key_hash text NOT NULL CHECK(key_hash ~ '^[a-f0-9]{64}$'), input_hash text NOT NULL CHECK(input_hash ~ '^[a-f0-9]{64}$'),
 record jsonb NOT NULL CHECK(jsonb_typeof(record)='object' AND octet_length(record::text)<=65536),
 PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,sequence), UNIQUE(tenant_id,created_by,key_hash)
);
CREATE INDEX decision_evaluation_owner ON decision_evaluations(tenant_id,created_by,sequence DESC);
CREATE INDEX decision_evaluation_policy ON decision_evaluations(tenant_id,created_by,policy_id,sequence DESC);
CREATE INDEX decision_evaluation_triage ON decision_evaluations(tenant_id,created_by,triage_id,sequence DESC);
CREATE INDEX decision_evaluation_expiry ON decision_evaluations(tenant_id,expires_at);
ALTER TABLE decision_evaluations ENABLE ROW LEVEL SECURITY;
ALTER TABLE decision_evaluations FORCE ROW LEVEL SECURITY;
CREATE POLICY decision_evaluation_scope ON decision_evaluations USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
CREATE POLICY decision_evaluation_expiry_delete ON decision_evaluations AS RESTRICTIVE FOR DELETE USING(expires_at<=now());
ALTER TABLE retention_maintenance DROP CONSTRAINT retention_maintenance_next_category_check;
ALTER TABLE retention_maintenance ADD CONSTRAINT retention_maintenance_next_category_check CHECK(next_category BETWEEN 0 AND 28);
-- +goose Down
UPDATE retention_maintenance SET next_category=0 WHERE next_category>27;
ALTER TABLE retention_maintenance DROP CONSTRAINT retention_maintenance_next_category_check;
ALTER TABLE retention_maintenance ADD CONSTRAINT retention_maintenance_next_category_check CHECK(next_category BETWEEN 0 AND 27);
DROP TABLE decision_evaluations;
