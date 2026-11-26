-- +goose Up
CREATE TABLE gateway_block_settings (
 tenant_id text PRIMARY KEY REFERENCES tenants(id), revision bigint NOT NULL CHECK(revision>0),
 enabled boolean NOT NULL, per_minute integer NOT NULL CHECK(per_minute BETWEEN 1 AND 60),
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE gateway_block_policies (
 tenant_id text NOT NULL REFERENCES tenants(id), id text NOT NULL, revision bigint NOT NULL CHECK(revision>0),
 definition jsonb NOT NULL CHECK(jsonb_typeof(definition)='object'), author_id text NOT NULL,
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,id)
);
CREATE INDEX gateway_block_rule_policies ON gateway_block_policies(tenant_id,id)
 WHERE definition->>'trigger'='rule' AND definition->>'enabled'='true';
CREATE TABLE gateway_block_requests (
 tenant_id text NOT NULL REFERENCES tenants(id), id text NOT NULL,
 event_id text NOT NULL CHECK(event_id ~ '^[a-f0-9]{64}$'), raw_sha256 text NOT NULL CHECK(raw_sha256 ~ '^[a-f0-9]{64}$'),
 policy_id text NOT NULL, policy_revision bigint NOT NULL CHECK(policy_revision>0),
 sensor_id text NOT NULL, registration_id text NOT NULL, trigger text NOT NULL CHECK(trigger IN ('rule','review')),
 rule_id text NOT NULL, rule_revision text NOT NULL, assessment_revision bigint NOT NULL DEFAULT 0,
 actor_id text NOT NULL, client_key_hash text, flow jsonb NOT NULL CHECK(jsonb_typeof(flow)='object'), flow_key text NOT NULL,
 state text NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','denied','authorized')), code text NOT NULL DEFAULT '',
 observed_at timestamptz NOT NULL, event_at timestamptz NOT NULL, received_at timestamptz NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(), deadline timestamptz NOT NULL,
 task_id text, authorized_at timestamptz, lease_until timestamptz, protection_sha256 text,
 expires_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,event_id), UNIQUE(tenant_id,actor_id,client_key_hash),
 CHECK((trigger='review')=(assessment_revision>0 AND client_key_hash IS NOT NULL)),
 CHECK((state='authorized')=(task_id IS NOT NULL AND authorized_at IS NOT NULL AND lease_until IS NOT NULL AND protection_sha256 IS NOT NULL))
);
CREATE INDEX gateway_block_pending ON gateway_block_requests(tenant_id,sensor_id,registration_id,created_at,id) WHERE state='pending';
CREATE INDEX gateway_block_budget ON gateway_block_requests(tenant_id,authorized_at) WHERE state='authorized';
CREATE INDEX gateway_block_active ON gateway_block_requests(tenant_id,sensor_id,registration_id,flow_key,lease_until) WHERE state='authorized';
CREATE INDEX gateway_block_history_expiry ON gateway_block_requests(tenant_id,expires_at,id);

ALTER TABLE gateway_block_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE gateway_block_settings FORCE ROW LEVEL SECURITY;
CREATE POLICY gateway_block_settings_scope ON gateway_block_settings
 USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
ALTER TABLE gateway_block_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE gateway_block_policies FORCE ROW LEVEL SECURITY;
CREATE POLICY gateway_block_policies_scope ON gateway_block_policies
 USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
ALTER TABLE gateway_block_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE gateway_block_requests FORCE ROW LEVEL SECURITY;
CREATE POLICY gateway_block_requests_scope ON gateway_block_requests
 USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
CREATE POLICY gateway_block_requests_expiry ON gateway_block_requests AS RESTRICTIVE FOR DELETE USING(expires_at<=now());

ALTER TABLE retention_maintenance DROP CONSTRAINT retention_maintenance_next_category_check;
ALTER TABLE retention_maintenance ADD CONSTRAINT retention_maintenance_next_category_check CHECK(next_category BETWEEN 0 AND 49);

-- +goose Down
UPDATE retention_maintenance SET next_category=LEAST(next_category,47);
ALTER TABLE retention_maintenance DROP CONSTRAINT retention_maintenance_next_category_check;
ALTER TABLE retention_maintenance ADD CONSTRAINT retention_maintenance_next_category_check CHECK(next_category BETWEEN 0 AND 47);
DROP TABLE gateway_block_requests,gateway_block_policies,gateway_block_settings;
