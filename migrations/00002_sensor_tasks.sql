-- +goose Up
CREATE TABLE sensor_tasks (
  tenant_id text NOT NULL REFERENCES tenants(id), id text NOT NULL,
  sensor_id text NOT NULL, registration_id text NOT NULL, kind text NOT NULL,
  state text NOT NULL DEFAULT 'queued' CHECK(state IN ('queued','delivered','running','succeeded','failed','unknown','expired','cancelled')),
  idempotency_key text NOT NULL, request_sha256 text NOT NULL,
  command bytea NOT NULL, signature bytea NOT NULL, command_sha256 text NOT NULL,
  receipt jsonb, created_by text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL, last_delivery_at timestamptz, delivery_count integer NOT NULL DEFAULT 0,
  updated_at timestamptz NOT NULL DEFAULT now(), retain_until timestamptz NOT NULL DEFAULT now()+interval '180 days',
  PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,idempotency_key),
  FOREIGN KEY(tenant_id,sensor_id,registration_id) REFERENCES sensors(tenant_id,id,registration_id)
);
CREATE INDEX sensor_tasks_delivery ON sensor_tasks(tenant_id,sensor_id,created_at) WHERE state IN ('queued','delivered');
CREATE UNIQUE INDEX sensor_tasks_serial ON sensor_tasks(tenant_id,sensor_id) WHERE state IN ('queued','delivered','running');
CREATE TABLE rule_packages (
  tenant_id text NOT NULL REFERENCES tenants(id), id text NOT NULL, name text NOT NULL,
  revision bigint NOT NULL, engine_version text NOT NULL, rules_text text NOT NULL, sha256 text NOT NULL,
  created_by text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(tenant_id,id,revision), CHECK(octet_length(rules_text)<=921600)
);
ALTER TABLE sensor_tasks ENABLE ROW LEVEL SECURITY;
ALTER TABLE sensor_tasks FORCE ROW LEVEL SECURITY;
CREATE POLICY task_scope ON sensor_tasks USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
ALTER TABLE rule_packages ENABLE ROW LEVEL SECURITY;
ALTER TABLE rule_packages FORCE ROW LEVEL SECURITY;
CREATE POLICY package_scope ON rule_packages USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));

-- +goose Down
DROP TABLE sensor_tasks,rule_packages;
