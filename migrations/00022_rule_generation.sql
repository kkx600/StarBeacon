-- +goose Up
CREATE TABLE rule_generation_jobs (
 tenant_id text NOT NULL REFERENCES tenants(id), id text NOT NULL, created_by text NOT NULL,
 provider_id text NOT NULL, provider_revision bigint NOT NULL,
 sample_id text, sample_sha256 text,
 request jsonb NOT NULL, request_hash text NOT NULL, idempotency_key_hash text NOT NULL,
 template text NOT NULL, evidence jsonb NOT NULL, assigned_sids jsonb NOT NULL,
 prompt text NOT NULL, prompt_hash text NOT NULL,
 candidates jsonb NOT NULL DEFAULT '[]', result jsonb NOT NULL DEFAULT '{"state":"queued","code":"awaiting_execution","usage":null,"duration_ms":null}',
 state text NOT NULL CHECK(state IN ('queued','running','succeeded','failed','refused','incomplete','uncertain','cancelled')),
 cancel_requested boolean NOT NULL DEFAULT false, river_job_id bigint,
 lease_token text, deadline timestamptz NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(), started_at timestamptz, finished_at timestamptz,
 expires_at timestamptz NOT NULL DEFAULT now()+interval '180 days',
 PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,created_by,idempotency_key_hash),
 FOREIGN KEY(tenant_id,provider_id,provider_revision) REFERENCES model_provider_versions(tenant_id,provider_id,revision),
 CHECK((sample_id IS NULL)=(sample_sha256 IS NULL))
);
CREATE INDEX rule_generation_owner ON rule_generation_jobs(tenant_id,created_by,created_at DESC,id DESC);
CREATE INDEX rule_generation_quota ON rule_generation_jobs(tenant_id,provider_id,created_at);
CREATE INDEX rule_generation_cleanup ON rule_generation_jobs(tenant_id,expires_at,id) WHERE state NOT IN ('queued','running');
CREATE INDEX rule_generation_sample ON rule_generation_jobs(tenant_id,sample_id) WHERE state IN ('queued','running');

-- SID 注册属于当前命名空间，历史到期后也不重新分配给不同规则。
CREATE TABLE rule_sid_registry (
 tenant_id text NOT NULL REFERENCES tenants(id), sid bigint NOT NULL CHECK(sid BETWEEN 1000000 AND 1999999),
 package_id text NOT NULL, generation_id text, created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(tenant_id,sid)
);
CREATE TABLE rule_sid_state (
 tenant_id text PRIMARY KEY REFERENCES tenants(id),
 next_sid bigint NOT NULL DEFAULT 1000000 CHECK(next_sid BETWEEN 1000000 AND 2000000)
);

ALTER TABLE rule_packages ADD COLUMN generation_id text;
ALTER TABLE rule_packages ADD COLUMN generation_sid bigint;
ALTER TABLE rule_packages ADD CONSTRAINT rule_package_generation_ref FOREIGN KEY(tenant_id,generation_id) REFERENCES rule_generation_jobs(tenant_id,id);
ALTER TABLE rule_packages ADD CONSTRAINT rule_package_generation_check CHECK((generation_id IS NULL)=(generation_sid IS NULL));

ALTER TABLE rule_generation_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE rule_generation_jobs FORCE ROW LEVEL SECURITY;
CREATE POLICY rule_generation_scope ON rule_generation_jobs USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
CREATE POLICY rule_generation_expiry_delete ON rule_generation_jobs AS RESTRICTIVE FOR DELETE USING(expires_at<=now() AND state NOT IN ('queued','running') AND NOT EXISTS(SELECT 1 FROM starbeacon_jobs.river_job j WHERE j.id=river_job_id AND j.state NOT IN ('completed','cancelled','discarded')));
ALTER TABLE rule_sid_registry ENABLE ROW LEVEL SECURITY;
ALTER TABLE rule_sid_registry FORCE ROW LEVEL SECURITY;
CREATE POLICY rule_sid_scope ON rule_sid_registry USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
ALTER TABLE rule_sid_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE rule_sid_state FORCE ROW LEVEL SECURITY;
CREATE POLICY rule_sid_state_scope ON rule_sid_state USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));

-- 保守登记既有保留区 SID；正文中的同形字符串宁可占用，不分配可能冲突的标识。
-- +goose StatementBegin
DO $$
DECLARE scope text;
BEGIN
 FOR scope IN SELECT id FROM tenants ORDER BY id LOOP
  PERFORM set_config('starbeacon.tenant_id',scope,true);
  INSERT INTO rule_sid_registry(tenant_id,sid,package_id)
   SELECT scope,m[1]::bigint,min(p.id) FROM rule_packages p,
    LATERAL regexp_matches(p.rules_text,'(?:^|[;[:space:]])sid[[:space:]]*:[[:space:]]*(1[0-9]{6})[[:space:]]*;','g') m
   WHERE p.tenant_id=scope GROUP BY m[1] ON CONFLICT DO NOTHING;
 END LOOP;
 PERFORM set_config('starbeacon.tenant_id','',true);
END $$;
-- +goose StatementEnd

ALTER TABLE retention_maintenance DROP CONSTRAINT retention_maintenance_next_category_check;
ALTER TABLE retention_maintenance ADD CONSTRAINT retention_maintenance_next_category_check CHECK(next_category BETWEEN 0 AND 18);
-- +goose Down
ALTER TABLE retention_maintenance DROP CONSTRAINT retention_maintenance_next_category_check;
UPDATE retention_maintenance SET next_category=0 WHERE next_category>17;
ALTER TABLE retention_maintenance ADD CONSTRAINT retention_maintenance_next_category_check CHECK(next_category BETWEEN 0 AND 17);
ALTER TABLE rule_packages DROP COLUMN generation_sid;
ALTER TABLE rule_packages DROP COLUMN generation_id;
DROP TABLE rule_sid_state,rule_sid_registry,rule_generation_jobs;
