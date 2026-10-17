-- +goose Up
CREATE TABLE rule_sync_plans (
 tenant_id text NOT NULL REFERENCES tenants(id), id text NOT NULL,
 sensor_id text NOT NULL, registration_id text NOT NULL,
 revision bigint NOT NULL CHECK(revision>0), created_by text NOT NULL REFERENCES users(id),
 spec jsonb NOT NULL, enabled boolean NOT NULL,
 processed_revision bigint NOT NULL DEFAULT 0 CHECK(processed_revision>=0),
 updated_at timestamptz NOT NULL DEFAULT now(), next_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,sensor_id),
 FOREIGN KEY(tenant_id,sensor_id) REFERENCES sensors(tenant_id,id)
);
CREATE TABLE rule_sync_runs (
 tenant_id text NOT NULL, id text NOT NULL, plan_id text NOT NULL, plan_revision bigint NOT NULL,
 spec jsonb NOT NULL, created_by text NOT NULL REFERENCES users(id),
 state text NOT NULL CHECK(state IN ('pending','validating','positive_replay','negative_replay','applying','succeeded','blocked','paused')),
 code text NOT NULL DEFAULT '', stage integer NOT NULL DEFAULT 0 CHECK(stage BETWEEN 0 AND 4),
 tasks jsonb NOT NULL DEFAULT '["","","",""]', expected_sha256 text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(), finished_at timestamptz,
 expires_at timestamptz NOT NULL CHECK(expires_at>created_at),
 PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,plan_id,plan_revision),
 FOREIGN KEY(tenant_id,plan_id) REFERENCES rule_sync_plans(tenant_id,id),
 CHECK((state IN ('succeeded','blocked','paused'))=(finished_at IS NOT NULL))
);
CREATE UNIQUE INDEX rule_sync_running ON rule_sync_runs(tenant_id,plan_id) WHERE finished_at IS NULL;
CREATE INDEX rule_sync_due ON rule_sync_plans(tenant_id,next_at,id);
CREATE INDEX rule_sync_history ON rule_sync_runs(tenant_id,plan_id,created_at,id);
CREATE INDEX rule_sync_expiry ON rule_sync_runs(tenant_id,expires_at);
CREATE INDEX rule_sync_task_refs ON rule_sync_runs USING gin(tasks);
ALTER TABLE rule_sync_plans ENABLE ROW LEVEL SECURITY;
ALTER TABLE rule_sync_plans FORCE ROW LEVEL SECURITY;
CREATE POLICY rule_sync_plan_scope ON rule_sync_plans USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
ALTER TABLE rule_sync_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE rule_sync_runs FORCE ROW LEVEL SECURITY;
CREATE POLICY rule_sync_run_scope ON rule_sync_runs USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
CREATE POLICY rule_sync_expiry_delete ON rule_sync_runs AS RESTRICTIVE FOR DELETE USING(expires_at<=now() AND finished_at IS NOT NULL);
CREATE POLICY rule_sync_task_protection ON sensor_tasks AS RESTRICTIVE FOR DELETE USING(NOT EXISTS(SELECT 1 FROM rule_sync_runs r WHERE r.tenant_id=sensor_tasks.tenant_id AND r.tasks ? sensor_tasks.id AND (r.finished_at IS NULL OR r.expires_at>now())));
ALTER TABLE retention_maintenance DROP CONSTRAINT retention_maintenance_next_category_check;
ALTER TABLE retention_maintenance ADD CONSTRAINT retention_maintenance_next_category_check CHECK(next_category BETWEEN 0 AND 32);
-- +goose Down
UPDATE retention_maintenance SET next_category=0 WHERE next_category>31;
ALTER TABLE retention_maintenance DROP CONSTRAINT retention_maintenance_next_category_check;
ALTER TABLE retention_maintenance ADD CONSTRAINT retention_maintenance_next_category_check CHECK(next_category BETWEEN 0 AND 31);
DROP POLICY rule_sync_task_protection ON sensor_tasks;
DROP TABLE rule_sync_runs,rule_sync_plans;
