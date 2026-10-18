-- +goose Up
CREATE TABLE rule_rollouts (
 tenant_id text NOT NULL REFERENCES tenants(id),id text NOT NULL,
 spec jsonb NOT NULL,request_sha256 text NOT NULL,created_by text NOT NULL REFERENCES users(id),
 state text NOT NULL DEFAULT 'pending' CHECK(state IN('pending','running','observing','stopping','succeeded','stopped','blocked')),
 code text NOT NULL DEFAULT '',current_batch integer NOT NULL DEFAULT 0 CHECK(current_batch>=0),
 package_sha256 text NOT NULL CHECK(length(package_sha256)=64),
 created_at timestamptz NOT NULL DEFAULT now(),deadline timestamptz NOT NULL,
 next_at timestamptz NOT NULL DEFAULT now(),observation_started_at timestamptz,finished_at timestamptz,
 expires_at timestamptz NOT NULL CHECK(expires_at>created_at),
 stop_reason text NOT NULL DEFAULT '',stopped_by text NOT NULL DEFAULT '',
 PRIMARY KEY(tenant_id,id),
 CHECK((state IN('succeeded','stopped','blocked'))=(finished_at IS NOT NULL))
);
CREATE TABLE rule_rollout_targets (
 tenant_id text NOT NULL,rollout_id text NOT NULL,ordinal integer NOT NULL CHECK(ordinal BETWEEN 0 AND 199),
 batch integer NOT NULL CHECK(batch>=0),plan_id text NOT NULL,
 authorized_revision bigint NOT NULL CHECK(authorized_revision>0),execution_revision bigint NOT NULL DEFAULT 0 CHECK(execution_revision>=0),
 spec jsonb NOT NULL,state text NOT NULL DEFAULT 'queued' CHECK(state IN('queued','active','observing','succeeded','blocked','stopped')),
 code text NOT NULL DEFAULT '',released boolean NOT NULL DEFAULT false,
 PRIMARY KEY(tenant_id,rollout_id,ordinal),UNIQUE(tenant_id,rollout_id,plan_id),
 FOREIGN KEY(tenant_id,rollout_id) REFERENCES rule_rollouts(tenant_id,id) ON DELETE CASCADE,
 FOREIGN KEY(tenant_id,plan_id) REFERENCES rule_sync_plans(tenant_id,id)
);
CREATE UNIQUE INDEX rule_rollout_reservation ON rule_rollout_targets(tenant_id,plan_id) WHERE NOT released;
CREATE INDEX rule_rollout_due ON rule_rollouts(tenant_id,next_at,id) WHERE finished_at IS NULL;
CREATE INDEX rule_rollout_expiry ON rule_rollouts(tenant_id,expires_at,id);
ALTER TABLE rule_rollouts ENABLE ROW LEVEL SECURITY;
ALTER TABLE rule_rollouts FORCE ROW LEVEL SECURITY;
CREATE POLICY rule_rollout_scope ON rule_rollouts USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
CREATE POLICY rule_rollout_expiry ON rule_rollouts AS RESTRICTIVE FOR DELETE USING(expires_at<=now() AND finished_at IS NOT NULL);
ALTER TABLE rule_rollout_targets ENABLE ROW LEVEL SECURITY;
ALTER TABLE rule_rollout_targets FORCE ROW LEVEL SECURITY;
CREATE POLICY rule_rollout_target_scope ON rule_rollout_targets USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
CREATE POLICY rule_rollout_run_protection ON rule_sync_runs AS RESTRICTIVE FOR DELETE USING(NOT EXISTS(SELECT 1 FROM rule_rollout_targets t JOIN rule_rollouts r ON r.tenant_id=t.tenant_id AND r.id=t.rollout_id WHERE t.tenant_id=rule_sync_runs.tenant_id AND t.plan_id=rule_sync_runs.plan_id AND t.execution_revision=rule_sync_runs.plan_revision AND (r.finished_at IS NULL OR r.expires_at>now())));
ALTER TABLE retention_maintenance DROP CONSTRAINT retention_maintenance_next_category_check;
ALTER TABLE retention_maintenance ADD CONSTRAINT retention_maintenance_next_category_check CHECK(next_category BETWEEN 0 AND 39);
-- +goose Down
UPDATE retention_maintenance SET next_category=LEAST(next_category,38);
ALTER TABLE retention_maintenance DROP CONSTRAINT retention_maintenance_next_category_check;
ALTER TABLE retention_maintenance ADD CONSTRAINT retention_maintenance_next_category_check CHECK(next_category BETWEEN 0 AND 38);
DROP POLICY rule_rollout_run_protection ON rule_sync_runs;
DROP TABLE rule_rollout_targets,rule_rollouts;
