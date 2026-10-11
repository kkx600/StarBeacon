-- +goose Up
CREATE TABLE report_plans (
 tenant_id text NOT NULL REFERENCES tenants(id), id text NOT NULL, created_by text NOT NULL,
 revision bigint NOT NULL CHECK(revision>0 AND revision<9007199254740992), spec jsonb NOT NULL,
 provider_id text, provider_revision bigint,
 next_at timestamptz, river_job_id bigint, updated_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(tenant_id,id),
 FOREIGN KEY(tenant_id,provider_id,provider_revision) REFERENCES model_provider_versions(tenant_id,provider_id,revision),
 CHECK((provider_id IS NULL)=(provider_revision IS NULL)),
 CHECK((next_at IS NULL)=(river_job_id IS NULL))
);
CREATE INDEX report_plan_owner ON report_plans(tenant_id,created_by,updated_at DESC,id DESC);
CREATE INDEX report_plan_provider ON report_plans(tenant_id,provider_id,provider_revision);
CREATE TABLE report_plan_runs (
 tenant_id text NOT NULL, id text NOT NULL, plan_id text NOT NULL, created_by text NOT NULL,
 plan_revision bigint NOT NULL, due_at timestamptz NOT NULL, effective_at timestamptz NOT NULL,
 skipped_from timestamptz, skipped_until timestamptz,
 request jsonb NOT NULL, provider_id text, provider_revision bigint,
 state text NOT NULL CHECK(state IN ('preparing','submitted','failed','cancelled')),
 code text NOT NULL DEFAULT '', analysis_id text, river_job_id bigint NOT NULL,
 deadline timestamptz NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), finished_at timestamptz,
 expires_at timestamptz NOT NULL DEFAULT now()+interval '180 days',
 PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,plan_id,plan_revision,due_at),
 FOREIGN KEY(tenant_id,plan_id) REFERENCES report_plans(tenant_id,id),
 FOREIGN KEY(tenant_id,analysis_id) REFERENCES analysis_jobs(tenant_id,id),
 FOREIGN KEY(tenant_id,provider_id,provider_revision) REFERENCES model_provider_versions(tenant_id,provider_id,revision),
 CHECK((provider_id IS NULL)=(provider_revision IS NULL)),
 CHECK((skipped_from IS NULL)=(skipped_until IS NULL)),
 CHECK(skipped_until IS NULL OR skipped_until>skipped_from), CHECK(effective_at>=due_at),
 CHECK((state='submitted')=(analysis_id IS NOT NULL))
);
CREATE INDEX report_plan_run_page ON report_plan_runs(tenant_id,plan_id,created_by,created_at DESC,id DESC);
CREATE INDEX report_plan_run_expiry ON report_plan_runs(tenant_id,expires_at);
CREATE INDEX report_plan_run_analysis ON report_plan_runs(tenant_id,analysis_id);
CREATE INDEX report_plan_run_provider ON report_plan_runs(tenant_id,provider_id,provider_revision);
ALTER TABLE report_plans ENABLE ROW LEVEL SECURITY;
ALTER TABLE report_plans FORCE ROW LEVEL SECURITY;
CREATE POLICY report_plan_scope ON report_plans USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
ALTER TABLE report_plan_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE report_plan_runs FORCE ROW LEVEL SECURITY;
CREATE POLICY report_plan_run_scope ON report_plan_runs USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
-- +goose Down
DROP TABLE report_plan_runs,report_plans;
