-- +goose Up
CREATE TABLE analysis_threads (
 tenant_id text NOT NULL REFERENCES tenants(id), id text NOT NULL, created_by text NOT NULL,
 title text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
 expires_at timestamptz NOT NULL DEFAULT now()+interval '180 days',
 PRIMARY KEY(tenant_id,id)
);
CREATE INDEX analysis_thread_owner ON analysis_threads(tenant_id,created_by,updated_at DESC,id DESC);
CREATE TABLE analysis_jobs (
 tenant_id text NOT NULL REFERENCES tenants(id), id text NOT NULL, created_by text NOT NULL,
 kind text NOT NULL CHECK(kind IN ('chat','daily','weekly','monthly')), thread_id text,
 provider_id text, provider_revision bigint, revision bigint NOT NULL CHECK(revision>0),
 period_start timestamptz NOT NULL, period_end timestamptz NOT NULL CHECK(period_end>period_start),
 request jsonb NOT NULL, request_hash text NOT NULL, idempotency_key_hash text NOT NULL,
 template text NOT NULL, evidence jsonb NOT NULL, prompt text NOT NULL DEFAULT '', prompt_hash text NOT NULL,
 answer jsonb, result jsonb NOT NULL DEFAULT '{}',
 state text NOT NULL CHECK(state IN ('queued','running','succeeded','failed','refused','incomplete','uncertain','cancelled')),
 cancel_requested boolean NOT NULL DEFAULT false, river_job_id bigint,
 lease_token text, deadline timestamptz,
 created_at timestamptz NOT NULL DEFAULT now(), started_at timestamptz, finished_at timestamptz,
 expires_at timestamptz NOT NULL DEFAULT now()+interval '180 days',
 PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,created_by,idempotency_key_hash),
 FOREIGN KEY(tenant_id,thread_id) REFERENCES analysis_threads(tenant_id,id),
 FOREIGN KEY(tenant_id,provider_id,provider_revision) REFERENCES model_provider_versions(tenant_id,provider_id,revision),
 CHECK((kind='chat')=(thread_id IS NOT NULL)), CHECK((provider_id IS NULL)=(provider_revision IS NULL))
);
CREATE UNIQUE INDEX analysis_report_revision ON analysis_jobs(tenant_id,kind,period_start,period_end,revision) WHERE kind<>'chat';
CREATE INDEX analysis_job_owner ON analysis_jobs(tenant_id,created_by,created_at DESC,id DESC);
CREATE INDEX analysis_job_quota ON analysis_jobs(tenant_id,provider_id,created_at);
CREATE INDEX analysis_job_thread ON analysis_jobs(tenant_id,thread_id,created_at DESC,id DESC);
ALTER TABLE analysis_threads ENABLE ROW LEVEL SECURITY;
ALTER TABLE analysis_threads FORCE ROW LEVEL SECURITY;
CREATE POLICY analysis_thread_scope ON analysis_threads USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
ALTER TABLE analysis_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE analysis_jobs FORCE ROW LEVEL SECURITY;
CREATE POLICY analysis_job_scope ON analysis_jobs USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
-- +goose Down
DROP TABLE analysis_jobs,analysis_threads;
