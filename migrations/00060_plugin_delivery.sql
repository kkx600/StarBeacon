-- +goose Up
ALTER TABLE watchlist_hits DROP CONSTRAINT watchlist_hits_severity_check,
 ADD CONSTRAINT watchlist_hits_severity_check CHECK(severity IN('critical','high','medium','low','unknown'));

ALTER TABLE response_plugin_versions
 ALTER COLUMN template DROP NOT NULL,
 ALTER COLUMN template_sha256 DROP NOT NULL,
 ADD COLUMN script jsonb CHECK(jsonb_typeof(script)='object' AND octet_length(script::text)<=196608),
 ADD COLUMN script_sha256 text CHECK(script_sha256 ~ '^[a-f0-9]{64}$'),
 ADD COLUMN examples jsonb NOT NULL DEFAULT '[]' CHECK(jsonb_typeof(examples)='array' AND jsonb_array_length(examples)<=48 AND octet_length(examples::text)<=196608),
 ADD CONSTRAINT response_plugin_definition CHECK(
  (template IS NOT NULL AND template_sha256 IS NOT NULL AND script IS NULL AND script_sha256 IS NULL)
  OR (template IS NULL AND template_sha256 IS NULL AND script IS NOT NULL AND script_sha256 IS NOT NULL)
 );

CREATE TABLE response_plugin_jobs (
 tenant_id text NOT NULL, task_id text NOT NULL, plugin_id text NOT NULL, version integer NOT NULL,
 sensor_id text NOT NULL, registration_id text NOT NULL,
 operation text NOT NULL CHECK(operation IN ('simulate','read','capability','publish','rollback','disable')),
 binding_sha256 text NOT NULL CHECK(binding_sha256 ~ '^[a-f0-9]{64}$'),
 request_sha256 text NOT NULL CHECK(request_sha256 ~ '^[a-f0-9]{64}$'),
 PRIMARY KEY(tenant_id,task_id),
 FOREIGN KEY(tenant_id,task_id) REFERENCES sensor_tasks(tenant_id,id) ON DELETE CASCADE,
 FOREIGN KEY(tenant_id,plugin_id,version) REFERENCES response_plugin_versions(tenant_id,plugin_id,version)
);
CREATE INDEX response_plugin_jobs_scope ON response_plugin_jobs(tenant_id,plugin_id,sensor_id,registration_id,version,operation,binding_sha256);

CREATE TABLE response_plugin_assignments (
 tenant_id text NOT NULL, plugin_id text NOT NULL CHECK(plugin_id ~ '^[a-z0-9][a-z0-9_-]{0,63}$'), sensor_id text NOT NULL,
 registration_id text NOT NULL, generation bigint NOT NULL CHECK(generation>0),
 current_artifact jsonb CHECK(jsonb_typeof(current_artifact)='object' AND octet_length(current_artifact::text)<=262144),
 previous_artifact jsonb CHECK(jsonb_typeof(previous_artifact)='object' AND octet_length(previous_artifact::text)<=262144),
 updated_at timestamptz NOT NULL DEFAULT now(),
 CHECK(current_artifact IS NOT NULL OR previous_artifact IS NOT NULL),
 PRIMARY KEY(tenant_id,plugin_id,sensor_id,registration_id),
 FOREIGN KEY(tenant_id,sensor_id,registration_id) REFERENCES sensors(tenant_id,id,registration_id)
);

ALTER TABLE response_plugin_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE response_plugin_jobs FORCE ROW LEVEL SECURITY;
CREATE POLICY response_plugin_job_scope ON response_plugin_jobs
 USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
ALTER TABLE response_plugin_assignments ENABLE ROW LEVEL SECURITY;
ALTER TABLE response_plugin_assignments FORCE ROW LEVEL SECURITY;
CREATE POLICY response_plugin_assignment_scope ON response_plugin_assignments
 USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));

-- +goose Down
ALTER TABLE watchlist_hits DROP CONSTRAINT watchlist_hits_severity_check,
 ADD CONSTRAINT watchlist_hits_severity_check CHECK(severity IN('high','medium','low','unknown'));
DROP TABLE response_plugin_assignments, response_plugin_jobs;
-- 仅在仍可由上一版解释全部草稿时执行回退。
ALTER TABLE response_plugin_versions
 ALTER COLUMN template SET NOT NULL,
 ALTER COLUMN template_sha256 SET NOT NULL,
 DROP CONSTRAINT response_plugin_definition,
 DROP COLUMN examples,
 DROP COLUMN script_sha256,
 DROP COLUMN script;
