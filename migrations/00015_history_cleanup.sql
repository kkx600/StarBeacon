-- +goose Up
CREATE TABLE retention_maintenance (
 tenant_id text PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
 next_category integer NOT NULL DEFAULT 0 CHECK(next_category BETWEEN 0 AND 14),
 last_category text NOT NULL DEFAULT '', last_deleted integer NOT NULL DEFAULT 0 CHECK(last_deleted>=0),
 total_deleted bigint NOT NULL DEFAULT 0 CHECK(total_deleted>=0),
 checked_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE retention_maintenance ENABLE ROW LEVEL SECURITY;
ALTER TABLE retention_maintenance FORCE ROW LEVEL SECURITY;
CREATE POLICY retention_maintenance_scope ON retention_maintenance USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));

-- 未识别账号的登录尝试没有租户归属，仅允许未设置业务租户的维护事务回收。
CREATE POLICY login_anonymous_read_scope ON login_audits FOR SELECT USING(tenant_id IS NULL AND COALESCE(current_setting('starbeacon.tenant_id',true),'')='');
CREATE POLICY login_anonymous_delete_scope ON login_audits FOR DELETE USING(tenant_id IS NULL AND COALESCE(current_setting('starbeacon.tenant_id',true),'')='');
-- 在线角色的历史删除权限仅对到期记录生效；保留当前配置和未结束的执行事实。
CREATE POLICY operation_expiry_delete ON operation_audits AS RESTRICTIVE FOR DELETE USING(expires_at<=now());
CREATE POLICY login_expiry_delete ON login_audits AS RESTRICTIVE FOR DELETE USING(expires_at<=now());
CREATE POLICY task_expiry_delete ON sensor_tasks AS RESTRICTIVE FOR DELETE USING(retain_until<=now() AND (state IN ('succeeded','failed','expired','cancelled') OR (state='unknown' AND kind<>'rules.apply') OR (state='queued' AND delivery_count=0 AND expires_at<=now())));
CREATE POLICY inventory_expiry_delete ON inventory_history AS RESTRICTIVE FOR DELETE USING(expires_at<=now());
CREATE POLICY retention_change_expiry_delete ON retention_changes AS RESTRICTIVE FOR DELETE USING(expires_at<=now());
CREATE POLICY delivery_expiry_delete ON notification_deliveries AS RESTRICTIVE FOR DELETE USING(expires_at<=now() AND state<>'running' AND (lease_until IS NULL OR lease_until<=now()));
CREATE POLICY batch_expiry_delete ON notification_batches AS RESTRICTIVE FOR DELETE USING(expires_at<=now());
CREATE POLICY channel_version_expiry_delete ON notification_channel_versions AS RESTRICTIVE FOR DELETE USING(expires_at<=now() AND NOT EXISTS(SELECT 1 FROM notification_channels c WHERE c.tenant_id=notification_channel_versions.tenant_id AND c.id=channel_id AND c.revision=notification_channel_versions.revision));
CREATE POLICY model_check_expiry_delete ON model_capability_checks AS RESTRICTIVE FOR DELETE USING(expires_at<=now() AND state<>'running');
CREATE POLICY provider_version_expiry_delete ON model_provider_versions AS RESTRICTIVE FOR DELETE USING(expires_at<=now() AND NOT EXISTS(SELECT 1 FROM model_providers p WHERE p.tenant_id=model_provider_versions.tenant_id AND p.id=provider_id AND p.revision=model_provider_versions.revision));
CREATE POLICY analysis_job_expiry_delete ON analysis_jobs AS RESTRICTIVE FOR DELETE USING(expires_at<=now() AND state NOT IN ('queued','running') AND NOT EXISTS(SELECT 1 FROM starbeacon_jobs.river_job j WHERE j.id=river_job_id AND j.state NOT IN ('completed','cancelled','discarded')));
CREATE POLICY analysis_thread_expiry_delete ON analysis_threads AS RESTRICTIVE FOR DELETE USING(expires_at<=now());
CREATE POLICY route_expiry_delete ON routes AS RESTRICTIVE FOR DELETE USING(expires_at<=now());
CREATE INDEX login_anonymous_cleanup ON login_audits(expires_at,id) WHERE tenant_id IS NULL;
CREATE INDEX login_history_cleanup ON login_audits(tenant_id,expires_at,id);
CREATE INDEX operation_history_cleanup ON operation_audits(tenant_id,expires_at,id);
CREATE INDEX task_history_cleanup ON sensor_tasks(tenant_id,retain_until,id)
 WHERE state IN ('succeeded','failed','expired','cancelled') OR (state='unknown' AND kind<>'rules.apply') OR (state='queued' AND delivery_count=0);
CREATE INDEX inventory_history_cleanup ON inventory_history(tenant_id,expires_at,kind,id,revision);
CREATE INDEX retention_change_cleanup ON retention_changes(tenant_id,expires_at,id);
CREATE INDEX notification_batch_cleanup ON notification_batches(tenant_id,expires_at,id);
CREATE INDEX notification_version_cleanup ON notification_channel_versions(tenant_id,expires_at,channel_id,revision);
CREATE INDEX model_check_cleanup ON model_capability_checks(tenant_id,expires_at,id) WHERE state<>'running';
CREATE INDEX model_version_cleanup ON model_provider_versions(tenant_id,expires_at,provider_id,revision);
CREATE INDEX analysis_job_cleanup ON analysis_jobs(tenant_id,expires_at,id) WHERE state NOT IN ('queued','running');
CREATE INDEX analysis_thread_cleanup ON analysis_threads(tenant_id,expires_at,id);
CREATE INDEX route_history_cleanup ON routes(tenant_id,expires_at,token);
-- +goose Down
DROP POLICY route_expiry_delete ON routes;
DROP POLICY analysis_thread_expiry_delete ON analysis_threads;
DROP POLICY analysis_job_expiry_delete ON analysis_jobs;
DROP POLICY provider_version_expiry_delete ON model_provider_versions;
DROP POLICY model_check_expiry_delete ON model_capability_checks;
DROP POLICY channel_version_expiry_delete ON notification_channel_versions;
DROP POLICY batch_expiry_delete ON notification_batches;
DROP POLICY delivery_expiry_delete ON notification_deliveries;
DROP POLICY retention_change_expiry_delete ON retention_changes;
DROP POLICY inventory_expiry_delete ON inventory_history;
DROP POLICY task_expiry_delete ON sensor_tasks;
DROP POLICY login_expiry_delete ON login_audits;
DROP POLICY operation_expiry_delete ON operation_audits;
DROP INDEX route_history_cleanup,analysis_thread_cleanup,analysis_job_cleanup,model_version_cleanup,model_check_cleanup,notification_version_cleanup,notification_batch_cleanup,retention_change_cleanup,inventory_history_cleanup,task_history_cleanup,operation_history_cleanup,login_history_cleanup,login_anonymous_cleanup;
DROP POLICY login_anonymous_delete_scope ON login_audits;
DROP POLICY login_anonymous_read_scope ON login_audits;
DROP TABLE retention_maintenance;
