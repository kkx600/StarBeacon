-- +goose Up
CREATE TABLE response_watchlist_checks (
 tenant_id text NOT NULL REFERENCES tenants(id), task_id text NOT NULL,
 command_sha256 text NOT NULL CHECK(command_sha256 ~ '^[a-f0-9]{64}$'),
 check_sha256 text NOT NULL CHECK(check_sha256 ~ '^[a-f0-9]{64}$'),
 check_data jsonb NOT NULL CHECK(jsonb_typeof(check_data)='object' AND octet_length(check_data::text)<=32768),
 created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,task_id),
 FOREIGN KEY(tenant_id,task_id) REFERENCES sensor_tasks(tenant_id,id)
);
CREATE INDEX response_watchlist_check_expiry ON response_watchlist_checks(tenant_id,expires_at);
ALTER TABLE response_watchlist_checks ENABLE ROW LEVEL SECURITY;
ALTER TABLE response_watchlist_checks FORCE ROW LEVEL SECURITY;
CREATE POLICY response_watchlist_check_scope ON response_watchlist_checks USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
CREATE POLICY response_watchlist_check_expiry_delete ON response_watchlist_checks AS RESTRICTIVE FOR DELETE USING(expires_at<=now() AND EXISTS(SELECT 1 FROM sensor_tasks t WHERE t.tenant_id=response_watchlist_checks.tenant_id AND t.id=response_watchlist_checks.task_id AND t.retain_until<=now() AND (t.state IN('succeeded','failed','expired','cancelled','unknown') OR (t.state='queued' AND t.delivery_count=0 AND t.expires_at<=now()))));
CREATE POLICY sensor_task_watchlist_check_delete ON sensor_tasks AS RESTRICTIVE FOR DELETE USING(NOT EXISTS(SELECT 1 FROM response_watchlist_checks c WHERE c.tenant_id=sensor_tasks.tenant_id AND c.task_id=sensor_tasks.id));
ALTER TABLE retention_maintenance DROP CONSTRAINT retention_maintenance_next_category_check;
ALTER TABLE retention_maintenance ADD CONSTRAINT retention_maintenance_next_category_check CHECK(next_category BETWEEN 0 AND 44);
-- +goose Down
UPDATE retention_maintenance SET next_category=LEAST(next_category,40);
ALTER TABLE retention_maintenance DROP CONSTRAINT retention_maintenance_next_category_check;
ALTER TABLE retention_maintenance ADD CONSTRAINT retention_maintenance_next_category_check CHECK(next_category BETWEEN 0 AND 40);
DROP POLICY sensor_task_watchlist_check_delete ON sensor_tasks;
DROP TABLE response_watchlist_checks;
