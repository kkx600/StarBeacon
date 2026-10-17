-- +goose Up
CREATE TABLE incident_tasks (
 tenant_id text NOT NULL REFERENCES tenants(id), incident_id text NOT NULL, id text NOT NULL,
 revision bigint NOT NULL CHECK(revision BETWEEN 1 AND 1000),
 state text NOT NULL CHECK(state IN('open','in_progress','completed','cancelled')),
 record jsonb NOT NULL, created_at timestamptz NOT NULL, expires_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,incident_id,id),
 FOREIGN KEY(tenant_id,incident_id) REFERENCES incidents(tenant_id,id)
);
CREATE INDEX incident_task_list ON incident_tasks(tenant_id,incident_id,created_at DESC,id DESC);
CREATE INDEX incident_task_open ON incident_tasks(tenant_id,incident_id) WHERE state IN('open','in_progress');
CREATE INDEX incident_task_expiry ON incident_tasks(tenant_id,expires_at);
CREATE TABLE incident_task_changes (
 tenant_id text NOT NULL REFERENCES tenants(id), incident_id text NOT NULL, task_id text NOT NULL,
 revision bigint NOT NULL CHECK(revision BETWEEN 1 AND 1000), created_by text NOT NULL,
 operation text NOT NULL CHECK(operation IN('create','change')),
 idempotency_key_hash text NOT NULL, input_hash text NOT NULL, record jsonb NOT NULL,
 created_at timestamptz NOT NULL, expires_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,task_id,revision),
 UNIQUE(tenant_id,created_by,operation,idempotency_key_hash),
 FOREIGN KEY(tenant_id,incident_id,task_id) REFERENCES incident_tasks(tenant_id,incident_id,id)
);
CREATE INDEX incident_task_change_history ON incident_task_changes(tenant_id,incident_id,task_id,revision DESC);
CREATE INDEX incident_task_change_budget ON incident_task_changes(tenant_id,created_at);
CREATE INDEX incident_task_change_expiry ON incident_task_changes(tenant_id,expires_at);
ALTER TABLE incident_tasks ENABLE ROW LEVEL SECURITY;
ALTER TABLE incident_tasks FORCE ROW LEVEL SECURITY;
CREATE POLICY incident_task_scope ON incident_tasks USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
ALTER TABLE incident_task_changes ENABLE ROW LEVEL SECURITY;
ALTER TABLE incident_task_changes FORCE ROW LEVEL SECURITY;
CREATE POLICY incident_task_change_scope ON incident_task_changes USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
CREATE POLICY incident_task_history_expiry_delete ON incident_task_changes AS RESTRICTIVE FOR DELETE USING(expires_at<=now() AND EXISTS(SELECT 1 FROM incidents i WHERE i.tenant_id=incident_task_changes.tenant_id AND i.id=incident_task_changes.incident_id AND i.state='closed'));
CREATE POLICY incident_task_expiry_delete ON incident_tasks AS RESTRICTIVE FOR DELETE USING(expires_at<=now() AND state IN('completed','cancelled') AND EXISTS(SELECT 1 FROM incidents i WHERE i.tenant_id=incident_tasks.tenant_id AND i.id=incident_tasks.incident_id AND i.state='closed') AND NOT EXISTS(SELECT 1 FROM incident_task_changes c WHERE c.tenant_id=incident_tasks.tenant_id AND c.task_id=incident_tasks.id));
DROP POLICY incident_expiry_delete ON incidents;
CREATE POLICY incident_expiry_delete ON incidents AS RESTRICTIVE FOR DELETE USING(state='closed' AND expires_at<=now() AND NOT EXISTS(SELECT 1 FROM incident_changes c WHERE c.tenant_id=incidents.tenant_id AND c.incident_id=incidents.id) AND NOT EXISTS(SELECT 1 FROM incident_tasks t WHERE t.tenant_id=incidents.tenant_id AND t.incident_id=incidents.id));
ALTER TABLE retention_maintenance DROP CONSTRAINT retention_maintenance_next_category_check;
ALTER TABLE retention_maintenance ADD CONSTRAINT retention_maintenance_next_category_check CHECK(next_category BETWEEN 0 AND 36);
-- +goose Down
UPDATE retention_maintenance SET next_category=LEAST(next_category,34);
ALTER TABLE retention_maintenance DROP CONSTRAINT retention_maintenance_next_category_check;
ALTER TABLE retention_maintenance ADD CONSTRAINT retention_maintenance_next_category_check CHECK(next_category BETWEEN 0 AND 34);
DROP POLICY incident_expiry_delete ON incidents;
CREATE POLICY incident_expiry_delete ON incidents AS RESTRICTIVE FOR DELETE USING(state='closed' AND expires_at<=now() AND NOT EXISTS(SELECT 1 FROM incident_changes c WHERE c.tenant_id=incidents.tenant_id AND c.incident_id=incidents.id));
DROP TABLE incident_task_changes,incident_tasks;
