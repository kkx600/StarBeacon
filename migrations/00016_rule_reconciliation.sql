-- +goose Up
ALTER TABLE sensor_tasks ADD COLUMN rule_resolution jsonb;
DROP INDEX sensor_tasks_serial;
CREATE UNIQUE INDEX sensor_tasks_serial ON sensor_tasks(tenant_id,sensor_id)
 WHERE state IN ('queued','delivered','running');
CREATE UNIQUE INDEX sensor_tasks_unresolved_rule ON sensor_tasks(tenant_id,sensor_id)
 WHERE state='unknown' AND kind='rules.apply' AND rule_resolution IS NULL;
-- 解除阻塞必须保留独立设备核实证据；原中断回执不得改写成成功。
ALTER TABLE sensor_tasks ADD CONSTRAINT rule_resolution_scope
 CHECK(rule_resolution IS NULL OR (state='unknown' AND kind='rules.apply' AND jsonb_typeof(rule_resolution)='object'));
DROP POLICY task_expiry_delete ON sensor_tasks;
CREATE POLICY task_expiry_delete ON sensor_tasks AS RESTRICTIVE FOR DELETE
 USING(retain_until<=now() AND (state IN ('succeeded','failed','expired','cancelled') OR
 (state='unknown' AND (kind<>'rules.apply' OR rule_resolution IS NOT NULL)) OR
 (state='queued' AND delivery_count=0 AND expires_at<=now())));
DROP INDEX task_history_cleanup;
CREATE INDEX task_history_cleanup ON sensor_tasks(tenant_id,retain_until,id)
 WHERE state IN ('succeeded','failed','expired','cancelled') OR
 (state='unknown' AND (kind<>'rules.apply' OR rule_resolution IS NOT NULL)) OR (state='queued' AND delivery_count=0);

-- +goose Down
DROP POLICY task_expiry_delete ON sensor_tasks;
CREATE POLICY task_expiry_delete ON sensor_tasks AS RESTRICTIVE FOR DELETE
 USING(retain_until<=now() AND (state IN ('succeeded','failed','expired','cancelled') OR
 (state='unknown' AND kind<>'rules.apply') OR (state='queued' AND delivery_count=0 AND expires_at<=now())));
DROP INDEX task_history_cleanup;
CREATE INDEX task_history_cleanup ON sensor_tasks(tenant_id,retain_until,id)
 WHERE state IN ('succeeded','failed','expired','cancelled') OR (state='unknown' AND kind<>'rules.apply') OR (state='queued' AND delivery_count=0);
DROP INDEX sensor_tasks_unresolved_rule;
DROP INDEX sensor_tasks_serial;
-- 同时存在诊断与待核实任务时，旧版唯一约束会拒绝降级并保留整个事务。
CREATE UNIQUE INDEX sensor_tasks_serial ON sensor_tasks(tenant_id,sensor_id)
 WHERE state IN ('queued','delivered','running') OR (state='unknown' AND kind='rules.apply');
ALTER TABLE sensor_tasks DROP COLUMN rule_resolution;
