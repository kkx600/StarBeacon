-- +goose Up
-- 未确认有副作用任务的实际结果前，不允许下一次写入覆盖未知设备状态。
DROP INDEX sensor_tasks_serial;
CREATE UNIQUE INDEX sensor_tasks_serial ON sensor_tasks(tenant_id,sensor_id)
WHERE state IN ('queued','delivered','running') OR (state='unknown' AND kind='rules.apply');

-- +goose Down
DROP INDEX sensor_tasks_serial;
CREATE UNIQUE INDEX sensor_tasks_serial ON sensor_tasks(tenant_id,sensor_id) WHERE state IN ('queued','delivered','running');
