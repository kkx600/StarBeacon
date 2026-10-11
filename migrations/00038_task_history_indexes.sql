-- +goose Up
-- 留存期内列表以时间和标识稳定排序；索引分别覆盖全租户与单探针入口。
CREATE INDEX sensor_tasks_recent_tenant ON sensor_tasks(tenant_id,created_at DESC,id DESC);
CREATE INDEX sensor_tasks_recent_sensor ON sensor_tasks(tenant_id,sensor_id,created_at DESC,id DESC);

-- +goose Down
DROP INDEX sensor_tasks_recent_sensor,sensor_tasks_recent_tenant;
