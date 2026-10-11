-- +goose Up
-- 响应提交预算只扫描租户内最近的联动任务，不读取规则载荷或高频事件。
CREATE INDEX sensor_tasks_response_budget ON sensor_tasks(tenant_id,created_at) WHERE kind LIKE 'response.%';

-- +goose Down
DROP INDEX sensor_tasks_response_budget;
