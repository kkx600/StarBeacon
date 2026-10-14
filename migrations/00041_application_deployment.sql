-- +goose Up
CREATE INDEX application_deployment_budget ON sensor_tasks(tenant_id,created_at) WHERE kind='applications.apply';
CREATE INDEX application_deployment_history ON sensor_tasks(tenant_id,sensor_id,registration_id,created_at) WHERE kind='applications.apply' AND state='succeeded';
-- +goose Down
DROP INDEX application_deployment_history,application_deployment_budget;
