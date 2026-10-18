-- +goose Up
-- 仅保存每个注册代次的最后原生快照作为累计比较水位，不建立逐采样 PG 历史。
ALTER TABLE sensor_quality_cursors ADD COLUMN observation jsonb;
ALTER TABLE sensor_quality_cursors ADD COLUMN event_config_sha256 text NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE sensor_quality_cursors DROP COLUMN observation,DROP COLUMN event_config_sha256;
