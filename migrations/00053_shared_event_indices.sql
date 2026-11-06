-- +goose Up
-- 共享事件索引在路由创建时冻结物理索引；重试与重投沿用同一索引，空值表示升级前按租户与日期建立的旧版索引。
ALTER TABLE routes ADD COLUMN index_name text NOT NULL DEFAULT '' CHECK(index_name='' OR index_name ~ '^sb-v2-(alerts|context|logs)-r[1-9][0-9]{0,3}-[dwm][0-9]{4}\.[0-9]{2}\.[0-9]{2}$');
ALTER TABLE sensor_quality_outbox ADD COLUMN index_name text NOT NULL DEFAULT '' CHECK(index_name='' OR index_name ~ '^sb-v2-context-r[1-9][0-9]{0,3}-[dwm][0-9]{4}\.[0-9]{2}\.[0-9]{2}$');
-- +goose Down
ALTER TABLE sensor_quality_outbox DROP COLUMN index_name;
ALTER TABLE routes DROP COLUMN index_name;
