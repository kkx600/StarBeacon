-- +goose Up
ALTER TABLE routes DROP CONSTRAINT routes_index_name_check,
 ADD CONSTRAINT routes_index_name_check CHECK(index_name ~ ('^sb-v2-'||stream_id
  ||CASE WHEN stream_id IN ('context','logs') THEN '(-logsdb)?' ELSE '' END
  ||'-r[1-9][0-9]{0,3}-[dwm][0-9]{4}\.[0-9]{2}\.[0-9]{2}$'));
ALTER TABLE sensor_quality_outbox DROP CONSTRAINT sensor_quality_outbox_index_name_check,
 ADD CONSTRAINT sensor_quality_outbox_index_name_check CHECK(index_name ~ '^sb-v2-context(-logsdb)?-r[1-9][0-9]{0,3}-[dwm][0-9]{4}\.[0-9]{2}\.[0-9]{2}$');

-- +goose Down
-- +goose StatementBegin
DO $$
BEGIN
 IF EXISTS(SELECT 1 FROM routes WHERE index_name LIKE 'sb-v2-%-logsdb-%')
    OR EXISTS(SELECT 1 FROM sensor_quality_outbox WHERE index_name LIKE 'sb-v2-context-logsdb-%') THEN
  RAISE EXCEPTION '存在冻结的 LogsDB 路由或质量待办，不能回退索引命名';
 END IF;
END $$;
-- +goose StatementEnd
ALTER TABLE sensor_quality_outbox DROP CONSTRAINT sensor_quality_outbox_index_name_check,
 ADD CONSTRAINT sensor_quality_outbox_index_name_check CHECK(index_name ~ '^sb-v2-context-r[1-9][0-9]{0,3}-[dwm][0-9]{4}\.[0-9]{2}\.[0-9]{2}$');
ALTER TABLE routes DROP CONSTRAINT routes_index_name_check,
 ADD CONSTRAINT routes_index_name_check CHECK(index_name ~ ('^sb-v2-'||stream_id||'-r[1-9][0-9]{0,3}-[dwm][0-9]{4}\.[0-9]{2}\.[0-9]{2}$'));
