-- +goose Up
-- 共享事件索引在路由与质量待办创建时冻结物理索引；重试与重投沿用同一索引，写入时必须提供。
ALTER TABLE routes ADD COLUMN index_name text;
ALTER TABLE sensor_quality_outbox ADD COLUMN index_name text;
-- 已有记录按默认布局（告警与日志按 UTC 周、协议记录按 UTC 日）和租户当前保留期补齐。
UPDATE routes r SET index_name='sb-v2-'||r.stream_id||'-r'||COALESCE((SELECT p.days FROM retention_policies p WHERE p.tenant_id=r.tenant_id AND p.category=CASE r.stream_id WHEN 'alerts' THEN 'alerts' WHEN 'logs' THEN 'security_logs' ELSE 'network' END),180)
  ||CASE r.stream_id WHEN 'context' THEN '-d'||to_char(r.partition_day,'YYYY.MM.DD') ELSE '-w'||to_char(date_trunc('week',r.partition_day::timestamp),'YYYY.MM.DD') END;
UPDATE sensor_quality_outbox q SET index_name='sb-v2-context-r'||COALESCE((SELECT p.days FROM retention_policies p WHERE p.tenant_id=q.tenant_id AND p.category='network'),180)||'-d'||to_char(q.partition_day,'YYYY.MM.DD');
ALTER TABLE routes ALTER COLUMN index_name SET NOT NULL, ADD CONSTRAINT routes_index_name_check CHECK(index_name ~ ('^sb-v2-'||stream_id||'-r[1-9][0-9]{0,3}-[dwm][0-9]{4}\.[0-9]{2}\.[0-9]{2}$'));
ALTER TABLE sensor_quality_outbox ALTER COLUMN index_name SET NOT NULL, ADD CONSTRAINT sensor_quality_outbox_index_name_check CHECK(index_name ~ '^sb-v2-context-r[1-9][0-9]{0,3}-[dwm][0-9]{4}\.[0-9]{2}\.[0-9]{2}$');
-- +goose Down
ALTER TABLE sensor_quality_outbox DROP COLUMN index_name;
ALTER TABLE routes DROP COLUMN index_name;
