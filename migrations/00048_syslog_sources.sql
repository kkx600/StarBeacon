-- +goose Up
ALTER TABLE routes DROP CONSTRAINT routes_stream_id_check;
ALTER TABLE routes ADD CONSTRAINT routes_stream_id_check CHECK(stream_id IN('alerts','context','logs'));
INSERT INTO retention_policies(tenant_id,category,days)
 SELECT id,'security_logs',180 FROM tenants ON CONFLICT(tenant_id,category) DO NOTHING;
-- +goose Down
-- 已登记日志路由是历史身份，不在回退时删除；存在数据时拒绝回退约束。
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM retention_policies WHERE category='security_logs' AND (revision<>1 OR days<>180)) THEN
  RAISE EXCEPTION 'security log retention has been configured; downgrade requires an explicit data migration';
 END IF;
END $$;
-- +goose StatementEnd
ALTER TABLE routes DROP CONSTRAINT routes_stream_id_check;
ALTER TABLE routes ADD CONSTRAINT routes_stream_id_check CHECK(stream_id IN('alerts','context'));

DELETE FROM retention_policies WHERE category='security_logs';
