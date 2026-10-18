-- +goose Up
-- 游标只保留注册代次的去重状态；历史事件主存储为 ES 网络事件分区。
CREATE TABLE sensor_quality_cursors (
 tenant_id text NOT NULL REFERENCES tenants(id), sensor_id text NOT NULL, registration_id text NOT NULL,
 run_id text NOT NULL, sampled_at timestamptz NOT NULL, evaluated_at timestamptz NOT NULL,
 signal jsonb, event_id text NOT NULL DEFAULT '', event_run_id text NOT NULL DEFAULT '', event_created_at timestamptz, expires_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,sensor_id,registration_id),
 FOREIGN KEY(tenant_id,sensor_id) REFERENCES sensors(tenant_id,id)
);
CREATE TABLE sensor_quality_outbox (
 tenant_id text NOT NULL REFERENCES tenants(id), id text NOT NULL, sensor_id text NOT NULL, registration_id text NOT NULL,
 partition_day date NOT NULL, document jsonb, state text NOT NULL CHECK(state IN('pending','leased','done','expired')),
 attempts integer NOT NULL DEFAULT 0 CHECK(attempts>=0), next_at timestamptz NOT NULL DEFAULT now(),
 lease_token text NOT NULL DEFAULT '', lease_until timestamptz, last_error text NOT NULL DEFAULT '',
 created_at timestamptz NOT NULL, expires_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,id), FOREIGN KEY(tenant_id,sensor_id) REFERENCES sensors(tenant_id,id),
 CHECK((state IN('pending','leased') AND document IS NOT NULL) OR (state IN('done','expired') AND document IS NULL))
);
CREATE INDEX quality_outbox_ready ON sensor_quality_outbox(tenant_id,next_at,created_at,id) WHERE state IN('pending','leased');
CREATE INDEX quality_outbox_expiry ON sensor_quality_outbox(tenant_id,expires_at);
CREATE INDEX quality_cursor_expiry ON sensor_quality_cursors(tenant_id,expires_at);
ALTER TABLE sensor_quality_cursors ENABLE ROW LEVEL SECURITY;
ALTER TABLE sensor_quality_cursors FORCE ROW LEVEL SECURITY;
CREATE POLICY quality_cursor_scope ON sensor_quality_cursors USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
CREATE POLICY quality_cursor_delete ON sensor_quality_cursors AS RESTRICTIVE FOR DELETE USING(expires_at<=now() AND NOT EXISTS(SELECT 1 FROM sensors s WHERE s.tenant_id=sensor_quality_cursors.tenant_id AND s.id=sensor_quality_cursors.sensor_id AND s.registration_id=sensor_quality_cursors.registration_id));
ALTER TABLE sensor_quality_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE sensor_quality_outbox FORCE ROW LEVEL SECURITY;
CREATE POLICY quality_outbox_scope ON sensor_quality_outbox USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
CREATE POLICY quality_outbox_delete ON sensor_quality_outbox AS RESTRICTIVE FOR DELETE USING(expires_at<=now() AND (state IN('done','expired') OR (state='pending' OR lease_until<=now())));
ALTER TABLE retention_maintenance DROP CONSTRAINT retention_maintenance_next_category_check;
ALTER TABLE retention_maintenance ADD CONSTRAINT retention_maintenance_next_category_check CHECK(next_category BETWEEN 0 AND 38);
ALTER TABLE notification_channels DROP CONSTRAINT notification_streams_valid;
ALTER TABLE notification_channels ADD CONSTRAINT notification_streams_valid CHECK(
 jsonb_typeof(streams)='array' AND jsonb_array_length(streams) BETWEEN 1 AND 4
 AND streams <@ '["alerts","operations","logins","quality"]'::jsonb
 AND jsonb_array_length(streams)=((streams ? 'alerts')::integer+(streams ? 'operations')::integer+(streams ? 'logins')::integer+(streams ? 'quality')::integer)
 AND (kind IN('syslog_tls','syslog_tcp') OR streams <@ '["alerts","quality"]'::jsonb)
);
-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM notification_channels WHERE streams ? 'quality') OR EXISTS(SELECT 1 FROM sensor_quality_outbox) THEN
  RAISE EXCEPTION '检测质量订阅或持久任务仍存在，不能隐式变更订阅或丢弃待办';
 END IF;
END $$;
-- +goose StatementEnd
ALTER TABLE notification_channels DROP CONSTRAINT notification_streams_valid;
ALTER TABLE notification_channels ADD CONSTRAINT notification_streams_valid CHECK(jsonb_typeof(streams)='array' AND jsonb_array_length(streams) BETWEEN 1 AND 3 AND streams <@ '["alerts","operations","logins"]'::jsonb AND jsonb_array_length(streams)=((streams ? 'alerts')::integer+(streams ? 'operations')::integer+(streams ? 'logins')::integer) AND (kind IN('syslog_tls','syslog_tcp') OR streams='["alerts"]'::jsonb));
UPDATE retention_maintenance SET next_category=LEAST(next_category,36);
ALTER TABLE retention_maintenance DROP CONSTRAINT retention_maintenance_next_category_check;
ALTER TABLE retention_maintenance ADD CONSTRAINT retention_maintenance_next_category_check CHECK(next_category BETWEEN 0 AND 36);
DROP TABLE sensor_quality_outbox,sensor_quality_cursors;
