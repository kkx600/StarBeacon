-- +goose Up
CREATE TABLE packet_session_outbox (
 tenant_id text NOT NULL REFERENCES tenants(id),
 archive_id text NOT NULL,
 partition_day date NOT NULL,
 index_name text NOT NULL CHECK(index_name ~ '^sb-v2-context-logsdb-r[1-9][0-9]{0,3}-[dwm][0-9]{4}\.[0-9]{2}\.[0-9]{2}$'),
 documents jsonb NOT NULL CHECK(jsonb_typeof(documents)='array' AND jsonb_array_length(documents) BETWEEN 1 AND 1024),
 next_at timestamptz NOT NULL DEFAULT now(),
 expires_at timestamptz NOT NULL,
 attempts integer NOT NULL DEFAULT 0 CHECK(attempts>=0),
 PRIMARY KEY (tenant_id,archive_id)
);
CREATE INDEX packet_session_outbox_next ON packet_session_outbox(tenant_id,next_at,archive_id);
CREATE INDEX packet_session_outbox_expiry ON packet_session_outbox(tenant_id,expires_at);
ALTER TABLE packet_session_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE packet_session_outbox FORCE ROW LEVEL SECURITY;
CREATE POLICY packet_session_outbox_scope ON packet_session_outbox
 USING (tenant_id=current_setting('starbeacon.tenant_id',true))
 WITH CHECK (tenant_id=current_setting('starbeacon.tenant_id',true));
ALTER TABLE retention_maintenance DROP CONSTRAINT retention_maintenance_next_category_check;
ALTER TABLE retention_maintenance ADD CONSTRAINT retention_maintenance_next_category_check CHECK(next_category BETWEEN 0 AND 47);

-- +goose Down
-- +goose StatementBegin
DO $$
BEGIN
 IF EXISTS(SELECT 1 FROM packet_session_outbox) THEN
  RAISE EXCEPTION '存在待投影的会话分段，不能清除待办';
 END IF;
END $$;
-- +goose StatementEnd
DROP TABLE packet_session_outbox;
ALTER TABLE retention_maintenance DROP CONSTRAINT retention_maintenance_next_category_check;
UPDATE retention_maintenance SET next_category=0 WHERE next_category=47;
ALTER TABLE retention_maintenance ADD CONSTRAINT retention_maintenance_next_category_check CHECK(next_category BETWEEN 0 AND 46);
