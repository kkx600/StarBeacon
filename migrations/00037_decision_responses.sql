-- +goose Up
-- 人工授权与影子结果分别保存；档案不随后续回读或设备状态变化改写。
CREATE TABLE decision_responses (
 tenant_id text NOT NULL REFERENCES tenants(id), id text NOT NULL,
 created_by text NOT NULL REFERENCES users(id), evaluation_id text NOT NULL,
 task_id text NOT NULL, created_at timestamptz NOT NULL,
 expires_at timestamptz NOT NULL CHECK(expires_at>created_at),
 key_hash text NOT NULL CHECK(key_hash ~ '^[a-f0-9]{64}$'),
 input_hash text NOT NULL CHECK(input_hash ~ '^[a-f0-9]{64}$'),
 record jsonb NOT NULL CHECK(jsonb_typeof(record)='object' AND octet_length(record::text)<=16384),
 PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,evaluation_id),
 UNIQUE(tenant_id,task_id), UNIQUE(tenant_id,created_by,key_hash)
);
CREATE INDEX decision_response_owner ON decision_responses(tenant_id,created_by,evaluation_id);
CREATE INDEX decision_response_expiry ON decision_responses(tenant_id,expires_at);
ALTER TABLE decision_responses ENABLE ROW LEVEL SECURITY;
ALTER TABLE decision_responses FORCE ROW LEVEL SECURITY;
CREATE POLICY decision_response_scope ON decision_responses USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
CREATE POLICY decision_response_expiry_delete ON decision_responses AS RESTRICTIVE FOR DELETE USING(expires_at<=now());
ALTER TABLE retention_maintenance DROP CONSTRAINT retention_maintenance_next_category_check;
ALTER TABLE retention_maintenance ADD CONSTRAINT retention_maintenance_next_category_check CHECK(next_category BETWEEN 0 AND 29);

-- +goose Down
UPDATE retention_maintenance SET next_category=0 WHERE next_category>28;
ALTER TABLE retention_maintenance DROP CONSTRAINT retention_maintenance_next_category_check;
ALTER TABLE retention_maintenance ADD CONSTRAINT retention_maintenance_next_category_check CHECK(next_category BETWEEN 0 AND 28);
DROP TABLE decision_responses;
