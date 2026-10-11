-- +goose Up
CREATE TABLE alert_assessments (
 tenant_id text NOT NULL REFERENCES tenants(id), event_id text NOT NULL,
 raw_sha256 text NOT NULL CHECK(raw_sha256 ~ '^[a-f0-9]{64}$'),
 revision bigint NOT NULL CHECK(revision>0 AND revision<9007199254740992),
 record jsonb NOT NULL, expires_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,event_id)
);
CREATE INDEX alert_assessment_expiry ON alert_assessments(tenant_id,expires_at);
CREATE TABLE alert_assessment_changes (
 tenant_id text NOT NULL REFERENCES tenants(id), event_id text NOT NULL, revision bigint NOT NULL,
 created_by text NOT NULL, idempotency_key_hash text NOT NULL, input_hash text NOT NULL,
 record jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,event_id,revision), UNIQUE(tenant_id,event_id,created_by,idempotency_key_hash)
);
CREATE INDEX alert_assessment_change_expiry ON alert_assessment_changes(tenant_id,expires_at);
CREATE INDEX alert_assessment_change_budget ON alert_assessment_changes(tenant_id,created_at);
ALTER TABLE alert_assessments ENABLE ROW LEVEL SECURITY;
ALTER TABLE alert_assessments FORCE ROW LEVEL SECURITY;
CREATE POLICY alert_assessment_scope ON alert_assessments USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
ALTER TABLE alert_assessment_changes ENABLE ROW LEVEL SECURITY;
ALTER TABLE alert_assessment_changes FORCE ROW LEVEL SECURITY;
CREATE POLICY alert_assessment_change_scope ON alert_assessment_changes USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
-- 在线角色只能删除到期历史；当前研判还需要全部历史已经回收。
CREATE POLICY alert_assessment_change_expiry_delete ON alert_assessment_changes AS RESTRICTIVE FOR DELETE USING(expires_at<=now());
CREATE POLICY alert_assessment_expiry_delete ON alert_assessments AS RESTRICTIVE FOR DELETE USING(expires_at<=now() AND NOT EXISTS(SELECT 1 FROM alert_assessment_changes c WHERE c.tenant_id=alert_assessments.tenant_id AND c.event_id=alert_assessments.event_id));
-- 清理分类游标覆盖报告与研判记录，已有游标不变。
ALTER TABLE retention_maintenance DROP CONSTRAINT retention_maintenance_next_category_check;
ALTER TABLE retention_maintenance ADD CONSTRAINT retention_maintenance_next_category_check CHECK(next_category BETWEEN 0 AND 18);
-- +goose Down
UPDATE retention_maintenance SET next_category=LEAST(next_category,14);
ALTER TABLE retention_maintenance DROP CONSTRAINT retention_maintenance_next_category_check;
ALTER TABLE retention_maintenance ADD CONSTRAINT retention_maintenance_next_category_check CHECK(next_category BETWEEN 0 AND 14);
DROP TABLE alert_assessment_changes,alert_assessments;
