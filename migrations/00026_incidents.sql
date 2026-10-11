-- +goose Up
CREATE TABLE incidents (
 tenant_id text NOT NULL REFERENCES tenants(id), id text NOT NULL,
 revision bigint NOT NULL CHECK(revision BETWEEN 1 AND 1000),
 state text NOT NULL CHECK(state IN('open','investigating','closed')),
 severity text NOT NULL CHECK(severity IN('low','medium','high','critical')),
 record jsonb NOT NULL, created_at timestamptz NOT NULL, expires_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,id)
);
CREATE INDEX incident_list ON incidents(tenant_id,created_at DESC,id DESC);
CREATE INDEX incident_expiry ON incidents(tenant_id,expires_at) WHERE state='closed';
CREATE TABLE incident_changes (
 tenant_id text NOT NULL REFERENCES tenants(id), incident_id text NOT NULL, revision bigint NOT NULL CHECK(revision BETWEEN 1 AND 1000),
 created_by text NOT NULL, operation text NOT NULL CHECK(operation IN('create','change')),
 idempotency_key_hash text NOT NULL, input_hash text NOT NULL, record jsonb NOT NULL,
 created_at timestamptz NOT NULL, expires_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,incident_id,revision),
 UNIQUE(tenant_id,created_by,operation,idempotency_key_hash)
);
CREATE INDEX incident_change_expiry ON incident_changes(tenant_id,expires_at);
CREATE INDEX incident_change_budget ON incident_changes(tenant_id,created_at);
CREATE TABLE incident_alert_links (
 tenant_id text NOT NULL REFERENCES tenants(id), event_id text NOT NULL, incident_id text NOT NULL,
 raw_sha256 text NOT NULL CHECK(raw_sha256 ~ '^[a-f0-9]{64}$'),
 PRIMARY KEY(tenant_id,event_id),
 FOREIGN KEY(tenant_id,incident_id) REFERENCES incidents(tenant_id,id) ON DELETE CASCADE
);
ALTER TABLE incidents ENABLE ROW LEVEL SECURITY;
ALTER TABLE incidents FORCE ROW LEVEL SECURITY;
CREATE POLICY incident_scope ON incidents USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
ALTER TABLE incident_changes ENABLE ROW LEVEL SECURITY;
ALTER TABLE incident_changes FORCE ROW LEVEL SECURITY;
CREATE POLICY incident_change_scope ON incident_changes USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
ALTER TABLE incident_alert_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE incident_alert_links FORCE ROW LEVEL SECURITY;
CREATE POLICY incident_link_scope ON incident_alert_links USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
-- 未关闭事件保留调查历史；闭环后按各修订首次提交时固化的期限清理。
CREATE POLICY incident_change_expiry_delete ON incident_changes AS RESTRICTIVE FOR DELETE USING(expires_at<=now() AND NOT EXISTS(SELECT 1 FROM incidents i WHERE i.tenant_id=incident_changes.tenant_id AND i.id=incident_changes.incident_id AND i.state<>'closed'));
CREATE POLICY incident_expiry_delete ON incidents AS RESTRICTIVE FOR DELETE USING(state='closed' AND expires_at<=now() AND NOT EXISTS(SELECT 1 FROM incident_changes c WHERE c.tenant_id=incidents.tenant_id AND c.incident_id=incidents.id));
INSERT INTO retention_policies(tenant_id,category,days) SELECT id,'incidents',180 FROM tenants ON CONFLICT DO NOTHING;
ALTER TABLE retention_maintenance DROP CONSTRAINT retention_maintenance_next_category_check;
ALTER TABLE retention_maintenance ADD CONSTRAINT retention_maintenance_next_category_check CHECK(next_category BETWEEN 0 AND 21);
-- +goose Down
UPDATE retention_maintenance SET next_category=LEAST(next_category,19);
ALTER TABLE retention_maintenance DROP CONSTRAINT retention_maintenance_next_category_check;
ALTER TABLE retention_maintenance ADD CONSTRAINT retention_maintenance_next_category_check CHECK(next_category BETWEEN 0 AND 19);
DELETE FROM retention_policies WHERE category='incidents';
DROP TABLE incident_alert_links,incident_changes,incidents;
