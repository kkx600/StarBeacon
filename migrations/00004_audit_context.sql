-- +goose Up
ALTER TABLE operation_audits ADD COLUMN source_ip text NOT NULL DEFAULT '',ADD COLUMN user_agent text NOT NULL DEFAULT '';
ALTER TABLE login_audits ADD COLUMN source_ip text NOT NULL DEFAULT '',ADD COLUMN user_agent text NOT NULL DEFAULT '',ADD COLUMN request_id text NOT NULL DEFAULT '',ADD COLUMN phase text NOT NULL DEFAULT 'password_verification';
CREATE INDEX operation_audits_scope_cursor ON operation_audits(tenant_id,id DESC);
CREATE INDEX login_audits_scope_cursor ON login_audits(tenant_id,id DESC);
ALTER TABLE login_audits ENABLE ROW LEVEL SECURITY;
ALTER TABLE login_audits FORCE ROW LEVEL SECURITY;
CREATE POLICY login_read_scope ON login_audits FOR SELECT USING(tenant_id=current_setting('starbeacon.tenant_id',true));
CREATE POLICY login_insert_scope ON login_audits FOR INSERT WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true) OR (tenant_id IS NULL AND COALESCE(current_setting('starbeacon.tenant_id',true),'')=''));
CREATE POLICY login_delete_scope ON login_audits FOR DELETE USING(tenant_id=current_setting('starbeacon.tenant_id',true));

-- +goose Down
DROP POLICY login_read_scope ON login_audits;
DROP POLICY login_insert_scope ON login_audits;
DROP POLICY login_delete_scope ON login_audits;
ALTER TABLE login_audits DISABLE ROW LEVEL SECURITY;
DROP INDEX operation_audits_scope_cursor,login_audits_scope_cursor;
ALTER TABLE operation_audits DROP COLUMN source_ip,DROP COLUMN user_agent;
ALTER TABLE login_audits DROP COLUMN source_ip,DROP COLUMN user_agent,DROP COLUMN request_id,DROP COLUMN phase;
