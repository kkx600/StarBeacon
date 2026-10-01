-- +goose Up
CREATE TABLE tenants (id text PRIMARY KEY, name text NOT NULL, active boolean NOT NULL DEFAULT true, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE users (id text PRIMARY KEY, tenant_id text NOT NULL REFERENCES tenants(id), username text NOT NULL UNIQUE, password_hash text NOT NULL, role text NOT NULL CHECK(role IN ('admin','viewer')), active boolean NOT NULL DEFAULT true, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE sessions (token_hash text PRIMARY KEY, user_id text NOT NULL REFERENCES users(id), csrf_token text NOT NULL, expires_at timestamptz NOT NULL, created_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX sessions_expiry ON sessions(expires_at);
CREATE TABLE sensors (tenant_id text NOT NULL REFERENCES tenants(id), id text NOT NULL, name text NOT NULL, registration_id text NOT NULL UNIQUE, active boolean NOT NULL DEFAULT true, created_at timestamptz NOT NULL DEFAULT now(), last_seen timestamptz, health jsonb NOT NULL DEFAULT '{}', PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,id,registration_id));
CREATE TABLE routes (token text PRIMARY KEY, tenant_id text NOT NULL, sensor_id text NOT NULL, registration_id text NOT NULL, stream_id text NOT NULL CHECK(stream_id IN ('alerts','context')), partition_day date NOT NULL, expires_at timestamptz NOT NULL, UNIQUE(tenant_id,sensor_id,registration_id,stream_id,partition_day), FOREIGN KEY(tenant_id,sensor_id,registration_id) REFERENCES sensors(tenant_id,id,registration_id));
CREATE TABLE retention_policies (tenant_id text NOT NULL REFERENCES tenants(id), category text NOT NULL, days integer NOT NULL DEFAULT 180 CHECK(days BETWEEN 1 AND 3650), PRIMARY KEY(tenant_id,category));
CREATE TABLE operation_audits (id bigserial PRIMARY KEY, tenant_id text NOT NULL REFERENCES tenants(id), user_id text NOT NULL, action text NOT NULL, object_id text NOT NULL, request_id text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL DEFAULT now()+interval '180 days');
CREATE INDEX operation_audits_tenant_time ON operation_audits(tenant_id,created_at DESC);
CREATE TABLE login_audits (id bigserial PRIMARY KEY, tenant_id text REFERENCES tenants(id), username text NOT NULL, success boolean NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL DEFAULT now()+interval '180 days');
ALTER TABLE sensors ENABLE ROW LEVEL SECURITY;
ALTER TABLE sensors FORCE ROW LEVEL SECURITY;
CREATE POLICY sensor_scope ON sensors USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
ALTER TABLE routes ENABLE ROW LEVEL SECURITY;
ALTER TABLE routes FORCE ROW LEVEL SECURITY;
CREATE POLICY route_scope ON routes USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
ALTER TABLE retention_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE retention_policies FORCE ROW LEVEL SECURITY;
CREATE POLICY retention_scope ON retention_policies USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
ALTER TABLE operation_audits ENABLE ROW LEVEL SECURITY;
ALTER TABLE operation_audits FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_scope ON operation_audits USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));

-- +goose Down
DROP TABLE operation_audits,login_audits,retention_policies,routes,sensors,sessions,users,tenants;
