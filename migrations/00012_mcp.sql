-- +goose Up
CREATE TABLE mcp_bindings (
 tenant_id text NOT NULL REFERENCES tenants(id), id text NOT NULL,
 name text NOT NULL, issuer text NOT NULL, subject text NOT NULL, oauth_client_id text NOT NULL,
 scopes text[] NOT NULL, enabled boolean NOT NULL, expires_at timestamptz NOT NULL,
 requests_per_minute integer NOT NULL CHECK(requests_per_minute BETWEEN 1 AND 120),
 owner_id text NOT NULL REFERENCES users(id), revision bigint NOT NULL CHECK(revision>0),
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(tenant_id,id)
);
-- 认证路由只保留三元身份摘要和业务路由，不包含查询结果、凭据或授权范围。
CREATE TABLE mcp_auth_routes (
 identity_hash text PRIMARY KEY CHECK(length(identity_hash)=64),
 tenant_id text NOT NULL, binding_id text NOT NULL,
 UNIQUE(tenant_id,binding_id),
 FOREIGN KEY(tenant_id,binding_id) REFERENCES mcp_bindings(tenant_id,id) ON DELETE CASCADE
);
ALTER TABLE mcp_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE mcp_bindings FORCE ROW LEVEL SECURITY;
CREATE POLICY mcp_binding_scope ON mcp_bindings USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
-- +goose Down
DROP TABLE mcp_auth_routes,mcp_bindings;
