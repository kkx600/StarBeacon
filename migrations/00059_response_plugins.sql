-- +goose Up
CREATE TABLE response_plugin_versions (
 tenant_id text NOT NULL REFERENCES tenants(id), plugin_id text NOT NULL CHECK(plugin_id ~ '^[a-z0-9][a-z0-9_-]{0,63}$'),
 version integer NOT NULL CHECK(version BETWEEN 1 AND 32),
 name text NOT NULL CHECK(char_length(name) BETWEEN 1 AND 128),
 device text NOT NULL CHECK(char_length(device) BETWEEN 1 AND 128),
 template jsonb NOT NULL CHECK(jsonb_typeof(template)='object' AND octet_length(template::text)<=24576),
 template_sha256 text NOT NULL CHECK(template_sha256 ~ '^[a-f0-9]{64}$'),
 created_by text NOT NULL REFERENCES users(id), created_at timestamptz NOT NULL DEFAULT now(),
 request_key_sha256 text NOT NULL CHECK(request_key_sha256 ~ '^[a-f0-9]{64}$'),
 request_sha256 text NOT NULL CHECK(request_sha256 ~ '^[a-f0-9]{64}$'),
 PRIMARY KEY(tenant_id,plugin_id,version), UNIQUE(tenant_id,created_by,request_key_sha256)
);
ALTER TABLE response_plugin_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE response_plugin_versions FORCE ROW LEVEL SECURITY;
CREATE POLICY response_plugin_scope ON response_plugin_versions
 USING(tenant_id=current_setting('starbeacon.tenant_id',true))
 WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));

-- +goose Down
DROP TABLE response_plugin_versions;
