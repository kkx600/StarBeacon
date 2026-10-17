-- +goose Up
ALTER TABLE sensors ADD COLUMN certificate_managed boolean NOT NULL DEFAULT false;
CREATE TABLE probe_enrollments (
 tenant_id text NOT NULL, id text NOT NULL, sensor_id text NOT NULL, registration_id text NOT NULL,
 token_hash text NOT NULL CHECK(length(token_hash)=64), input_hash text NOT NULL,
 created_by text NOT NULL REFERENCES users(id), created_at timestamptz NOT NULL DEFAULT now(),
 expires_at timestamptz NOT NULL, revoked boolean NOT NULL DEFAULT false, retain_until timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,id), FOREIGN KEY(tenant_id,sensor_id) REFERENCES sensors(tenant_id,id)
);
CREATE TABLE probe_certificates (
 tenant_id text NOT NULL, id text NOT NULL, sensor_id text NOT NULL, registration_id text NOT NULL,
 kind text NOT NULL CHECK(kind IN ('enroll','renew')), credential_id text NOT NULL,
 csr_pem text NOT NULL CHECK(octet_length(csr_pem)<=16384), csr_sha256 text NOT NULL CHECK(length(csr_sha256)=64),
 state text NOT NULL CHECK(state IN ('signing','issued','unknown')),
 chain_pem text NOT NULL DEFAULT '', fingerprint text, serial text NOT NULL DEFAULT '',
 not_before timestamptz, not_after timestamptz, revoked_at timestamptz,
 ca_revocation text NOT NULL DEFAULT 'none' CHECK(ca_revocation IN ('none','pending','confirmed','unknown')),
 created_at timestamptz NOT NULL DEFAULT now(), retain_until timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,kind,credential_id), UNIQUE(tenant_id,fingerprint),
 FOREIGN KEY(tenant_id,sensor_id) REFERENCES sensors(tenant_id,id),
 CHECK((state='issued')=(fingerprint IS NOT NULL AND not_before IS NOT NULL AND not_after IS NOT NULL AND chain_pem<>'')),
 CHECK(revoked_at IS NULL OR state='issued'), CHECK(not_after IS NULL OR retain_until>not_after)
);
CREATE INDEX probe_enrollment_sensor ON probe_enrollments(tenant_id,sensor_id,created_at,id);
CREATE INDEX probe_certificate_sensor ON probe_certificates(tenant_id,sensor_id,created_at,id);
CREATE INDEX probe_enrollment_retention ON probe_enrollments(tenant_id,retain_until);
CREATE INDEX probe_certificate_retention ON probe_certificates(tenant_id,retain_until);
ALTER TABLE probe_enrollments ENABLE ROW LEVEL SECURITY;
ALTER TABLE probe_enrollments FORCE ROW LEVEL SECURITY;
ALTER TABLE probe_certificates ENABLE ROW LEVEL SECURITY;
ALTER TABLE probe_certificates FORCE ROW LEVEL SECURITY;
CREATE POLICY probe_enrollment_scope ON probe_enrollments USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
CREATE POLICY probe_certificate_scope ON probe_certificates USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
CREATE POLICY probe_enrollment_expiry ON probe_enrollments AS RESTRICTIVE FOR DELETE USING(retain_until<=now());
CREATE POLICY probe_certificate_expiry ON probe_certificates AS RESTRICTIVE FOR DELETE USING(retain_until<=now() AND state<>'signing' AND (not_after IS NULL OR not_after<=now()));
-- 运行账号不取得 sensors 的 INSERT 权限，只允许经当前管理员和租户核验的注册。
-- +goose StatementBegin
CREATE FUNCTION public.register_managed_probe(p_tenant text,p_user text,p_sensor text,p_registration text,p_name text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
 IF p_tenant IS DISTINCT FROM current_setting('starbeacon.tenant_id',true) OR NOT EXISTS(SELECT 1 FROM public.users u JOIN public.tenants t ON t.id=u.tenant_id WHERE u.tenant_id=p_tenant AND u.id=p_user AND u.active AND u.role='admin' AND t.active) THEN
  RAISE EXCEPTION 'registration denied' USING ERRCODE='42501';
 END IF;
 IF p_sensor !~ '^[a-z0-9][a-z0-9_-]{0,63}$' OR p_registration !~ '^[a-z0-9][a-z0-9_-]{0,63}$' OR char_length(p_name) NOT BETWEEN 1 AND 128 THEN
  RAISE EXCEPTION 'invalid identity' USING ERRCODE='22023';
 END IF;
 INSERT INTO public.sensors(tenant_id,id,name,registration_id,certificate_managed) VALUES(p_tenant,p_sensor,p_name,p_registration,true) ON CONFLICT(tenant_id,id) DO NOTHING;
 IF NOT EXISTS(SELECT 1 FROM public.sensors WHERE tenant_id=p_tenant AND id=p_sensor AND registration_id=p_registration AND name=p_name AND certificate_managed AND active) THEN
  RAISE EXCEPTION 'identity conflict' USING ERRCODE='40001';
 END IF;
END;
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION public.register_managed_probe(text,text,text,text,text) FROM PUBLIC;
ALTER TABLE retention_maintenance DROP CONSTRAINT retention_maintenance_next_category_check;
ALTER TABLE retention_maintenance ADD CONSTRAINT retention_maintenance_next_category_check CHECK(next_category BETWEEN 0 AND 34);
-- +goose Down
UPDATE retention_maintenance SET next_category=0 WHERE next_category>32;
ALTER TABLE retention_maintenance DROP CONSTRAINT retention_maintenance_next_category_check;
ALTER TABLE retention_maintenance ADD CONSTRAINT retention_maintenance_next_category_check CHECK(next_category BETWEEN 0 AND 32);
DROP FUNCTION public.register_managed_probe(text,text,text,text,text);
DROP TABLE probe_certificates,probe_enrollments;
ALTER TABLE sensors DROP COLUMN certificate_managed;
