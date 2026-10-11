-- +goose Up
ALTER TABLE users ADD COLUMN revision bigint NOT NULL DEFAULT 1 CHECK(revision BETWEEN 1 AND 1000000), ADD COLUMN updated_at timestamptz NOT NULL DEFAULT now();
CREATE TABLE user_management_requests (
 tenant_id text NOT NULL REFERENCES tenants(id), created_by text NOT NULL,
 operation text NOT NULL CHECK(operation IN('create','change')), key_hash text NOT NULL,
 input_hash text NOT NULL, user_id text NOT NULL, record jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(), expires_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,created_by,operation,key_hash)
);
CREATE INDEX user_management_expiry ON user_management_requests(tenant_id,expires_at);
CREATE INDEX user_management_budget ON user_management_requests(tenant_id,created_at);
ALTER TABLE user_management_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_management_requests FORCE ROW LEVEL SECURITY;
CREATE POLICY user_management_scope ON user_management_requests USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
CREATE POLICY user_management_expiry_delete ON user_management_requests AS RESTRICTIVE FOR DELETE USING(expires_at<=now());
-- 身份表仍承担登录前的全局身份解析；运行角色通过固定函数修改指定租户的账号，不取得表的写权限。
-- +goose StatementBegin
CREATE FUNCTION public.save_tenant_user(p_actor text,p_id text,p_username text,p_password_hash text,p_role text,p_active boolean,p_revision bigint,p_request text,p_context jsonb DEFAULT '{}')
RETURNS TABLE(id text,username text,role text,active boolean,revision bigint,created_at timestamptz,updated_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE scope text := current_setting('starbeacon.tenant_id',true); prior public.users%ROWTYPE; actor public.users%ROWTYPE; total bigint;
BEGIN
 IF scope IS NULL OR scope='' OR p_id IS NULL OR p_id !~ '^[a-z0-9][a-z0-9_-]{0,63}$' OR p_role IS NULL OR p_role NOT IN('admin','viewer') OR p_active IS NULL OR p_revision IS NULL OR p_revision<0 OR p_revision>=1000000 OR p_request IS NULL OR p_request !~ '^[a-z0-9][a-z0-9_-]{0,63}$' THEN RAISE EXCEPTION 'invalid_user' USING ERRCODE='22023'; END IF;
 IF p_context IS NULL OR jsonb_typeof(p_context)<>'object' OR octet_length(p_context::text)>16384 THEN RAISE EXCEPTION 'invalid_audit_context' USING ERRCODE='22023'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(scope||'/users',0));
 SELECT u.* INTO actor FROM public.users u JOIN public.tenants t ON t.id=u.tenant_id WHERE u.tenant_id=scope AND u.id=p_actor AND u.active AND u.role='admin' AND t.active FOR UPDATE OF u,t;
 IF NOT FOUND THEN RAISE EXCEPTION 'actor_unavailable' USING ERRCODE='42501'; END IF;
 IF p_revision=0 THEN
  IF p_username IS NULL OR octet_length(p_username)<3 OR octet_length(p_username)>64 OR p_username<>btrim(p_username) OR p_username ~ '[[:cntrl:]]' OR p_password_hash IS NULL OR p_password_hash !~ '^\$2[aby]\$10\$[./A-Za-z0-9]{53}$' THEN RAISE EXCEPTION 'invalid_user' USING ERRCODE='22023'; END IF;
  SELECT count(*) INTO total FROM public.users u WHERE u.tenant_id=scope;
  IF total>=500 THEN RAISE EXCEPTION 'user_quota' USING ERRCODE='P0003'; END IF;
  INSERT INTO public.users(id,tenant_id,username,password_hash,role,active) VALUES(p_id,scope,p_username,p_password_hash,p_role,p_active);
 ELSE
  IF p_username<>'' OR p_password_hash<>'' OR p_username IS NULL OR p_password_hash IS NULL THEN RAISE EXCEPTION 'credential_change_not_supported' USING ERRCODE='22023'; END IF;
  SELECT u.* INTO prior FROM public.users u WHERE u.tenant_id=scope AND u.id=p_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'user_not_found' USING ERRCODE='P0002'; END IF;
  IF prior.revision<>p_revision THEN RAISE EXCEPTION 'user_conflict' USING ERRCODE='40001'; END IF;
  IF p_id=p_actor AND (NOT p_active OR p_role<>'admin') THEN RAISE EXCEPTION 'current_user_protected' USING ERRCODE='P0004'; END IF;
  IF prior.role=p_role AND prior.active=p_active THEN RAISE EXCEPTION 'user_unchanged' USING ERRCODE='22023'; END IF;
  UPDATE public.users u SET role=p_role,active=p_active,revision=u.revision+1,updated_at=clock_timestamp() WHERE u.tenant_id=scope AND u.id=p_id;
  DELETE FROM public.sessions s WHERE s.user_id=p_id;
 END IF;
 INSERT INTO public.operation_audits(tenant_id,user_id,action,object_id,request_id,source_ip,user_agent,expires_at) VALUES(scope,p_actor,CASE WHEN p_revision=0 THEN 'users.create' ELSE 'users.change' END,p_id,COALESCE(NULLIF(p_context->>'request_id',''),p_request),COALESCE(p_context->>'source_ip',''),COALESCE(p_context->>'user_agent',''),now()+make_interval(days=>COALESCE((SELECT r.days FROM public.retention_policies r WHERE r.tenant_id=scope AND r.category='operations'),180)));
 RETURN QUERY SELECT u.id,u.username,u.role,u.active,u.revision,u.created_at,u.updated_at FROM public.users u WHERE u.tenant_id=scope AND u.id=p_id;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION public.save_tenant_user(text,text,text,text,text,boolean,bigint,text,jsonb) FROM PUBLIC;
ALTER TABLE retention_maintenance DROP CONSTRAINT retention_maintenance_next_category_check;
ALTER TABLE retention_maintenance ADD CONSTRAINT retention_maintenance_next_category_check CHECK(next_category BETWEEN 0 AND 22);
-- +goose Down
UPDATE retention_maintenance SET next_category=LEAST(next_category,21);
ALTER TABLE retention_maintenance DROP CONSTRAINT retention_maintenance_next_category_check;
ALTER TABLE retention_maintenance ADD CONSTRAINT retention_maintenance_next_category_check CHECK(next_category BETWEEN 0 AND 21);
DROP FUNCTION public.save_tenant_user(text,text,text,text,text,boolean,bigint,text,jsonb);
DROP TABLE user_management_requests;
ALTER TABLE users DROP COLUMN revision, DROP COLUMN updated_at;
