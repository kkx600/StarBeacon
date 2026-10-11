-- +goose Up
ALTER TABLE user_management_requests DROP CONSTRAINT user_management_requests_operation_check;
ALTER TABLE user_management_requests ADD CONSTRAINT user_management_requests_operation_check CHECK(operation IN('create','change','password'));
-- 计数是按账号有界的验证预算，不保存密码、密码指纹或请求正文。
CREATE TABLE password_attempts (
 tenant_id text NOT NULL REFERENCES tenants(id), user_id text NOT NULL REFERENCES users(id),
 window_started timestamptz NOT NULL DEFAULT clock_timestamp(), attempts integer NOT NULL CHECK(attempts BETWEEN 1 AND 11),
 PRIMARY KEY(tenant_id,user_id)
);
ALTER TABLE password_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE password_attempts FORCE ROW LEVEL SECURITY;
CREATE POLICY password_attempts_scope ON password_attempts USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
-- 固定函数以最小权限串行化身份检查与会话创建，运行角色不取得身份表 UPDATE 权限。
-- +goose StatementBegin
CREATE FUNCTION public.create_tenant_session(p_actor text,p_role text,p_revision bigint,p_token text,p_csrf text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE scope text := current_setting('starbeacon.tenant_id',true); actual bigint;
BEGIN
 IF scope IS NULL OR scope='' OR p_actor IS NULL OR p_actor !~ '^[a-z0-9][a-z0-9_-]{0,63}$' OR p_role IS NULL OR p_role NOT IN('admin','viewer') OR p_revision IS NULL OR p_revision<1 OR p_revision>1000000 OR p_token IS NULL OR p_token !~ '^[a-f0-9]{64}$' OR p_csrf IS NULL OR p_csrf !~ '^[a-f0-9]{64}$' THEN RETURN false; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(scope||'/users',0));
 SELECT u.revision INTO actual FROM public.users u JOIN public.tenants t ON t.id=u.tenant_id WHERE u.tenant_id=scope AND u.id=p_actor AND u.role=p_role AND u.active AND t.active FOR SHARE OF u,t;
 IF NOT FOUND OR actual<>p_revision THEN RETURN false; END IF;
 INSERT INTO public.sessions(token_hash,user_id,csrf_token,expires_at) VALUES(p_token,p_actor,p_csrf,clock_timestamp()+interval '8 hours');
 RETURN true;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION public.create_tenant_session(text,text,bigint,text,text) FROM PUBLIC;
-- +goose StatementBegin
CREATE FUNCTION public.change_tenant_password(p_actor text,p_actor_revision bigint,p_actor_hash text,p_id text,p_revision bigint,p_password_hash text,p_request text,p_context jsonb DEFAULT '{}')
RETURNS TABLE(id text,username text,role text,active boolean,revision bigint,created_at timestamptz,updated_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE scope text := current_setting('starbeacon.tenant_id',true); prior public.users%ROWTYPE; actor public.users%ROWTYPE;
BEGIN
 IF scope IS NULL OR scope='' OR p_actor IS NULL OR p_actor !~ '^[a-z0-9][a-z0-9_-]{0,63}$' OR p_id IS NULL OR p_id !~ '^[a-z0-9][a-z0-9_-]{0,63}$' OR p_revision IS NULL OR p_revision<1 OR p_revision>=1000000 OR p_actor_revision IS NULL OR p_actor_revision<1 OR p_actor_revision>1000000 OR p_actor_hash IS NULL OR p_password_hash IS NULL OR p_password_hash !~ '^\$2[aby]\$10\$[./A-Za-z0-9]{53}$' OR p_request IS NULL OR p_request !~ '^[a-z0-9][a-z0-9_-]{0,63}$' THEN RAISE EXCEPTION 'invalid_password_change' USING ERRCODE='22023'; END IF;
 IF p_context IS NULL OR jsonb_typeof(p_context)<>'object' OR octet_length(p_context::text)>16384 THEN RAISE EXCEPTION 'invalid_audit_context' USING ERRCODE='22023'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(scope||'/users',0));
 SELECT u.* INTO actor FROM public.users u JOIN public.tenants t ON t.id=u.tenant_id WHERE u.tenant_id=scope AND u.id=p_actor AND u.active AND t.active FOR UPDATE OF u,t;
 IF NOT FOUND OR (p_actor<>p_id AND actor.role<>'admin') THEN RAISE EXCEPTION 'actor_unavailable' USING ERRCODE='42501'; END IF;
 IF actor.revision<>p_actor_revision OR actor.password_hash<>p_actor_hash THEN RAISE EXCEPTION 'actor_changed' USING ERRCODE='40001'; END IF;
 SELECT u.* INTO prior FROM public.users u WHERE u.tenant_id=scope AND u.id=p_id FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'user_not_found' USING ERRCODE='P0002'; END IF;
 IF prior.revision<>p_revision THEN RAISE EXCEPTION 'user_conflict' USING ERRCODE='40001'; END IF;
 UPDATE public.users u SET password_hash=p_password_hash,revision=u.revision+1,updated_at=clock_timestamp() WHERE u.tenant_id=scope AND u.id=p_id;
 DELETE FROM public.sessions s WHERE s.user_id=p_id;
 INSERT INTO public.operation_audits(tenant_id,user_id,action,object_id,request_id,source_ip,user_agent,expires_at) VALUES(scope,p_actor,CASE WHEN p_actor=p_id THEN 'users.password.change' ELSE 'users.password.reset' END,p_id,COALESCE(NULLIF(p_context->>'request_id',''),p_request),COALESCE(p_context->>'source_ip',''),COALESCE(p_context->>'user_agent',''),now()+make_interval(days=>COALESCE((SELECT r.days FROM public.retention_policies r WHERE r.tenant_id=scope AND r.category='operations'),180)));
 RETURN QUERY SELECT u.id,u.username,u.role,u.active,u.revision,u.created_at,u.updated_at FROM public.users u WHERE u.tenant_id=scope AND u.id=p_id;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION public.change_tenant_password(text,bigint,text,text,bigint,text,text,jsonb) FROM PUBLIC;
-- +goose Down
DROP FUNCTION public.change_tenant_password(text,bigint,text,text,bigint,text,text,jsonb);
DROP FUNCTION public.create_tenant_session(text,text,bigint,text,text);
DROP TABLE password_attempts;
-- 迁移事务内恢复既有回执契约，提交前重新启用行级隔离。
ALTER TABLE user_management_requests DISABLE ROW LEVEL SECURITY;
DELETE FROM user_management_requests WHERE operation='password';
ALTER TABLE user_management_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_management_requests DROP CONSTRAINT user_management_requests_operation_check;
ALTER TABLE user_management_requests ADD CONSTRAINT user_management_requests_operation_check CHECK(operation IN('create','change'));
