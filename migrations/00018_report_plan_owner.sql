-- +goose Up
-- SELECT 锁定需要写权限；仅暴露本租户资格核验，不能由在线账号改写用户或租户。
-- +goose StatementBegin
CREATE FUNCTION public.lock_report_plan_owner(owner_id text) RETURNS SETOF text
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp
AS $$
 SELECT u.id FROM public.users u JOIN public.tenants t ON t.id=u.tenant_id
 WHERE u.tenant_id=current_setting('starbeacon.tenant_id',true) AND u.id=$1
 AND u.active AND u.role='admin' AND t.active
 FOR SHARE OF t,u
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION public.lock_report_plan_owner(text) FROM PUBLIC;
-- +goose Down
DROP FUNCTION public.lock_report_plan_owner(text);
