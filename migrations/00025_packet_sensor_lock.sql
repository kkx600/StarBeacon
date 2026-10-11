-- +goose Up
-- 行锁只用于冻结当前租户与注册代次的上传资格，不授予在线账号租户表写权限。
-- +goose StatementBegin
CREATE FUNCTION public.lock_packet_sensor(sensor_id text, registration_id text) RETURNS SETOF text
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp
AS $$
 SELECT s.id FROM public.sensors s JOIN public.tenants t ON t.id=s.tenant_id
 WHERE s.tenant_id=current_setting('starbeacon.tenant_id',true)
 AND s.id=$1 AND s.registration_id=$2 AND s.active AND t.active
 FOR SHARE OF t,s
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION public.lock_packet_sensor(text,text) FROM PUBLIC;
-- +goose Down
DROP FUNCTION public.lock_packet_sensor(text,text);
