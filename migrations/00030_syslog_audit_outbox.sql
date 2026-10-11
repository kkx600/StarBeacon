-- +goose Up
ALTER TABLE notification_channels ADD COLUMN streams jsonb NOT NULL DEFAULT '["alerts"]';
ALTER TABLE notification_channels ADD CONSTRAINT notification_streams_valid CHECK (
 jsonb_typeof(streams)='array' AND jsonb_array_length(streams) BETWEEN 1 AND 3
 AND streams <@ '["alerts","operations","logins"]'::jsonb
 AND jsonb_array_length(streams)=((streams ? 'alerts')::integer+(streams ? 'operations')::integer+(streams ? 'logins')::integer)
 AND (kind IN ('syslog_tls','syslog_tcp') OR streams='["alerts"]'::jsonb)
);

-- 原始审计与投递材料在同一事务提交；工作进程中断不丢失尚未投递的日志。
-- 使用调用者权限及租户 RLS，不赋予触发器跨租户读取能力。
-- +goose StatementBegin
CREATE FUNCTION public.enqueue_syslog_audit() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE
 category text;
 entry jsonb;
 field text;
 maximum integer;
 clipped boolean := false;
 destination record;
 batch_key text;
 batch_id text;
 delivery_id text;
 expiry timestamptz;
 inserted integer;
BEGIN
 IF NEW.tenant_id IS NULL THEN RETURN NEW; END IF;
 IF TG_TABLE_NAME='operation_audits' THEN
  category := 'operations';
  entry := jsonb_build_object('id',NEW.id::text,'actor',NEW.user_id,'action',NEW.action,'object_id',NEW.object_id);
 ELSE
  category := 'logins';
  entry := jsonb_build_object('id',NEW.id::text,'actor',NEW.username,'action','auth.password_verification','object_id','',
   'success',NEW.success,'phase',NEW.phase);
 END IF;
 entry := entry || jsonb_build_object('stream',category,'timestamp',NEW.created_at,'request_id',NEW.request_id,
  'source_ip',NEW.source_ip,'user_agent',NEW.user_agent);
 FOREACH field IN ARRAY ARRAY['actor','action','object_id','request_id','source_ip','user_agent'] LOOP
  maximum := CASE field WHEN 'actor' THEN 256 WHEN 'object_id' THEN 1024 WHEN 'source_ip' THEN 45 WHEN 'user_agent' THEN 512 ELSE 128 END;
  clipped := clipped OR length(entry->>field)>maximum OR (entry->>field) ~ '[[:cntrl:]]';
  entry := jsonb_set(entry,ARRAY[field],to_jsonb(regexp_replace(left(entry->>field,maximum),'[[:cntrl:]]',' ','g')));
 END LOOP;
 entry := entry || jsonb_build_object('truncated',clipped);
 -- 冒号保留为内部来源命名空间，探针上报的合法批次标识不能与其碰撞。
 batch_key := 'audit:' || category || ':' || NEW.id::text;
 expiry := LEAST(NEW.expires_at,now()+make_interval(days=>COALESCE(
  (SELECT rp.days FROM public.retention_policies rp WHERE rp.tenant_id=NEW.tenant_id AND rp.category='notifications'),180)));
 FOR destination IN SELECT id,revision,enabled,muted_until FROM public.notification_channels
  WHERE tenant_id=NEW.tenant_id AND kind IN ('syslog_tls','syslog_tcp') AND streams ? category
  ORDER BY id LIMIT 50 FOR SHARE LOOP
  batch_id := 'audit_notice_' || md5(NEW.tenant_id || '/' || batch_key || '/' || destination.id);
  delivery_id := 'audit_delivery_' || md5(batch_id);
  INSERT INTO public.notification_batches(tenant_id,id,upstream_batch_id,channel_id,channel_revision,message,expires_at)
   VALUES(NEW.tenant_id,batch_id,batch_key,destination.id,destination.revision,
    jsonb_build_object('tenant_id',NEW.tenant_id,'batch_id','audit_' || category || '_' || NEW.id::text,
     'created_at',clock_timestamp(),'alerts','[]'::jsonb,'logs',jsonb_build_array(entry),'test',false),expiry)
   ON CONFLICT(tenant_id,upstream_batch_id,channel_id) DO NOTHING;
  GET DIAGNOSTICS inserted=ROW_COUNT;
  IF inserted=1 THEN
   INSERT INTO public.notification_deliveries(tenant_id,id,batch_id,recipient,state,expires_at)
    VALUES(NEW.tenant_id,delivery_id,batch_id,'',CASE WHEN destination.enabled AND
     (destination.muted_until IS NULL OR destination.muted_until<=now()) THEN 'queued' ELSE 'suppressed' END,expiry);
  END IF;
 END LOOP;
 RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER operation_syslog_outbox AFTER INSERT ON operation_audits FOR EACH ROW EXECUTE FUNCTION public.enqueue_syslog_audit();
CREATE TRIGGER login_syslog_outbox AFTER INSERT ON login_audits FOR EACH ROW EXECUTE FUNCTION public.enqueue_syslog_audit();

-- +goose Down
DROP TRIGGER login_syslog_outbox ON login_audits;
DROP TRIGGER operation_syslog_outbox ON operation_audits;
DROP FUNCTION public.enqueue_syslog_audit();
ALTER TABLE notification_channels DROP COLUMN streams;
