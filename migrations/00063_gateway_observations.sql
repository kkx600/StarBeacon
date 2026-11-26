-- +goose Up
ALTER TABLE gateway_block_requests
 ADD COLUMN gateway_result jsonb CHECK(gateway_result IS NULL OR jsonb_typeof(gateway_result)='object'),
 ADD COLUMN follow_up_state text NOT NULL DEFAULT 'none' CHECK(follow_up_state IN ('none','pending','skipped','issued')),
 ADD COLUMN follow_up_code text NOT NULL DEFAULT '',
 ADD COLUMN follow_up_until timestamptz,
 ADD COLUMN follow_up_at timestamptz,
 ADD COLUMN follow_up_task_id text,
 ADD COLUMN notice_pending boolean NOT NULL DEFAULT false,
 ADD CONSTRAINT gateway_follow_up_bound CHECK(
   (follow_up_state='pending')=(follow_up_until IS NOT NULL)
   AND (follow_up_state='issued')=(follow_up_at IS NOT NULL AND follow_up_task_id IS NOT NULL)
   AND (follow_up_state='none' OR (gateway_result IS NOT NULL AND state='authorized'))
 );
CREATE INDEX gateway_block_record_order ON gateway_block_requests(tenant_id,created_at DESC,id DESC);
CREATE INDEX gateway_block_follow_up_pending ON gateway_block_requests(tenant_id,sensor_id,registration_id,follow_up_until,id)
 WHERE follow_up_state='pending';
CREATE INDEX gateway_block_follow_up_budget ON gateway_block_requests(tenant_id,follow_up_at)
 WHERE follow_up_state='issued';
CREATE INDEX gateway_block_notice_pending ON gateway_block_requests(tenant_id,created_at,id) WHERE notice_pending;

-- +goose Down
DROP INDEX gateway_block_notice_pending,gateway_block_follow_up_budget,gateway_block_follow_up_pending,gateway_block_record_order;
ALTER TABLE gateway_block_requests DROP CONSTRAINT gateway_follow_up_bound,
 DROP COLUMN notice_pending,DROP COLUMN follow_up_task_id,DROP COLUMN follow_up_at,DROP COLUMN follow_up_until,
 DROP COLUMN follow_up_code,DROP COLUMN follow_up_state,DROP COLUMN gateway_result;
