-- +goose Up
-- 上传 PCAP 保持来源未知；合成材料显式记录原始字节摘要与编码参数。
ALTER TABLE replay_samples ADD COLUMN origin jsonb NOT NULL DEFAULT 'null'::jsonb;
ALTER TABLE replay_samples ADD CONSTRAINT replay_sample_origin_check
 CHECK(origin='null'::jsonb OR (jsonb_typeof(origin)='object' AND octet_length(origin::text)<=1024));
-- +goose Down
ALTER TABLE replay_samples DROP COLUMN origin;
