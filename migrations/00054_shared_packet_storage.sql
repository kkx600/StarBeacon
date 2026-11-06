-- +goose Up
-- 原包存储由全部租户共享，容量取决于部署存储：不再按租户预占额度，空间不足时按全局最早优先回收。
DROP TABLE packet_archive_capacity;
CREATE INDEX packet_archive_age ON packet_archives(tenant_id,created_at,id) WHERE state='ready';
-- +goose Down
DROP INDEX packet_archive_age;
-- 回退后预占量从零开始；旧版本回收前需按租户重算 reserved_bytes。
CREATE TABLE packet_archive_capacity(tenant_id text PRIMARY KEY REFERENCES tenants(id),reserved_bytes bigint NOT NULL DEFAULT 0 CHECK(reserved_bytes>=0));
ALTER TABLE packet_archive_capacity ENABLE ROW LEVEL SECURITY;
ALTER TABLE packet_archive_capacity FORCE ROW LEVEL SECURITY;
CREATE POLICY packet_archive_capacity_scope ON packet_archive_capacity USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
