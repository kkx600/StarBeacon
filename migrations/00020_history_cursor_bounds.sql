-- +goose Up
-- 分类共 18 项。旧边界允许的 18 不对应任何分类，恢复到首项后按预算继续清理。
ALTER TABLE retention_maintenance DROP CONSTRAINT retention_maintenance_next_category_check;
UPDATE retention_maintenance SET next_category=0 WHERE next_category>17;
ALTER TABLE retention_maintenance ADD CONSTRAINT retention_maintenance_next_category_check CHECK(next_category BETWEEN 0 AND 17);
-- +goose Down
ALTER TABLE retention_maintenance DROP CONSTRAINT retention_maintenance_next_category_check;
ALTER TABLE retention_maintenance ADD CONSTRAINT retention_maintenance_next_category_check CHECK(next_category BETWEEN 0 AND 18);
