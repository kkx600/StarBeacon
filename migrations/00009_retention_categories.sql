-- +goose Up
-- 缺失类别继承 180 天默认值，已有租户自定义时长保持原值。
INSERT INTO retention_policies(tenant_id,category,days)
SELECT t.id,c.category,180 FROM tenants t
CROSS JOIN (VALUES ('alerts'),('pcap'),('network'),('operations'),('logins'),
 ('notifications'),('reports'),('files'),('asset_history'),('models')) AS c(category)
ON CONFLICT(tenant_id,category) DO NOTHING;

-- +goose Down
-- 回退代码不能销毁用户已生效的留存策略。
SELECT 1;
