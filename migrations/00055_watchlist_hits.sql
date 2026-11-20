-- +goose Up
-- 观察名单命中只关联修订保存后接收的新告警，并绑定原修订；命中不表示攻击成立、误报结论或任何设备授权。
CREATE TABLE watchlist_hits (
 tenant_id text NOT NULL REFERENCES tenants(id), id text NOT NULL CHECK(id ~ '^whit_[a-f0-9]{56}$'),
 list_id text NOT NULL, list_revision bigint NOT NULL CHECK(list_revision BETWEEN 1 AND 1000000),
 definition_sha256 text NOT NULL CHECK(definition_sha256 ~ '^[a-f0-9]{64}$'),
 event_id text NOT NULL CHECK(event_id ~ '^[a-z0-9][a-z0-9_-]{0,63}$'), raw_sha256 text NOT NULL CHECK(raw_sha256 ~ '^[a-f0-9]{64}$'),
 sensor_id text NOT NULL, registration_id text NOT NULL,
 matches jsonb NOT NULL CHECK(jsonb_typeof(matches)='array' AND jsonb_array_length(matches) BETWEEN 1 AND 16 AND octet_length(matches::text)<=8192),
 severity text NOT NULL CHECK(severity IN('high','medium','low','unknown')),
 rule_id text NOT NULL CHECK(char_length(rule_id)<=64), rule_name text NOT NULL CHECK(char_length(rule_name)<=512),
 observed_at timestamptz NOT NULL, received_at timestamptz NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL CHECK(expires_at>created_at),
 PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,list_id,list_revision,event_id),
 FOREIGN KEY(tenant_id,list_id,list_revision) REFERENCES watchlist_revisions(tenant_id,list_id,revision)
);
CREATE INDEX watchlist_hit_list ON watchlist_hits(tenant_id,list_id,observed_at DESC,id DESC);
CREATE INDEX watchlist_hit_event ON watchlist_hits(tenant_id,event_id);
CREATE INDEX watchlist_hit_expiry ON watchlist_hits(tenant_id,expires_at);
-- 处理日计数与截断时刻限定逐条登记的规模；截断后的命中次数未统计。
CREATE TABLE watchlist_hit_days (
 tenant_id text NOT NULL REFERENCES tenants(id), list_id text NOT NULL, day date NOT NULL,
 recorded integer NOT NULL DEFAULT 0 CHECK(recorded BETWEEN 0 AND 10000), capped_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL CHECK(expires_at>created_at),
 PRIMARY KEY(tenant_id,list_id,day),
 FOREIGN KEY(tenant_id,list_id) REFERENCES watchlists(tenant_id,id)
);
CREATE INDEX watchlist_hit_day_expiry ON watchlist_hit_days(tenant_id,expires_at);
ALTER TABLE watchlist_hits ENABLE ROW LEVEL SECURITY;
ALTER TABLE watchlist_hits FORCE ROW LEVEL SECURITY;
ALTER TABLE watchlist_hit_days ENABLE ROW LEVEL SECURITY;
ALTER TABLE watchlist_hit_days FORCE ROW LEVEL SECURITY;
CREATE POLICY watchlist_hit_scope ON watchlist_hits USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
CREATE POLICY watchlist_hit_expiry_delete ON watchlist_hits AS RESTRICTIVE FOR DELETE USING(expires_at<=now());
CREATE POLICY watchlist_hit_day_scope ON watchlist_hit_days USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
CREATE POLICY watchlist_hit_day_expiry_delete ON watchlist_hit_days AS RESTRICTIVE FOR DELETE USING(expires_at<=now());
-- 未到期命中引用的历史修订不被回收；修订读取仍按其自身留存期，到期后命中只保留定义摘要与修订号。
DROP POLICY watchlist_revision_expiry ON watchlist_revisions;
CREATE POLICY watchlist_revision_expiry ON watchlist_revisions AS RESTRICTIVE FOR DELETE USING(expires_at<=now() AND NOT EXISTS(SELECT 1 FROM watchlists h WHERE h.tenant_id=watchlist_revisions.tenant_id AND h.id=watchlist_revisions.list_id AND h.revision=watchlist_revisions.revision) AND NOT EXISTS(SELECT 1 FROM watchlist_hits x WHERE x.tenant_id=watchlist_revisions.tenant_id AND x.list_id=watchlist_revisions.list_id AND x.list_revision=watchlist_revisions.revision));
ALTER TABLE retention_maintenance DROP CONSTRAINT retention_maintenance_next_category_check;
ALTER TABLE retention_maintenance ADD CONSTRAINT retention_maintenance_next_category_check CHECK(next_category BETWEEN 0 AND 46);

-- +goose Down
UPDATE retention_maintenance SET next_category=LEAST(next_category,44);
ALTER TABLE retention_maintenance DROP CONSTRAINT retention_maintenance_next_category_check;
ALTER TABLE retention_maintenance ADD CONSTRAINT retention_maintenance_next_category_check CHECK(next_category BETWEEN 0 AND 44);
DROP POLICY watchlist_revision_expiry ON watchlist_revisions;
CREATE POLICY watchlist_revision_expiry ON watchlist_revisions AS RESTRICTIVE FOR DELETE USING(expires_at<=now() AND NOT EXISTS(SELECT 1 FROM watchlists h WHERE h.tenant_id=watchlist_revisions.tenant_id AND h.id=watchlist_revisions.list_id AND h.revision=watchlist_revisions.revision));
DROP TABLE watchlist_hit_days;
DROP TABLE watchlist_hits;
