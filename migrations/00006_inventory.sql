-- +goose Up
CREATE TABLE inventory_objects (
 tenant_id text NOT NULL REFERENCES tenants(id), kind text NOT NULL CHECK(kind IN ('assets','groups','networks')),
 id text NOT NULL, name text NOT NULL, revision bigint NOT NULL CHECK(revision>0),
 group_id text, group_kind text GENERATED ALWAYS AS ('groups') STORED,
 active boolean NOT NULL, data jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(tenant_id,kind,id),
 FOREIGN KEY(tenant_id,group_kind,group_id) REFERENCES inventory_objects(tenant_id,kind,id),
 CHECK(kind<>'groups' OR group_id IS NULL)
);
CREATE INDEX inventory_group_members ON inventory_objects(tenant_id,group_id) WHERE active;
CREATE TABLE inventory_history (
 tenant_id text NOT NULL, kind text NOT NULL, id text NOT NULL, revision bigint NOT NULL,
 name text NOT NULL, active boolean NOT NULL, data jsonb NOT NULL,
 valid_from timestamptz NOT NULL, expires_at timestamptz NOT NULL DEFAULT now()+interval '180 days',
 PRIMARY KEY(tenant_id,kind,id,revision),
 FOREIGN KEY(tenant_id,kind,id) REFERENCES inventory_objects(tenant_id,kind,id)
);
CREATE INDEX inventory_history_time ON inventory_history(tenant_id,kind,id,valid_from DESC);
ALTER TABLE inventory_objects ENABLE ROW LEVEL SECURITY;
ALTER TABLE inventory_objects FORCE ROW LEVEL SECURITY;
CREATE POLICY inventory_scope ON inventory_objects USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
ALTER TABLE inventory_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE inventory_history FORCE ROW LEVEL SECURITY;
CREATE POLICY inventory_history_scope ON inventory_history USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
INSERT INTO retention_policies(tenant_id,category,days) SELECT id,'asset_history',180 FROM tenants ON CONFLICT DO NOTHING;
-- +goose Down
DELETE FROM retention_policies WHERE category='asset_history';
DROP TABLE inventory_history,inventory_objects;
