-- +goose Up
CREATE TABLE watchlists (
 tenant_id text NOT NULL REFERENCES tenants(id),id text NOT NULL,
 revision bigint NOT NULL CHECK(revision BETWEEN 1 AND 1000000),
 name text NOT NULL CHECK(char_length(name) BETWEEN 1 AND 128),
 kind text NOT NULL CHECK(kind IN ('protect','observe')),active boolean NOT NULL,
 PRIMARY KEY(tenant_id,id)
);
CREATE TABLE watchlist_revisions (
 tenant_id text NOT NULL REFERENCES tenants(id),list_id text NOT NULL,
 revision bigint NOT NULL CHECK(revision BETWEEN 1 AND 1000000),
 name text NOT NULL CHECK(char_length(name) BETWEEN 1 AND 128),
 description text NOT NULL CHECK(char_length(description) BETWEEN 1 AND 1000),active boolean NOT NULL,
 definition jsonb NOT NULL CHECK(jsonb_typeof(definition)='object' AND octet_length(definition::text)<=32768),
 definition_sha256 text NOT NULL CHECK(definition_sha256 ~ '^[a-f0-9]{64}$'),
 created_by text NOT NULL REFERENCES users(id),key_hash text NOT NULL,input_hash text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),expires_at timestamptz NOT NULL CHECK(expires_at>created_at),
 PRIMARY KEY(tenant_id,list_id,revision),UNIQUE(tenant_id,created_by,key_hash),
 FOREIGN KEY(tenant_id,list_id) REFERENCES watchlists(tenant_id,id) DEFERRABLE INITIALLY DEFERRED
);
ALTER TABLE watchlists ADD CONSTRAINT watchlist_current FOREIGN KEY(tenant_id,id,revision) REFERENCES watchlist_revisions(tenant_id,list_id,revision) DEFERRABLE INITIALLY DEFERRED;
CREATE INDEX watchlist_expiry ON watchlist_revisions(tenant_id,expires_at);
CREATE INDEX watchlist_budget ON watchlist_revisions(tenant_id,created_at);
ALTER TABLE watchlists ENABLE ROW LEVEL SECURITY;
ALTER TABLE watchlists FORCE ROW LEVEL SECURITY;
CREATE POLICY watchlist_scope ON watchlists USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
ALTER TABLE watchlist_revisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE watchlist_revisions FORCE ROW LEVEL SECURITY;
CREATE POLICY watchlist_revision_scope ON watchlist_revisions USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
CREATE POLICY watchlist_revision_expiry ON watchlist_revisions AS RESTRICTIVE FOR DELETE USING(expires_at<=now() AND NOT EXISTS(SELECT 1 FROM watchlists h WHERE h.tenant_id=watchlist_revisions.tenant_id AND h.id=watchlist_revisions.list_id AND h.revision=watchlist_revisions.revision));
-- +goose Down
ALTER TABLE watchlists DROP CONSTRAINT watchlist_current;
DROP TABLE watchlist_revisions,watchlists;
