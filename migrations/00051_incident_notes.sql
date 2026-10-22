-- +goose Up
CREATE TABLE incident_notes (
 tenant_id text NOT NULL REFERENCES tenants(id), incident_id text NOT NULL, id text NOT NULL,
 author_id text NOT NULL REFERENCES users(id), revision bigint NOT NULL CHECK(revision BETWEEN 1 AND 1000),
 state text NOT NULL CHECK(state IN('active','withdrawn')), record jsonb NOT NULL,
 created_at timestamptz NOT NULL, expires_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,incident_id,id),
 FOREIGN KEY(tenant_id,incident_id) REFERENCES incidents(tenant_id,id)
);
CREATE INDEX incident_note_list ON incident_notes(tenant_id,incident_id,created_at DESC,id DESC);
CREATE INDEX incident_note_expiry ON incident_notes(tenant_id,expires_at);
CREATE TABLE incident_note_changes (
 tenant_id text NOT NULL REFERENCES tenants(id), incident_id text NOT NULL, note_id text NOT NULL,
 revision bigint NOT NULL CHECK(revision BETWEEN 1 AND 1000), created_by text NOT NULL,
 operation text NOT NULL CHECK(operation IN('create','change')),
 idempotency_key_hash text NOT NULL, input_hash text NOT NULL, record jsonb NOT NULL,
 created_at timestamptz NOT NULL, expires_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,note_id,revision), UNIQUE(tenant_id,created_by,operation,idempotency_key_hash),
 FOREIGN KEY(tenant_id,incident_id,note_id) REFERENCES incident_notes(tenant_id,incident_id,id)
);
CREATE INDEX incident_note_change_history ON incident_note_changes(tenant_id,incident_id,note_id,revision DESC);
CREATE INDEX incident_note_change_budget ON incident_note_changes(tenant_id,created_at);
CREATE INDEX incident_note_change_expiry ON incident_note_changes(tenant_id,expires_at);
ALTER TABLE incident_notes ENABLE ROW LEVEL SECURITY;
ALTER TABLE incident_notes FORCE ROW LEVEL SECURITY;
CREATE POLICY incident_note_scope ON incident_notes USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
ALTER TABLE incident_note_changes ENABLE ROW LEVEL SECURITY;
ALTER TABLE incident_note_changes FORCE ROW LEVEL SECURITY;
CREATE POLICY incident_note_change_scope ON incident_note_changes USING(tenant_id=current_setting('starbeacon.tenant_id',true)) WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
CREATE POLICY incident_note_history_expiry_delete ON incident_note_changes AS RESTRICTIVE FOR DELETE USING(expires_at<=now() AND EXISTS(SELECT 1 FROM incidents i WHERE i.tenant_id=incident_note_changes.tenant_id AND i.id=incident_note_changes.incident_id AND i.state='closed'));
CREATE POLICY incident_note_expiry_delete ON incident_notes AS RESTRICTIVE FOR DELETE USING(expires_at<=now() AND EXISTS(SELECT 1 FROM incidents i WHERE i.tenant_id=incident_notes.tenant_id AND i.id=incident_notes.incident_id AND i.state='closed') AND NOT EXISTS(SELECT 1 FROM incident_note_changes c WHERE c.tenant_id=incident_notes.tenant_id AND c.note_id=incident_notes.id));
DROP POLICY incident_expiry_delete ON incidents;
CREATE POLICY incident_expiry_delete ON incidents AS RESTRICTIVE FOR DELETE USING(state='closed' AND expires_at<=now() AND NOT EXISTS(SELECT 1 FROM incident_changes c WHERE c.tenant_id=incidents.tenant_id AND c.incident_id=incidents.id) AND NOT EXISTS(SELECT 1 FROM incident_tasks t WHERE t.tenant_id=incidents.tenant_id AND t.incident_id=incidents.id) AND NOT EXISTS(SELECT 1 FROM incident_notes n WHERE n.tenant_id=incidents.tenant_id AND n.incident_id=incidents.id));
-- +goose Down
DROP POLICY incident_expiry_delete ON incidents;
CREATE POLICY incident_expiry_delete ON incidents AS RESTRICTIVE FOR DELETE USING(state='closed' AND expires_at<=now() AND NOT EXISTS(SELECT 1 FROM incident_changes c WHERE c.tenant_id=incidents.tenant_id AND c.incident_id=incidents.id) AND NOT EXISTS(SELECT 1 FROM incident_tasks t WHERE t.tenant_id=incidents.tenant_id AND t.incident_id=incidents.id));
DROP TABLE incident_note_changes,incident_notes;
