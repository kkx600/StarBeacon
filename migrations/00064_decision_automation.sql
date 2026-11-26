-- +goose Up
CREATE TABLE decision_automation_settings (
 tenant_id text PRIMARY KEY REFERENCES tenants(id),
 revision bigint NOT NULL CHECK(revision BETWEEN 1 AND 9007199254740991),
 ceiling text NOT NULL CHECK(ceiling IN ('observe','approval','conditional','full')),
 paused boolean NOT NULL
);
ALTER TABLE decision_automation_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE decision_automation_settings FORCE ROW LEVEL SECURITY;
CREATE POLICY decision_automation_scope ON decision_automation_settings
 USING(tenant_id=current_setting('starbeacon.tenant_id',true))
 WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));

ALTER TABLE decision_continuous_runs ADD COLUMN confirmation_deadline timestamptz
 CHECK(confirmation_deadline IS NULL OR (state='awaiting_confirmation' AND confirmation_deadline>created_at AND confirmation_deadline<=expires_at));
CREATE INDEX decision_plan_owner_order ON decision_continuous_runs(tenant_id,created_by,created_at DESC,id DESC);
CREATE INDEX decision_plan_by_event ON decision_continuous_runs(tenant_id,policy_id,policy_revision,event_id,raw_sha256)
 WHERE state='awaiting_confirmation';
CREATE INDEX decision_plan_deadline ON decision_continuous_runs
 (tenant_id,(COALESCE(confirmation_deadline,timezone('UTC',timezone('UTC',created_at)+interval '15 minutes'))),id)
 WHERE state='awaiting_confirmation';

CREATE TABLE decision_plan_reviews (
 tenant_id text NOT NULL REFERENCES tenants(id),
 evaluation_id text NOT NULL,
 plan_sha256 text NOT NULL CHECK(plan_sha256 ~ '^[a-f0-9]{64}$'),
 state text NOT NULL CHECK(state IN ('rejected','expired')),
 actor_id text NOT NULL,
 reason text NOT NULL,
 created_at timestamptz NOT NULL,
 expires_at timestamptz NOT NULL CHECK(expires_at>created_at),
 PRIMARY KEY(tenant_id,evaluation_id),
 CHECK((state='rejected' AND actor_id<>'' AND char_length(reason) BETWEEN 1 AND 500)
       OR (state='expired' AND actor_id='' AND reason=''))
);
CREATE INDEX decision_plan_review_expiry ON decision_plan_reviews(tenant_id,expires_at);
ALTER TABLE decision_plan_reviews ENABLE ROW LEVEL SECURITY;
ALTER TABLE decision_plan_reviews FORCE ROW LEVEL SECURITY;
CREATE POLICY decision_plan_review_scope ON decision_plan_reviews
 USING(tenant_id=current_setting('starbeacon.tenant_id',true))
 WITH CHECK(tenant_id=current_setting('starbeacon.tenant_id',true));
CREATE POLICY decision_plan_review_expiry_delete ON decision_plan_reviews AS RESTRICTIVE FOR DELETE USING(expires_at<=now());
ALTER TABLE retention_maintenance DROP CONSTRAINT retention_maintenance_next_category_check;
ALTER TABLE retention_maintenance ADD CONSTRAINT retention_maintenance_next_category_check CHECK(next_category BETWEEN 0 AND 50);

-- +goose Down
UPDATE retention_maintenance SET next_category=0 WHERE next_category>49;
ALTER TABLE retention_maintenance DROP CONSTRAINT retention_maintenance_next_category_check;
ALTER TABLE retention_maintenance ADD CONSTRAINT retention_maintenance_next_category_check CHECK(next_category BETWEEN 0 AND 49);
DROP TABLE decision_plan_reviews;
DROP INDEX decision_plan_deadline,decision_plan_by_event,decision_plan_owner_order;
ALTER TABLE decision_continuous_runs DROP COLUMN confirmation_deadline;
DROP TABLE decision_automation_settings;
