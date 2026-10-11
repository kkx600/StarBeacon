-- +goose Up
ALTER TABLE sensor_tasks ADD COLUMN replay_sample_id text;
UPDATE sensor_tasks
 SET replay_sample_id=(convert_from(command,'UTF8')::jsonb)->'payload'->>'sample_id'
 WHERE kind='rules.replay';
ALTER TABLE sensor_tasks ADD CONSTRAINT sensor_tasks_replay_reference
 CHECK((kind='rules.replay')=(replay_sample_id IS NOT NULL));
ALTER TABLE sensor_tasks ADD CONSTRAINT sensor_tasks_replay_identity
 CHECK(replay_sample_id IS NULL OR replay_sample_id ~ '^[a-z0-9][a-z0-9_-]{0,63}$');
CREATE INDEX sensor_tasks_replay_lease
 ON sensor_tasks(tenant_id,replay_sample_id,expires_at)
 WHERE kind='rules.replay' AND state IN ('queued','delivered','running');

-- +goose Down
DROP INDEX sensor_tasks_replay_lease;
ALTER TABLE sensor_tasks DROP CONSTRAINT sensor_tasks_replay_reference;
ALTER TABLE sensor_tasks DROP CONSTRAINT sensor_tasks_replay_identity;
ALTER TABLE sensor_tasks DROP COLUMN replay_sample_id;
