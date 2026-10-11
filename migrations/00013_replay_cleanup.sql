-- +goose Up
ALTER TABLE replay_samples DROP CONSTRAINT replay_samples_state_check;
ALTER TABLE replay_samples ADD CONSTRAINT replay_samples_state_check
 CHECK(state IN ('uploading','ready','failed','deleting'));
CREATE INDEX replay_samples_pending_cleanup
 ON replay_samples(tenant_id,state,created_at,id)
 WHERE state IN ('uploading','failed','deleting');

-- +goose Down
UPDATE replay_samples SET state='failed' WHERE state='deleting';
DROP INDEX replay_samples_pending_cleanup;
ALTER TABLE replay_samples DROP CONSTRAINT replay_samples_state_check;
ALTER TABLE replay_samples ADD CONSTRAINT replay_samples_state_check
 CHECK(state IN ('uploading','ready','failed'));
