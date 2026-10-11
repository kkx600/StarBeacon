-- +goose Up
ALTER TABLE operation_audits ADD COLUMN reason text NOT NULL DEFAULT '' CHECK(octet_length(reason)<=512);
-- +goose Down
ALTER TABLE operation_audits DROP COLUMN reason;
