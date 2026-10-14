-- Schema family 2: administrator deletion of assets and target accounts.
-- Deletion is a soft delete, matching users.deleted_at: the row stays so that connection and audit
-- history keeps its foreign keys, while the resource leaves every catalog immediately.
ALTER TABLE assets ADD COLUMN deleted_at timestamptz;
ALTER TABLE assets ADD CONSTRAINT assets_deleted_disables CHECK(deleted_at IS NULL OR NOT enabled);
ALTER TABLE target_accounts ADD COLUMN deleted_at timestamptz;
ALTER TABLE target_accounts ADD CONSTRAINT target_accounts_deleted_disables CHECK(deleted_at IS NULL OR NOT enabled);
-- A deleted account releases its display name inside the asset, like a deleted username is released.
-- A partial UNIQUE INDEX, not a table constraint: PostgreSQL only accepts a WHERE clause on the index form.
ALTER TABLE target_accounts DROP CONSTRAINT target_accounts_asset_id_label_key;
CREATE UNIQUE INDEX target_accounts_active_label_key ON target_accounts(asset_id,label) WHERE deleted_at IS NULL;
CREATE INDEX assets_active ON assets(created_at,id) WHERE deleted_at IS NULL;
