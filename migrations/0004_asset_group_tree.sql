-- Schema family 2: hierarchical asset groups for the ZeroTerm client tree.
-- parent_id forms a forest; sort_order orders siblings. Existing groups become roots with sort_order 0.
ALTER TABLE asset_groups ADD COLUMN parent_id uuid REFERENCES asset_groups(id) ON DELETE RESTRICT;
ALTER TABLE asset_groups ADD COLUMN sort_order integer NOT NULL DEFAULT 0;
-- A group can never be its own parent; longer cycles are rejected in the store by walking the ancestor chain.
ALTER TABLE asset_groups ADD CONSTRAINT asset_groups_no_self_parent CHECK (parent_id IS DISTINCT FROM id);
CREATE INDEX asset_groups_parent ON asset_groups(parent_id,sort_order,name,id);
