CREATE TABLE asset_groups (
    id uuid PRIMARY KEY,
    name text NOT NULL UNIQUE CHECK (char_length(name) BETWEEN 1 AND 128),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TRIGGER asset_groups_revision BEFORE UPDATE ON asset_groups
    FOR EACH ROW EXECUTE FUNCTION revision_never_decreases('revision');
ALTER TABLE assets ADD COLUMN group_id uuid REFERENCES asset_groups(id);
CREATE INDEX assets_group ON assets(group_id,created_at,id);
