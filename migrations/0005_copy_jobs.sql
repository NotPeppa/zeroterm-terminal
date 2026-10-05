-- Minimal single-file copy metadata; not a queue, outbox or resumable transfer.
CREATE TABLE copy_jobs (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users(id),
    login_session_id uuid NOT NULL REFERENCES login_sessions(id),
    gateway_id text NOT NULL,
    source_asset_id uuid NOT NULL REFERENCES assets(id),
    source_account_id uuid NOT NULL,
    source_path text NOT NULL CHECK (octet_length(source_path) BETWEEN 1 AND 4096),
    destination_asset_id uuid NOT NULL REFERENCES assets(id),
    destination_account_id uuid NOT NULL,
    destination_path text NOT NULL CHECK (octet_length(destination_path) BETWEEN 1 AND 4096),
    state text NOT NULL DEFAULT 'queued' CHECK (state IN ('queued','running','completed','failed','cancelled','interrupted')),
    bytes_total bigint CHECK (bytes_total>=0),
    bytes_copied bigint NOT NULL DEFAULT 0 CHECK (bytes_copied>=0 AND (bytes_total IS NULL OR bytes_copied<=bytes_total)),
    failure_code text,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    started_at timestamptz,
    ended_at timestamptz,
    FOREIGN KEY(source_account_id,source_asset_id) REFERENCES target_accounts(id,asset_id),
    FOREIGN KEY(destination_account_id,destination_asset_id) REFERENCES target_accounts(id,asset_id)
);
CREATE INDEX copy_jobs_owner_page ON copy_jobs(user_id,created_at,id);
CREATE INDEX copy_jobs_gateway_state ON copy_jobs(gateway_id,state);
