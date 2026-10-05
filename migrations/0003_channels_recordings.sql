-- Forward-only M3 shell channel/recording metadata. No filesystem I/O in a transaction.
CREATE TABLE channels (
    id uuid PRIMARY KEY,
    connection_id uuid NOT NULL REFERENCES connections(id),
    upstream_channel_id bigint NOT NULL CHECK (upstream_channel_id BETWEEN 0 AND 4294967295),
    kind text NOT NULL CHECK (kind IN ('shell','exec','sftp')),
    state text NOT NULL DEFAULT 'allocated' CHECK (state IN ('allocated','configuring','starting','streaming','draining','closed','failed')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    started_at timestamptz,
    ended_at timestamptz,
    exit_code bigint CHECK (exit_code BETWEEN 0 AND 4294967295),
    exit_signal text,
    failure_code text,
    UNIQUE(connection_id,upstream_channel_id)
);
CREATE INDEX channels_connection_state ON channels(connection_id,state);
CREATE TABLE recordings (
    id uuid PRIMARY KEY,
    channel_id uuid NOT NULL UNIQUE REFERENCES channels(id),
    relative_path text NOT NULL UNIQUE CHECK (relative_path ~ '^[a-zA-Z0-9][a-zA-Z0-9_/-]*[.]ztrec$' AND relative_path !~ '(^|/)\.\.(/|$)' AND relative_path !~ '//'),
    format_version integer NOT NULL CHECK (format_version=1),
    bytes bigint NOT NULL DEFAULT 0 CHECK (bytes>=0),
    checksum text CHECK (checksum ~ '^[a-f0-9]{64}$'),
    state text NOT NULL DEFAULT 'preparing' CHECK (state IN ('preparing','active','complete','partial','failed','corrupt','missing','expired')),
    retention_until timestamptz NOT NULL,
    wrapped_dek bytea NOT NULL CHECK (octet_length(wrapped_dek)=48),
    wrap_nonce bytea NOT NULL CHECK (octet_length(wrap_nonce)=24),
    key_version bigint NOT NULL CHECK (key_version>0),
    nonce_prefix bytea NOT NULL CHECK (octet_length(nonce_prefix)=16),
    last_written_seq bigint NOT NULL DEFAULT -1 CHECK (last_written_seq>=-1),
    last_synced_seq bigint NOT NULL DEFAULT -1 CHECK (last_synced_seq>=-1 AND last_synced_seq<=last_written_seq),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    ended_at timestamptz,
    UNIQUE(id,channel_id),
    CONSTRAINT recordings_complete CHECK (state<>'complete' OR (checksum IS NOT NULL AND last_written_seq=last_synced_seq))
);
CREATE INDEX recordings_retention ON recordings(state,retention_until);
