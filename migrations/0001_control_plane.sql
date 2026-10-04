CREATE TABLE server_settings (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    server_id text NOT NULL UNIQUE,
    policy_revision bigint NOT NULL DEFAULT 1 CHECK (policy_revision > 0),
    schema_version integer NOT NULL DEFAULT 1
);
CREATE TABLE users (
    id uuid PRIMARY KEY, username text NOT NULL UNIQUE CHECK (username ~ '^[a-z0-9][a-z0-9_.-]{0,63}$'),
    password_hash text NOT NULL, role text NOT NULL CHECK (role IN ('admin','operator','auditor')),
    enabled boolean NOT NULL DEFAULT true, auth_revision bigint NOT NULL DEFAULT 1 CHECK (auth_revision>0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE login_sessions (
    id uuid PRIMARY KEY, user_id uuid NOT NULL REFERENCES users(id), device_label text NOT NULL CHECK (octet_length(device_label) BETWEEN 1 AND 128),
    family_id uuid NOT NULL UNIQUE, refresh_hash bytea NOT NULL CHECK (octet_length(refresh_hash)=32),
    revoked_at timestamptz, expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX login_sessions_user ON login_sessions(user_id);
CREATE TABLE access_tokens (
    token_hash bytea PRIMARY KEY CHECK(octet_length(token_hash)=32), login_session_id uuid NOT NULL REFERENCES login_sessions(id), expires_at timestamptz NOT NULL
);
CREATE INDEX access_tokens_session ON access_tokens(login_session_id);
CREATE TABLE refresh_tokens (
    id uuid PRIMARY KEY, login_session_id uuid NOT NULL REFERENCES login_sessions(id),
    token_hash bytea NOT NULL UNIQUE CHECK(octet_length(token_hash)=32), state text NOT NULL CHECK(state IN ('active','rotated','revoked')),
    expires_at timestamptz NOT NULL, rotated_at timestamptz, replaced_by uuid REFERENCES refresh_tokens(id) DEFERRABLE INITIALLY DEFERRED
);
CREATE INDEX refresh_tokens_session ON refresh_tokens(login_session_id);
CREATE TABLE assets (
    id uuid PRIMARY KEY, name text NOT NULL CHECK(char_length(name) BETWEEN 1 AND 128),
    host text NOT NULL CHECK(octet_length(host) BETWEEN 1 AND 253), port integer NOT NULL CHECK(port BETWEEN 1 AND 65535),
    tags text[] NOT NULL DEFAULT '{}', enabled boolean NOT NULL DEFAULT true,
    config_revision bigint NOT NULL DEFAULT 1 CHECK(config_revision>0), created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE credentials (
    id uuid PRIMARY KEY, kind text NOT NULL CHECK(kind IN ('password','private_key')), revision bigint NOT NULL CHECK(revision>0),
    ciphertext bytea NOT NULL CHECK(octet_length(ciphertext) BETWEEN 17 AND 262144), nonce bytea NOT NULL CHECK(octet_length(nonce)=24),
    wrapped_dek bytea NOT NULL CHECK(octet_length(wrapped_dek)=48), wrap_nonce bytea NOT NULL CHECK(octet_length(wrap_nonce)=24), key_version bigint NOT NULL CHECK(key_version>0)
);
CREATE TABLE target_accounts (
    id uuid PRIMARY KEY, asset_id uuid NOT NULL REFERENCES assets(id), username text NOT NULL CHECK(octet_length(username) BETWEEN 1 AND 128),
    credential_id uuid NOT NULL UNIQUE REFERENCES credentials(id), enabled boolean NOT NULL DEFAULT true,
    config_revision bigint NOT NULL DEFAULT 1 CHECK(config_revision>0), created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE(asset_id,username), UNIQUE(id,asset_id)
);
CREATE TABLE asset_host_keys (
    id uuid PRIMARY KEY, asset_id uuid NOT NULL REFERENCES assets(id), algorithm text NOT NULL, public_key text NOT NULL,
    fingerprint text NOT NULL, state text NOT NULL CHECK(state IN ('candidate','approved','revoked')),
    approved_by uuid REFERENCES users(id), created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    revision bigint NOT NULL DEFAULT 1 CHECK(revision>0), UNIQUE(asset_id,public_key)
);
CREATE INDEX asset_host_keys_asset ON asset_host_keys(asset_id,state);
CREATE FUNCTION valid_capabilities(text[]) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
    SELECT cardinality($1) BETWEEN 1 AND 3 AND $1 <@ ARRAY['shell','exec','sftp']::text[]
      AND array_position($1,NULL) IS NULL AND cardinality($1)=(SELECT count(DISTINCT x) FROM unnest($1) x)
$$;
CREATE TABLE grants (
    id uuid PRIMARY KEY, user_id uuid NOT NULL REFERENCES users(id), asset_id uuid NOT NULL REFERENCES assets(id),
    account_id uuid NOT NULL, capabilities text[] NOT NULL CHECK(valid_capabilities(capabilities)),
    enabled boolean NOT NULL DEFAULT true, expires_at timestamptz, revision bigint NOT NULL DEFAULT 1 CHECK(revision>0), created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY(account_id,asset_id) REFERENCES target_accounts(id,asset_id)
);
CREATE INDEX grants_identity ON grants(user_id,asset_id,account_id);
CREATE TABLE connection_tickets (
    id uuid PRIMARY KEY, secret_hash bytea NOT NULL UNIQUE CHECK(octet_length(secret_hash)=32), connection_id uuid NOT NULL UNIQUE,
    user_id uuid NOT NULL REFERENCES users(id), login_session_id uuid NOT NULL REFERENCES login_sessions(id),
    asset_id uuid NOT NULL REFERENCES assets(id), account_id uuid NOT NULL,
    capabilities text[] NOT NULL CHECK(valid_capabilities(capabilities)), purpose text NOT NULL CHECK(purpose IN ('terminal','sftp','metrics','server_tool')),
    gateway_id text NOT NULL, auth_revision bigint NOT NULL, asset_revision bigint NOT NULL, account_revision bigint NOT NULL, policy_revision bigint NOT NULL,
    state text NOT NULL CHECK(state IN ('issued','consumed','expired','revoked')), expires_at timestamptz NOT NULL, consumed_at timestamptz,
    FOREIGN KEY(account_id,asset_id) REFERENCES target_accounts(id,asset_id)
);
CREATE INDEX tickets_expiry ON connection_tickets(state,expires_at);
CREATE TABLE connections (
    id uuid PRIMARY KEY, ticket_id uuid NOT NULL UNIQUE REFERENCES connection_tickets(id) DEFERRABLE INITIALLY DEFERRED,
    user_id uuid NOT NULL REFERENCES users(id), login_session_id uuid NOT NULL REFERENCES login_sessions(id), asset_id uuid NOT NULL REFERENCES assets(id), account_id uuid NOT NULL,
    capabilities text[] NOT NULL CHECK(valid_capabilities(capabilities)), purpose text NOT NULL CHECK(purpose IN ('terminal','sftp','metrics','server_tool')),
    state text NOT NULL CHECK(state IN ('pending','connecting','active','closing','closed','failed','expired','revoked','interrupted')),
    gateway_id text NOT NULL, auth_revision bigint NOT NULL, asset_revision bigint NOT NULL, target_host text NOT NULL, target_port integer NOT NULL,
    target_username text NOT NULL, user_snapshot text NOT NULL, asset_snapshot text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(), started_at timestamptz, ended_at timestamptz, failure_code text,
    FOREIGN KEY(account_id,asset_id) REFERENCES target_accounts(id,asset_id)
);
ALTER TABLE connection_tickets ADD FOREIGN KEY(connection_id) REFERENCES connections(id) DEFERRABLE INITIALLY DEFERRED;
CREATE INDEX connections_user_state ON connections(user_id,state);
CREATE INDEX connections_gateway ON connections(gateway_id,state);
CREATE TABLE audit_events (
    id uuid PRIMARY KEY, occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(), actor_id uuid REFERENCES users(id),
    login_session_id uuid REFERENCES login_sessions(id), action text NOT NULL, resource_type text NOT NULL, resource_id uuid,
    request_id uuid NOT NULL, sanitized_payload jsonb NOT NULL DEFAULT '{}'
);
CREATE INDEX audit_events_time ON audit_events(occurred_at,id);
CREATE FUNCTION audit_append_only() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'audit events are append only'; END $$;
CREATE TRIGGER audit_append_only BEFORE UPDATE OR DELETE ON audit_events FOR EACH ROW EXECUTE FUNCTION audit_append_only();
