-- RFC-005 fresh schema family 2 only. PgStore rejects previous databases before MIGRATOR.run.
CREATE TABLE server_settings (singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton), server_id text NOT NULL UNIQUE, policy_revision bigint NOT NULL DEFAULT 1 CHECK(policy_revision>0), schema_version integer NOT NULL DEFAULT 2 CHECK(schema_version=2));
CREATE TABLE users (id uuid PRIMARY KEY, username text NOT NULL CHECK(username ~ '^[a-z0-9][a-z0-9_.-]{0,63}$'), password_hash text NOT NULL, role text NOT NULL CHECK(role IN ('admin','operator','auditor')), enabled boolean NOT NULL DEFAULT true, auth_revision bigint NOT NULL DEFAULT 1 CHECK(auth_revision>0), created_at timestamptz NOT NULL DEFAULT clock_timestamp(), deleted_at timestamptz, CHECK(deleted_at IS NULL OR NOT enabled));
CREATE UNIQUE INDEX users_active_username_key ON users(username) WHERE deleted_at IS NULL;
CREATE TABLE login_sessions (id uuid PRIMARY KEY,user_id uuid NOT NULL REFERENCES users(id),device_label text NOT NULL CHECK(octet_length(device_label) BETWEEN 1 AND 128),family_id uuid NOT NULL UNIQUE,refresh_hash bytea NOT NULL CHECK(octet_length(refresh_hash)=32),revoked_at timestamptz,expires_at timestamptz NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp());
CREATE INDEX login_sessions_page ON login_sessions(user_id,created_at,id);
CREATE TABLE access_tokens (token_hash bytea PRIMARY KEY CHECK(octet_length(token_hash)=32),login_session_id uuid NOT NULL REFERENCES login_sessions(id),expires_at timestamptz NOT NULL);
CREATE INDEX access_tokens_session ON access_tokens(login_session_id);
CREATE TABLE refresh_tokens (id uuid PRIMARY KEY,login_session_id uuid NOT NULL REFERENCES login_sessions(id),token_hash bytea NOT NULL UNIQUE CHECK(octet_length(token_hash)=32),state text NOT NULL CHECK(state IN ('active','rotated','revoked')),expires_at timestamptz NOT NULL,rotated_at timestamptz,replaced_by uuid REFERENCES refresh_tokens(id) DEFERRABLE INITIALLY DEFERRED);
CREATE INDEX refresh_tokens_session ON refresh_tokens(login_session_id);
CREATE TABLE assets (
 id uuid PRIMARY KEY,name text NOT NULL CHECK(char_length(name) BETWEEN 1 AND 128),host text NOT NULL CHECK(octet_length(host) BETWEEN 1 AND 253),port integer NOT NULL CHECK(port BETWEEN 1 AND 65535),tags text[] NOT NULL DEFAULT '{}',enabled boolean NOT NULL DEFAULT true,
 protocol text NOT NULL CHECK(protocol IN ('ssh','rdp','vnc')),security text CHECK(security IN ('nla','tls')),ssh_host_key text,rdp_certificate_sha256 text CHECK(rdp_certificate_sha256 ~ '^[a-f0-9]{64}$'),
 config_revision bigint NOT NULL DEFAULT 1 CHECK(config_revision>0),routing_revision bigint NOT NULL DEFAULT 1 CHECK(routing_revision>0),created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 CHECK((protocol='ssh' AND ssh_host_key IS NOT NULL AND char_length(ssh_host_key)>0 AND security IS NULL AND rdp_certificate_sha256 IS NULL) OR (protocol='rdp' AND security IS NOT NULL AND rdp_certificate_sha256 IS NOT NULL AND ssh_host_key IS NULL) OR (protocol='vnc' AND security IS NULL AND ssh_host_key IS NULL AND rdp_certificate_sha256 IS NULL))
);
CREATE TABLE credentials (id uuid PRIMARY KEY,kind text NOT NULL CHECK(kind IN ('password','private_key')),revision bigint NOT NULL CHECK(revision>0),ciphertext bytea NOT NULL CHECK(octet_length(ciphertext) BETWEEN 17 AND 262144),nonce bytea NOT NULL CHECK(octet_length(nonce)=24),wrapped_dek bytea NOT NULL CHECK(octet_length(wrapped_dek)=48),wrap_nonce bytea NOT NULL CHECK(octet_length(wrap_nonce)=24),key_version bigint NOT NULL CHECK(key_version>0));
CREATE TABLE target_accounts (id uuid PRIMARY KEY,asset_id uuid NOT NULL REFERENCES assets(id),label text NOT NULL CHECK(char_length(label) BETWEEN 1 AND 128),username text CHECK(octet_length(username) BETWEEN 1 AND 128),domain text CHECK(octet_length(domain) BETWEEN 1 AND 253),credential_id uuid UNIQUE REFERENCES credentials(id),enabled boolean NOT NULL DEFAULT true,config_revision bigint NOT NULL DEFAULT 1 CHECK(config_revision>0),security_revision bigint NOT NULL DEFAULT 1 CHECK(security_revision>0),created_at timestamptz NOT NULL DEFAULT clock_timestamp(),UNIQUE(asset_id,label),UNIQUE(id,asset_id));
CREATE TABLE grants (id uuid PRIMARY KEY,user_id uuid NOT NULL REFERENCES users(id),asset_id uuid NOT NULL REFERENCES assets(id),account_id uuid NOT NULL,enabled boolean NOT NULL DEFAULT true,expires_at timestamptz,revision bigint NOT NULL DEFAULT 1 CHECK(revision>0),created_at timestamptz NOT NULL DEFAULT clock_timestamp(),FOREIGN KEY(account_id,asset_id) REFERENCES target_accounts(id,asset_id));
CREATE INDEX grants_identity ON grants(user_id,asset_id,account_id);
CREATE TABLE connection_tickets (id uuid PRIMARY KEY,secret_hash bytea NOT NULL UNIQUE CHECK(octet_length(secret_hash)=32),connection_id uuid NOT NULL UNIQUE,user_id uuid NOT NULL REFERENCES users(id),login_session_id uuid NOT NULL REFERENCES login_sessions(id),asset_id uuid NOT NULL REFERENCES assets(id),account_id uuid NOT NULL,gateway_id text NOT NULL,auth_revision bigint NOT NULL,routing_revision bigint NOT NULL,account_revision bigint NOT NULL,credential_revision bigint,state text NOT NULL CHECK(state IN ('issued','consumed','expired','revoked')),expires_at timestamptz NOT NULL,consumed_at timestamptz,FOREIGN KEY(account_id,asset_id) REFERENCES target_accounts(id,asset_id));
CREATE INDEX tickets_expiry ON connection_tickets(state,expires_at);
CREATE TABLE connections (
 id uuid PRIMARY KEY,ticket_id uuid NOT NULL UNIQUE REFERENCES connection_tickets(id) DEFERRABLE INITIALLY DEFERRED,user_id uuid NOT NULL REFERENCES users(id),login_session_id uuid NOT NULL REFERENCES login_sessions(id),asset_id uuid NOT NULL REFERENCES assets(id),account_id uuid NOT NULL,
 target_protocol text NOT NULL CHECK(target_protocol IN ('ssh','rdp','vnc')),width integer NOT NULL CHECK(width BETWEEN 1 AND 3840),height integer NOT NULL CHECK(height BETWEEN 1 AND 2160),dpi integer NOT NULL CHECK(dpi BETWEEN 48 AND 192),protocol_version integer NOT NULL DEFAULT 2 CHECK(protocol_version=2),
 state text NOT NULL CHECK(state IN ('pending','connecting','active','closing','closed','failed','expired','revoked','interrupted')),gateway_id text NOT NULL,auth_revision bigint NOT NULL,routing_revision bigint NOT NULL,account_revision bigint NOT NULL,credential_revision bigint,
 target_host text NOT NULL,target_port integer NOT NULL,target_username text,user_snapshot text NOT NULL,asset_snapshot text NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),started_at timestamptz,ended_at timestamptz,failure_code text,bytes_in bigint NOT NULL DEFAULT 0 CHECK(bytes_in>=0),bytes_out bigint NOT NULL DEFAULT 0 CHECK(bytes_out>=0),FOREIGN KEY(account_id,asset_id) REFERENCES target_accounts(id,asset_id),UNIQUE(id,target_protocol)
);
ALTER TABLE connection_tickets ADD FOREIGN KEY(connection_id) REFERENCES connections(id) DEFERRABLE INITIALLY DEFERRED;
CREATE INDEX connections_user_state ON connections(user_id,state);
CREATE INDEX connections_gateway ON connections(gateway_id,state);
CREATE INDEX connections_page ON connections(created_at,id);
CREATE INDEX connections_owner_page ON connections(user_id,created_at,id);
CREATE TABLE recordings (
 id uuid PRIMARY KEY,connection_id uuid NOT NULL UNIQUE,target_protocol text NOT NULL,relative_path text NOT NULL UNIQUE CHECK(relative_path ~ '^[a-zA-Z0-9][a-zA-Z0-9_.-]*[.]ztrec$'),format_version integer NOT NULL CHECK(format_version=2),bytes bigint NOT NULL DEFAULT 0 CHECK(bytes>=0),checksum text CHECK(checksum ~ '^[a-f0-9]{64}$'),state text NOT NULL DEFAULT 'preparing' CHECK(state IN ('preparing','active','complete','partial','failed','corrupt','missing','expired')),retention_until timestamptz NOT NULL,wrapped_dek bytea NOT NULL CHECK(octet_length(wrapped_dek)=48),wrap_nonce bytea NOT NULL CHECK(octet_length(wrap_nonce)=24),key_version bigint NOT NULL CHECK(key_version>0),nonce_prefix bytea NOT NULL CHECK(octet_length(nonce_prefix)=16),last_written_seq bigint NOT NULL DEFAULT -1 CHECK(last_written_seq>=-1),last_synced_seq bigint NOT NULL DEFAULT -1 CHECK(last_synced_seq>=-1 AND last_synced_seq<=last_written_seq),created_at timestamptz NOT NULL DEFAULT clock_timestamp(),ended_at timestamptz,
 FOREIGN KEY(connection_id,target_protocol) REFERENCES connections(id,target_protocol),CHECK(state<>'complete' OR (checksum IS NOT NULL AND last_written_seq=last_synced_seq AND last_written_seq>=1))
);
CREATE INDEX recordings_retention ON recordings(state,retention_until);
CREATE TABLE audit_events (id uuid PRIMARY KEY,occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),actor_id uuid REFERENCES users(id),login_session_id uuid REFERENCES login_sessions(id),action text NOT NULL,resource_type text NOT NULL,resource_id uuid,request_id uuid NOT NULL,sanitized_payload jsonb NOT NULL DEFAULT '{}');
CREATE INDEX audit_events_time ON audit_events(occurred_at,id);
CREATE INDEX audit_events_actor_time ON audit_events(actor_id,occurred_at,id);
CREATE INDEX audit_events_resource_time ON audit_events(resource_type,resource_id,occurred_at,id);
CREATE FUNCTION audit_append_only() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'audit events are append only'; END $$;
CREATE TRIGGER audit_append_only BEFORE UPDATE OR DELETE ON audit_events FOR EACH ROW EXECUTE FUNCTION audit_append_only();
CREATE FUNCTION canonical_failure_code(text) RETURNS text LANGUAGE sql IMMUTABLE STRICT AS $$ SELECT $1 $$;
CREATE FUNCTION revision_never_decreases() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF (to_jsonb(NEW)->>TG_ARGV[0])::bigint < (to_jsonb(OLD)->>TG_ARGV[0])::bigint THEN RAISE EXCEPTION 'revision cannot decrease' USING ERRCODE='23514'; END IF; RETURN NEW; END $$;
CREATE TRIGGER users_revision BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION revision_never_decreases('auth_revision');
CREATE TRIGGER assets_revision BEFORE UPDATE ON assets FOR EACH ROW EXECUTE FUNCTION revision_never_decreases('config_revision');
CREATE TRIGGER assets_routing_revision BEFORE UPDATE ON assets FOR EACH ROW EXECUTE FUNCTION revision_never_decreases('routing_revision');
CREATE TRIGGER accounts_revision BEFORE UPDATE ON target_accounts FOR EACH ROW EXECUTE FUNCTION revision_never_decreases('config_revision');
CREATE TRIGGER accounts_security_revision BEFORE UPDATE ON target_accounts FOR EACH ROW EXECUTE FUNCTION revision_never_decreases('security_revision');
CREATE TRIGGER grants_revision BEFORE UPDATE ON grants FOR EACH ROW EXECUTE FUNCTION revision_never_decreases('revision');
CREATE TRIGGER credentials_revision BEFORE UPDATE ON credentials FOR EACH ROW EXECUTE FUNCTION revision_never_decreases('revision');
CREATE TRIGGER policy_revision BEFORE UPDATE ON server_settings FOR EACH ROW EXECUTE FUNCTION revision_never_decreases('policy_revision');
CREATE FUNCTION immutable_asset_protocol() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.protocol<>OLD.protocol THEN RAISE EXCEPTION 'asset protocol is immutable' USING ERRCODE='23514'; END IF; RETURN NEW; END $$;
CREATE TRIGGER immutable_asset_protocol BEFORE UPDATE ON assets FOR EACH ROW EXECUTE FUNCTION immutable_asset_protocol();
