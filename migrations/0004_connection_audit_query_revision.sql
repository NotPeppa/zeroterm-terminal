-- Keep schema family 1 and original migration checksums compatible with M1/M2.
ALTER TABLE connections
    ADD COLUMN account_revision bigint,
    ADD COLUMN policy_revision bigint,
    ADD COLUMN bytes_in bigint NOT NULL DEFAULT 0 CHECK (bytes_in>=0),
    ADD COLUMN bytes_out bigint NOT NULL DEFAULT 0 CHECK (bytes_out>=0);
ALTER TABLE assets ADD COLUMN routing_revision bigint NOT NULL DEFAULT 1 CHECK(routing_revision>0);
UPDATE assets SET routing_revision=config_revision;
ALTER TABLE connections ADD COLUMN routing_revision bigint;
UPDATE connections c SET account_revision=t.account_revision,policy_revision=t.policy_revision,routing_revision=c.asset_revision FROM connection_tickets t WHERE t.id=c.ticket_id;
ALTER TABLE connections ALTER COLUMN account_revision SET NOT NULL,ALTER COLUMN account_revision SET DEFAULT 1,ALTER COLUMN policy_revision SET NOT NULL,ALTER COLUMN policy_revision SET DEFAULT 1,ALTER COLUMN routing_revision SET NOT NULL,ALTER COLUMN routing_revision SET DEFAULT 1;
ALTER TABLE connections ADD CONSTRAINT connections_revision_check CHECK (account_revision>0 AND policy_revision>0 AND routing_revision>0);
ALTER TABLE connection_tickets ADD COLUMN routing_revision bigint;
UPDATE connection_tickets SET routing_revision=asset_revision;
ALTER TABLE connection_tickets ALTER COLUMN routing_revision SET NOT NULL,ALTER COLUMN routing_revision SET DEFAULT 1;

CREATE FUNCTION canonical_failure_code(text) RETURNS text LANGUAGE sql IMMUTABLE STRICT AS $$
    SELECT CASE $1 WHEN 'TICKET_INVALID' THEN 'SESSION_TICKET_INVALID' WHEN 'TICKET_USED' THEN 'SESSION_TICKET_USED' WHEN 'TICKET_EXPIRED' THEN 'SESSION_TICKET_EXPIRED' WHEN 'TICKET_STALE' THEN 'SESSION_TICKET_STALE' WHEN 'ACCESS_TOKEN_EXPIRED' THEN 'SESSION_EXPIRED' ELSE $1 END
$$;
UPDATE connections SET failure_code=canonical_failure_code(failure_code) WHERE failure_code IS NOT NULL;
-- Audit is deliberately not rewritten: normalization happens in read projections.
CREATE INDEX connections_page ON connections(created_at,id);
CREATE INDEX connections_owner_page ON connections(user_id,created_at,id);
CREATE INDEX connections_filter ON connections(state,transport,created_at,id);
CREATE INDEX audit_events_actor_time ON audit_events(actor_id,occurred_at,id);
CREATE INDEX audit_events_resource_time ON audit_events(resource_type,resource_id,occurred_at,id);
CREATE INDEX login_sessions_page ON login_sessions(user_id,created_at,id);

CREATE FUNCTION revision_never_decreases() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF (to_jsonb(NEW)->>TG_ARGV[0])::bigint < (to_jsonb(OLD)->>TG_ARGV[0])::bigint THEN
        RAISE EXCEPTION 'revision cannot decrease' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER users_revision BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION revision_never_decreases('auth_revision');
CREATE TRIGGER assets_revision BEFORE UPDATE ON assets FOR EACH ROW EXECUTE FUNCTION revision_never_decreases('config_revision');
CREATE TRIGGER assets_routing_revision BEFORE UPDATE OF host,port,enabled ON assets FOR EACH ROW EXECUTE FUNCTION revision_never_decreases('routing_revision');
CREATE TRIGGER accounts_revision BEFORE UPDATE ON target_accounts FOR EACH ROW EXECUTE FUNCTION revision_never_decreases('config_revision');
CREATE TRIGGER grants_revision BEFORE UPDATE ON grants FOR EACH ROW EXECUTE FUNCTION revision_never_decreases('revision');
CREATE TRIGGER host_keys_revision BEFORE UPDATE ON asset_host_keys FOR EACH ROW EXECUTE FUNCTION revision_never_decreases('revision');
CREATE TRIGGER credentials_revision BEFORE UPDATE ON credentials FOR EACH ROW EXECUTE FUNCTION revision_never_decreases('revision');
CREATE TRIGGER policy_revision BEFORE UPDATE ON server_settings FOR EACH ROW EXECUTE FUNCTION revision_never_decreases('policy_revision');
