-- Existing rows and old SSH-only writers remain SSH v1. SQLx owns migration
-- numbering; server_settings.schema_version remains the compatible schema family 1.
ALTER TABLE login_sessions
    ADD COLUMN client_type text NOT NULL DEFAULT 'zeroterm',
    ADD CONSTRAINT login_sessions_client_type_check CHECK (client_type IN ('web', 'zeroterm'));

ALTER TABLE connection_tickets
    ADD COLUMN transport text NOT NULL DEFAULT 'ssh',
    ADD COLUMN protocol_version integer NOT NULL DEFAULT 1,
    ADD CONSTRAINT connection_tickets_transport_check CHECK (transport IN ('ssh', 'websocket')),
    ADD CONSTRAINT connection_tickets_protocol_version_check CHECK (protocol_version = 1);

ALTER TABLE connections
    ADD COLUMN transport text NOT NULL DEFAULT 'ssh',
    ADD COLUMN protocol_version integer NOT NULL DEFAULT 1,
    ADD CONSTRAINT connections_transport_check CHECK (transport IN ('ssh', 'websocket')),
    ADD CONSTRAINT connections_protocol_version_check CHECK (protocol_version = 1);

-- Prevent a connection from claiming a different transport/version from its ticket.
ALTER TABLE connection_tickets
    ADD CONSTRAINT connection_tickets_transport_identity UNIQUE (id, transport, protocol_version);
ALTER TABLE connections
    ADD CONSTRAINT connections_ticket_transport_fk
    FOREIGN KEY (ticket_id, transport, protocol_version)
    REFERENCES connection_tickets (id, transport, protocol_version)
    DEFERRABLE INITIALLY DEFERRED;
