-- Preserve existing pins while allowing assets to wait for first confirmation.
ALTER TABLE assets DROP CONSTRAINT assets_check;
ALTER TABLE assets ADD CONSTRAINT assets_protocol_trust_check CHECK (
    (protocol = 'ssh' AND (ssh_host_key IS NULL OR char_length(ssh_host_key) > 0)
        AND security IS NULL AND rdp_certificate_sha256 IS NULL)
    OR (protocol = 'rdp' AND security IS NOT NULL AND rdp_certificate_sha256 IS NOT NULL AND ssh_host_key IS NULL)
    OR (protocol = 'vnc' AND security IS NULL AND ssh_host_key IS NULL AND rdp_certificate_sha256 IS NULL)
);
