ALTER TABLE oidc_clients ADD COLUMN previous_secret_hash TEXT NOT NULL DEFAULT '';
ALTER TABLE oidc_clients ADD COLUMN previous_secret_expires_at INTEGER NOT NULL DEFAULT 0;
ALTER TABLE oidc_clients ADD COLUMN tls_client_auth_subject_dn TEXT NOT NULL DEFAULT '';
ALTER TABLE oidc_clients ADD COLUMN tls_client_auth_san_dns TEXT NOT NULL DEFAULT '';
ALTER TABLE oidc_clients ADD COLUMN tls_client_auth_san_uri TEXT NOT NULL DEFAULT '';
ALTER TABLE oidc_clients ADD COLUMN tls_client_auth_san_ip TEXT NOT NULL DEFAULT '';
ALTER TABLE oidc_clients ADD COLUMN tls_client_auth_san_email TEXT NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS oidc_ssf_streams (
    id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    delivery_method TEXT NOT NULL,
    endpoint_url TEXT NOT NULL DEFAULT '',
    sealed_authorization_header BLOB,
    events_requested TEXT NOT NULL DEFAULT '[]',
    events_delivered TEXT NOT NULL DEFAULT '[]',
    description TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    status_reason TEXT NOT NULL DEFAULT '',
    updated_at INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_oidc_ssf_streams_client ON oidc_ssf_streams(client_id);

CREATE TABLE IF NOT EXISTS oidc_ssf_events (
    jti TEXT PRIMARY KEY,
    stream_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    delivery_method TEXT NOT NULL,
    held INTEGER NOT NULL DEFAULT 0,
    claims BLOB NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at INTEGER NOT NULL DEFAULT 0,
    expires_at INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_oidc_ssf_events_stream_ready ON oidc_ssf_events(stream_id, delivery_method, held, jti);
CREATE INDEX IF NOT EXISTS idx_oidc_ssf_events_due ON oidc_ssf_events(delivery_method, held, stream_id, next_attempt_at, jti);
CREATE INDEX IF NOT EXISTS idx_oidc_ssf_events_expires ON oidc_ssf_events(expires_at);

CREATE INDEX IF NOT EXISTS idx_oidc_sessions_subject ON oidc_sessions(subject);
