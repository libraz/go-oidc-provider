ALTER TABLE oidc_clients
    ADD COLUMN previous_secret_hash TEXT NOT NULL,
    ADD COLUMN previous_secret_expires_at BIGINT NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS oidc_ssf_streams (
    id VARCHAR(255) NOT NULL PRIMARY KEY,
    client_id VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    delivery_method VARCHAR(32) NOT NULL,
    endpoint_url TEXT NOT NULL,
    sealed_authorization_header VARBINARY(8192) NULL,
    events_requested JSON NOT NULL,
    events_delivered JSON NOT NULL,
    description TEXT NOT NULL,
    status VARCHAR(32) NOT NULL,
    status_reason TEXT NOT NULL,
    updated_at BIGINT NOT NULL DEFAULT 0,
    created_at BIGINT NOT NULL DEFAULT 0,
    UNIQUE KEY idx_oidc_ssf_streams_client (client_id)
);

CREATE TABLE IF NOT EXISTS oidc_ssf_events (
    jti VARCHAR(255) NOT NULL PRIMARY KEY,
    stream_id VARCHAR(255) NOT NULL,
    kind VARCHAR(32) NOT NULL,
    delivery_method VARCHAR(32) NOT NULL,
    held TINYINT(1) NOT NULL DEFAULT 0,
    claims MEDIUMBLOB NOT NULL,
    attempts INT NOT NULL DEFAULT 0,
    next_attempt_at BIGINT NOT NULL DEFAULT 0,
    expires_at BIGINT NOT NULL DEFAULT 0,
    INDEX idx_oidc_ssf_events_stream_ready (stream_id, delivery_method, held, jti),
    INDEX idx_oidc_ssf_events_due (delivery_method, held, stream_id, next_attempt_at, jti),
    INDEX idx_oidc_ssf_events_expires (expires_at)
);

ALTER TABLE oidc_sessions ADD INDEX idx_oidc_sessions_subject (subject);
