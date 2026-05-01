-- v1 schema for github.com/libraz/go-oidc-provider/op/storeadapter/sql
-- when configured with oidcsql.MySQL(). Targets MySQL 8.0.20+ (so the
-- INSERT ... AS new ON DUPLICATE KEY UPDATE alias is available) and
-- MariaDB 10.5+.
--
-- Conventions:
--   * VARCHAR(255) is used for opaque identifiers; fits in a UTF8MB4
--     btree (255*4 = 1020 bytes) without hitting the prefix-length cap.
--   * JSON is stored in JSON columns; the application still encodes
--     and decodes itself so behaviour is identical across engines.
--   * Booleans use TINYINT(1) for portability with the other dialects.
--   * Timestamps use BIGINT (unix nanoseconds).
--   * Column order mirrors the project convention recorded in
--     .claude/agents/op-store.md: id > *_id (foreign keys) > data
--     columns > notes > updated_at > created_at.
-- Apply once before opening the adapter.

CREATE TABLE IF NOT EXISTS oidc_clients (
    id VARCHAR(255) NOT NULL PRIMARY KEY,
    client_id_issued_at BIGINT NOT NULL DEFAULT 0,
    redirect_uris JSON NOT NULL,
    post_logout_redirect_uris JSON NOT NULL,
    backchannel_logout_uri TEXT NOT NULL,
    backchannel_logout_session_required TINYINT(1) NOT NULL DEFAULT 0,
    grant_types JSON NOT NULL,
    response_types JSON NOT NULL,
    scopes JSON NOT NULL,
    resources JSON NOT NULL,
    token_endpoint_auth_method VARCHAR(64) NOT NULL DEFAULT '',
    secret_hash TEXT NOT NULL,
    public_client TINYINT(1) NOT NULL DEFAULT 0,
    source VARCHAR(32) NOT NULL DEFAULT '',
    application_type VARCHAR(32) NOT NULL DEFAULT '',
    subject_type VARCHAR(32) NOT NULL DEFAULT '',
    id_token_signed_response_alg VARCHAR(16) NOT NULL DEFAULT '',
    introspection_signed_response_alg VARCHAR(16) NOT NULL DEFAULT '',
    sector_identifier_uri TEXT NOT NULL,
    client_name VARCHAR(255) NOT NULL DEFAULT '',
    client_uri TEXT NOT NULL,
    logo_uri TEXT NOT NULL,
    policy_uri TEXT NOT NULL,
    tos_uri TEXT NOT NULL,
    jwks_uri TEXT NOT NULL,
    jwks BLOB,
    contacts JSON NOT NULL,
    default_max_age BIGINT NULL,
    require_auth_time TINYINT(1) NOT NULL DEFAULT 0,
    default_acr_values JSON NOT NULL,
    initiate_login_uri TEXT NOT NULL,
    request_uris JSON NOT NULL,
    request_object_signing_alg VARCHAR(16) NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS oidc_authorization_codes (
    id VARCHAR(255) NOT NULL PRIMARY KEY,
    client_id VARCHAR(255) NOT NULL,
    grant_id VARCHAR(255) NOT NULL,
    subject VARCHAR(255) NOT NULL,
    redirect_uri TEXT NOT NULL,
    scope JSON NOT NULL,
    resource TEXT NOT NULL,
    code_challenge VARCHAR(255) NOT NULL DEFAULT '',
    code_challenge_method VARCHAR(16) NOT NULL DEFAULT '',
    nonce VARCHAR(255) NOT NULL DEFAULT '',
    state VARCHAR(255) NOT NULL DEFAULT '',
    dpop_jkt VARCHAR(64) NOT NULL DEFAULT '',
    expires_at BIGINT NOT NULL,
    consumed_at BIGINT NULL,
    created_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS oidc_refresh_tokens (
    id VARCHAR(255) NOT NULL PRIMARY KEY,
    client_id VARCHAR(255) NOT NULL,
    grant_id VARCHAR(255) NOT NULL,
    parent_id VARCHAR(255) NULL,
    subject VARCHAR(255) NOT NULL,
    scope JSON NOT NULL,
    resource TEXT NOT NULL,
    dpop_jkt VARCHAR(64) NOT NULL DEFAULT '',
    mtls_cert_thumbprint VARCHAR(64) NOT NULL DEFAULT '',
    revoked TINYINT(1) NOT NULL DEFAULT 0,
    expires_at BIGINT NOT NULL,
    consumed_at BIGINT NULL,
    created_at BIGINT NOT NULL,
    INDEX idx_oidc_refresh_tokens_parent (parent_id),
    INDEX idx_oidc_refresh_tokens_grant (grant_id)
);

CREATE TABLE IF NOT EXISTS oidc_access_tokens (
    jti VARCHAR(255) NOT NULL PRIMARY KEY,
    client_id VARCHAR(255) NOT NULL,
    grant_id VARCHAR(255) NOT NULL DEFAULT '',
    subject VARCHAR(255) NOT NULL DEFAULT '',
    scopes JSON NOT NULL,
    revoked TINYINT(1) NOT NULL DEFAULT 0,
    expires_at BIGINT NOT NULL,
    issued_at BIGINT NOT NULL,
    INDEX idx_oidc_access_tokens_grant (grant_id)
);

CREATE TABLE IF NOT EXISTS oidc_opaque_access_tokens (
    token_hash VARBINARY(32) NOT NULL PRIMARY KEY,
    grant_id VARCHAR(255) NOT NULL DEFAULT '',
    subject VARCHAR(255) NOT NULL DEFAULT '',
    client_id VARCHAR(255) NOT NULL,
    audience TEXT NOT NULL,
    scope JSON NOT NULL,
    acr VARCHAR(64) NOT NULL DEFAULT '',
    amr JSON NOT NULL,
    auth_time BIGINT NOT NULL DEFAULT 0,
    dpop_jkt VARCHAR(64) NOT NULL DEFAULT '',
    mtls_cert_thumb VARCHAR(64) NOT NULL DEFAULT '',
    issued_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    revoked TINYINT(1) NOT NULL DEFAULT 0,
    INDEX idx_oidc_opaque_access_tokens_grant (grant_id),
    INDEX idx_oidc_opaque_access_tokens_expires (expires_at)
);

CREATE TABLE IF NOT EXISTS oidc_grant_revocations (
    grant_id VARCHAR(255) NOT NULL PRIMARY KEY,
    revoked_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    reason VARCHAR(64) NOT NULL DEFAULT '',
    INDEX idx_oidc_grant_revocations_expires (expires_at)
);

CREATE TABLE IF NOT EXISTS oidc_revoked_jtis (
    jti VARCHAR(255) NOT NULL PRIMARY KEY,
    grant_id VARCHAR(255) NOT NULL DEFAULT '',
    expires_at BIGINT NOT NULL,
    INDEX idx_oidc_revoked_jtis_expires (expires_at)
);

CREATE TABLE IF NOT EXISTS oidc_grants (
    id VARCHAR(255) NOT NULL PRIMARY KEY,
    client_id VARCHAR(255) NOT NULL,
    subject VARCHAR(255) NOT NULL,
    scope JSON NOT NULL,
    claims JSON NOT NULL,
    auth_time BIGINT NOT NULL DEFAULT 0,
    acr VARCHAR(64) NOT NULL DEFAULT '',
    amr JSON NOT NULL,
    updated_at BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    INDEX idx_oidc_grants_sub_client (subject, client_id, updated_at)
);

CREATE TABLE IF NOT EXISTS oidc_sessions (
    id VARCHAR(255) NOT NULL PRIMARY KEY,
    chooser_group_id VARCHAR(255) NOT NULL DEFAULT '',
    subject VARCHAR(255) NOT NULL,
    auth_time BIGINT NOT NULL DEFAULT 0,
    amr JSON NOT NULL,
    acr VARCHAR(64) NOT NULL DEFAULT '',
    expires_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    INDEX idx_oidc_sessions_chooser (chooser_group_id)
);

CREATE TABLE IF NOT EXISTS oidc_par_records (
    uri VARCHAR(255) NOT NULL PRIMARY KEY,
    client_id VARCHAR(255) NOT NULL,
    raw_params LONGBLOB NOT NULL,
    expires_at BIGINT NOT NULL,
    consumed_at BIGINT NULL,
    created_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS oidc_interactions (
    id VARCHAR(255) NOT NULL PRIMARY KEY,
    client_id VARCHAR(255) NOT NULL,
    step VARCHAR(64) NOT NULL,
    raw_state LONGBLOB NOT NULL,
    expires_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    created_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS oidc_consumed_jtis (
    jti VARCHAR(255) NOT NULL PRIMARY KEY,
    expires_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS oidc_users (
    subject VARCHAR(255) NOT NULL PRIMARY KEY,
    claims JSON NOT NULL,
    updated_at BIGINT NOT NULL,
    username VARCHAR(255) NULL,
    password_hash VARBINARY(512) NULL,
    UNIQUE KEY oidc_users_username (username)
);

CREATE TABLE IF NOT EXISTS oidc_initial_access_tokens (
    id VARCHAR(255) NOT NULL PRIMARY KEY,
    hashed_value VARCHAR(128) NOT NULL UNIQUE,
    max_uses INT NOT NULL DEFAULT 0,
    uses INT NOT NULL DEFAULT 0,
    allowed_scopes JSON NOT NULL,
    tag VARCHAR(255) NOT NULL DEFAULT '',
    expires_at BIGINT NOT NULL,
    created_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS oidc_registration_access_tokens (
    client_id VARCHAR(255) NOT NULL PRIMARY KEY,
    hashed_value VARCHAR(128) NOT NULL,
    created_at BIGINT NOT NULL
);
