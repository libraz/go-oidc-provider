-- v1 schema for github.com/libraz/go-oidc-provider/op/storeadapter/sql
-- when configured with oidcsql.Postgres(). Targets PostgreSQL 14+.
--
-- Conventions:
--   * TEXT is used for opaque identifiers (no length cap; PostgreSQL
--     does not penalise this versus VARCHAR(N)).
--   * JSONB is used for slice and map columns. The application still
--     encodes/decodes JSON itself so behaviour matches the SQLite and
--     MySQL paths byte-for-byte.
--   * Booleans are stored as SMALLINT (0/1) for portability with the
--     other dialects; pgx accepts integer-typed bind values into
--     SMALLINT columns and the conversion is symmetric.
--   * Timestamps use BIGINT (unix nanoseconds).
--   * Column order follows the project convention:
--     id > *_id (foreign keys) > data columns > notes >
--     updated_at > created_at.
-- Apply once before opening the adapter.

CREATE TABLE IF NOT EXISTS oidc_clients (
    id TEXT PRIMARY KEY,
    client_id_issued_at BIGINT NOT NULL DEFAULT 0,
    redirect_uris JSONB NOT NULL DEFAULT '[]'::jsonb,
    post_logout_redirect_uris JSONB NOT NULL DEFAULT '[]'::jsonb,
    backchannel_logout_uri TEXT NOT NULL DEFAULT '',
    backchannel_logout_session_required SMALLINT NOT NULL DEFAULT 0,
    grant_types JSONB NOT NULL DEFAULT '[]'::jsonb,
    response_types JSONB NOT NULL DEFAULT '[]'::jsonb,
    scopes JSONB NOT NULL DEFAULT '[]'::jsonb,
    resources JSONB NOT NULL DEFAULT '[]'::jsonb,
    token_endpoint_auth_method TEXT NOT NULL DEFAULT '',
    secret_hash TEXT NOT NULL DEFAULT '',
    public_client SMALLINT NOT NULL DEFAULT 0,
    source TEXT NOT NULL DEFAULT '',
    application_type TEXT NOT NULL DEFAULT '',
    subject_type TEXT NOT NULL DEFAULT '',
    id_token_signed_response_alg TEXT NOT NULL DEFAULT '',
    introspection_signed_response_alg TEXT NOT NULL DEFAULT '',
    sector_identifier_uri TEXT NOT NULL DEFAULT '',
    client_name TEXT NOT NULL DEFAULT '',
    client_uri TEXT NOT NULL DEFAULT '',
    logo_uri TEXT NOT NULL DEFAULT '',
    policy_uri TEXT NOT NULL DEFAULT '',
    tos_uri TEXT NOT NULL DEFAULT '',
    jwks_uri TEXT NOT NULL DEFAULT '',
    jwks BYTEA,
    contacts JSONB NOT NULL DEFAULT '[]'::jsonb,
    default_max_age BIGINT,
    require_auth_time SMALLINT NOT NULL DEFAULT 0,
    default_acr_values JSONB NOT NULL DEFAULT '[]'::jsonb,
    initiate_login_uri TEXT NOT NULL DEFAULT '',
    request_uris JSONB NOT NULL DEFAULT '[]'::jsonb,
    request_object_signing_alg TEXT NOT NULL DEFAULT ''
);

-- oidc_authorization_codes.id stores the SHA-256 hex digest (64
-- ASCII chars) of the authorization-code bearer secret the client
-- redeems at the token endpoint; the raw value is never persisted.
-- The adapter computes the digest on Save / Find / Consume via the
-- shared op/storeadapter/patterns.Digest helper.
CREATE TABLE IF NOT EXISTS oidc_authorization_codes (
    id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    grant_id TEXT NOT NULL,
    subject TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    scope JSONB NOT NULL DEFAULT '[]'::jsonb,
    resource TEXT NOT NULL DEFAULT '',
    code_challenge TEXT NOT NULL DEFAULT '',
    code_challenge_method TEXT NOT NULL DEFAULT '',
    nonce TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL DEFAULT '',
    dpop_jkt TEXT NOT NULL DEFAULT '',
    expires_at BIGINT NOT NULL,
    consumed_at BIGINT,
    created_at BIGINT NOT NULL
);

-- oidc_refresh_tokens.id and oidc_refresh_tokens.parent_id store
-- SHA-256 hex digests (64 ASCII chars) of the refresh-token bearer
-- secrets; the raw values are never persisted. RevokeChain walks
-- the parent_id graph entirely in the digest space so the rotation
-- chain is internally consistent without ever materialising a raw
-- secret. The adapter computes the digest on Save / Find / Consume
-- via the shared op/storeadapter/patterns.Digest helper.
CREATE TABLE IF NOT EXISTS oidc_refresh_tokens (
    id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    grant_id TEXT NOT NULL,
    parent_id TEXT,
    subject TEXT NOT NULL,
    scope JSONB NOT NULL DEFAULT '[]'::jsonb,
    resource TEXT NOT NULL DEFAULT '',
    dpop_jkt TEXT NOT NULL DEFAULT '',
    mtls_cert_thumbprint TEXT NOT NULL DEFAULT '',
    nonce TEXT NOT NULL DEFAULT '',
    revoked SMALLINT NOT NULL DEFAULT 0,
    expires_at BIGINT NOT NULL,
    consumed_at BIGINT,
    created_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_oidc_refresh_tokens_parent ON oidc_refresh_tokens(parent_id);
CREATE INDEX IF NOT EXISTS idx_oidc_refresh_tokens_grant ON oidc_refresh_tokens(grant_id);

CREATE TABLE IF NOT EXISTS oidc_access_tokens (
    jti TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    grant_id TEXT NOT NULL DEFAULT '',
    subject TEXT NOT NULL DEFAULT '',
    scopes JSONB NOT NULL DEFAULT '[]'::jsonb,
    revoked SMALLINT NOT NULL DEFAULT 0,
    expires_at BIGINT NOT NULL,
    issued_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_oidc_access_tokens_grant ON oidc_access_tokens(grant_id);

CREATE TABLE IF NOT EXISTS oidc_opaque_access_tokens (
    token_hash BYTEA PRIMARY KEY,
    grant_id TEXT NOT NULL DEFAULT '',
    subject TEXT NOT NULL DEFAULT '',
    client_id TEXT NOT NULL,
    audience TEXT NOT NULL DEFAULT '',
    scope JSONB NOT NULL DEFAULT '[]'::jsonb,
    acr TEXT NOT NULL DEFAULT '',
    amr JSONB NOT NULL DEFAULT '[]'::jsonb,
    auth_time BIGINT NOT NULL DEFAULT 0,
    dpop_jkt TEXT NOT NULL DEFAULT '',
    mtls_cert_thumb TEXT NOT NULL DEFAULT '',
    issued_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    revoked SMALLINT NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_oidc_opaque_access_tokens_grant ON oidc_opaque_access_tokens(grant_id);
CREATE INDEX IF NOT EXISTS idx_oidc_opaque_access_tokens_expires ON oidc_opaque_access_tokens(expires_at);

CREATE TABLE IF NOT EXISTS oidc_grant_revocations (
    grant_id TEXT PRIMARY KEY,
    revoked_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    reason TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_oidc_grant_revocations_expires ON oidc_grant_revocations(expires_at);

CREATE TABLE IF NOT EXISTS oidc_revoked_jtis (
    jti TEXT PRIMARY KEY,
    grant_id TEXT NOT NULL DEFAULT '',
    expires_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_oidc_revoked_jtis_expires ON oidc_revoked_jtis(expires_at);

CREATE TABLE IF NOT EXISTS oidc_grants (
    id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    subject TEXT NOT NULL,
    scope JSONB NOT NULL DEFAULT '[]'::jsonb,
    claims JSONB NOT NULL DEFAULT 'null'::jsonb,
    auth_time BIGINT NOT NULL DEFAULT 0,
    acr TEXT NOT NULL DEFAULT '',
    amr JSONB NOT NULL DEFAULT '[]'::jsonb,
    updated_at BIGINT NOT NULL,
    created_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_oidc_grants_sub_client ON oidc_grants(subject, client_id, updated_at);

CREATE TABLE IF NOT EXISTS oidc_sessions (
    id TEXT PRIMARY KEY,
    chooser_group_id TEXT NOT NULL DEFAULT '',
    subject TEXT NOT NULL,
    auth_time BIGINT NOT NULL DEFAULT 0,
    amr JSONB NOT NULL DEFAULT '[]'::jsonb,
    acr TEXT NOT NULL DEFAULT '',
    expires_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    created_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_oidc_sessions_chooser ON oidc_sessions(chooser_group_id);

-- oidc_par_records.uri stores the SHA-256 hex digest (64 ASCII
-- chars) of the request_uri bearer secret returned to the client by
-- the PAR endpoint; the raw value is never persisted. The adapter
-- computes the digest on Save / Find / Consume via the shared
-- op/storeadapter/patterns.Digest helper.
CREATE TABLE IF NOT EXISTS oidc_par_records (
    uri TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    raw_params BYTEA NOT NULL,
    expires_at BIGINT NOT NULL,
    consumed_at BIGINT,
    created_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS oidc_interactions (
    id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    step TEXT NOT NULL,
    raw_state BYTEA NOT NULL,
    expires_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    created_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS oidc_consumed_jtis (
    jti TEXT PRIMARY KEY,
    expires_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS oidc_users (
    subject TEXT PRIMARY KEY,
    claims JSONB NOT NULL DEFAULT 'null'::jsonb,
    updated_at BIGINT NOT NULL,
    username TEXT NULL,
    password_hash BYTEA NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS oidc_users_username ON oidc_users (username);

CREATE TABLE IF NOT EXISTS oidc_initial_access_tokens (
    id TEXT PRIMARY KEY,
    hashed_value TEXT NOT NULL UNIQUE,
    max_uses INTEGER NOT NULL DEFAULT 0,
    uses INTEGER NOT NULL DEFAULT 0,
    allowed_scopes JSONB NOT NULL DEFAULT '[]'::jsonb,
    tag TEXT NOT NULL DEFAULT '',
    expires_at BIGINT NOT NULL,
    created_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS oidc_registration_access_tokens (
    client_id TEXT PRIMARY KEY,
    hashed_value TEXT NOT NULL,
    created_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS oidc_op_metadata (
    meta_key TEXT PRIMARY KEY,
    meta_value TEXT NOT NULL
);
