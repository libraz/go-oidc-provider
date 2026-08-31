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
    token_endpoint_auth_signing_alg TEXT NOT NULL DEFAULT '',
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
    request_object_signing_alg TEXT NOT NULL DEFAULT '',
    request_object_encryption_alg TEXT NOT NULL DEFAULT '',
    request_object_encryption_enc TEXT NOT NULL DEFAULT '',
    id_token_encrypted_response_alg TEXT NOT NULL DEFAULT '',
    id_token_encrypted_response_enc TEXT NOT NULL DEFAULT '',
    userinfo_encrypted_response_alg TEXT NOT NULL DEFAULT '',
    userinfo_encrypted_response_enc TEXT NOT NULL DEFAULT '',
    authorization_encrypted_response_alg TEXT NOT NULL DEFAULT '',
    authorization_encrypted_response_enc TEXT NOT NULL DEFAULT '',
    introspection_encrypted_response_alg TEXT NOT NULL DEFAULT '',
    introspection_encrypted_response_enc TEXT NOT NULL DEFAULT ''
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
CREATE INDEX IF NOT EXISTS idx_oidc_authorization_codes_expires ON oidc_authorization_codes(expires_at);

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
    subject_public SMALLINT NOT NULL DEFAULT 0,
    scope JSONB NOT NULL DEFAULT '[]'::jsonb,
    resource TEXT NOT NULL DEFAULT '',
    origin TEXT NOT NULL DEFAULT '',
    auth_time BIGINT NOT NULL DEFAULT 0,
    acr TEXT NOT NULL DEFAULT '',
    amr JSONB NOT NULL DEFAULT '[]'::jsonb,
    authorization_details JSONB NOT NULL DEFAULT 'null'::jsonb,
    access_token_extra JSONB NOT NULL DEFAULT 'null'::jsonb,
    dpop_jkt TEXT NOT NULL DEFAULT '',
    mtls_cert_thumbprint TEXT NOT NULL DEFAULT '',
    nonce TEXT NOT NULL DEFAULT '',
    revoked SMALLINT NOT NULL DEFAULT 0,
    expires_at BIGINT NOT NULL,
    consumed_at BIGINT,
    created_at BIGINT NOT NULL,
    retry_response BYTEA
);
CREATE INDEX IF NOT EXISTS idx_oidc_refresh_tokens_parent ON oidc_refresh_tokens(parent_id);
CREATE INDEX IF NOT EXISTS idx_oidc_refresh_tokens_grant ON oidc_refresh_tokens(grant_id);
CREATE INDEX IF NOT EXISTS idx_oidc_refresh_tokens_expires ON oidc_refresh_tokens(expires_at);
-- Deleting a client revokes its outstanding tokens with an UPDATE
-- filtered on client_id alone. An UPDATE over an unindexed column scans
-- the table exactly as a DELETE does, and on MySQL it locks every row it
-- examines rather than every row it changes, so the whole table is held
-- against concurrent refresh and introspection until the cascade ends.
CREATE INDEX IF NOT EXISTS idx_oidc_refresh_tokens_client ON oidc_refresh_tokens(client_id);

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
CREATE INDEX IF NOT EXISTS idx_oidc_access_tokens_expires ON oidc_access_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_oidc_access_tokens_client ON oidc_access_tokens(client_id);

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
CREATE INDEX IF NOT EXISTS idx_oidc_opaque_access_tokens_client ON oidc_opaque_access_tokens(client_id);

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
    authorization_details JSONB NOT NULL DEFAULT 'null'::jsonb,
    updated_at BIGINT NOT NULL,
    created_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_oidc_grants_sub_client ON oidc_grants(subject, client_id, updated_at);
-- The composite index above leads with subject, so it cannot serve the
-- client-scoped cascade a client deletion runs
-- (DELETE FROM oidc_grants WHERE client_id = ?).
CREATE INDEX IF NOT EXISTS idx_oidc_grants_client ON oidc_grants(client_id);
CREATE INDEX IF NOT EXISTS idx_oidc_grants_client_subject ON oidc_grants(client_id, subject, updated_at);

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
CREATE INDEX IF NOT EXISTS idx_oidc_sessions_expires ON oidc_sessions(expires_at);

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
CREATE INDEX IF NOT EXISTS idx_oidc_par_records_expires ON oidc_par_records(expires_at);

CREATE TABLE IF NOT EXISTS oidc_interactions (
    id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    step TEXT NOT NULL,
    raw_state BYTEA NOT NULL,
    expires_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    created_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_oidc_interactions_expires ON oidc_interactions(expires_at);

CREATE TABLE IF NOT EXISTS oidc_consumed_jtis (
    jti TEXT PRIMARY KEY,
    expires_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_oidc_consumed_jtis_expires ON oidc_consumed_jtis(expires_at);

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
    allowed_scopes JSONB NULL,
    created_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS oidc_op_metadata (
    meta_key TEXT PRIMARY KEY,
    meta_value TEXT NOT NULL
);

-- oidc_device_codes.id stores the SHA-256 hex digest (64 ASCII chars)
-- of the RFC 8628 device_code bearer secret the device polls with at
-- the token endpoint; the raw value is never persisted. The adapter
-- computes the digest on Save / Find / state transitions via the
-- shared op/storeadapter/patterns.Digest helper. user_code is the
-- human-read-aloud value gated by the package's brute-force lockout,
-- so it is stored canonicalised (uppercase, separators stripped) and
-- carries a UNIQUE constraint so a fresh user_code never collides with
-- a live record.
CREATE TABLE IF NOT EXISTS oidc_device_codes (
    id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    user_code TEXT NOT NULL,
    subject TEXT NOT NULL DEFAULT '',
    scope JSONB NOT NULL DEFAULT '[]'::jsonb,
    resource JSONB NOT NULL DEFAULT '[]'::jsonb,
    dpop_jkt TEXT NOT NULL DEFAULT '',
    mtls_cert_thumbprint TEXT NOT NULL DEFAULT '',
    poll_interval BIGINT NOT NULL DEFAULT 0,
    status SMALLINT NOT NULL DEFAULT 0,
    auth_time BIGINT NOT NULL DEFAULT 0,
    deny_reason TEXT NOT NULL DEFAULT '',
    user_code_strikes SMALLINT NOT NULL DEFAULT 0,
    poll_violations SMALLINT NOT NULL DEFAULT 0,
    last_polled_at BIGINT,
    expires_at BIGINT NOT NULL,
    issued_at BIGINT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS oidc_device_codes_user_code ON oidc_device_codes(user_code);
CREATE INDEX IF NOT EXISTS idx_oidc_device_codes_expires ON oidc_device_codes(expires_at);

-- oidc_ciba_requests.id stores the SHA-256 hex digest (64 ASCII chars)
-- of the OIDC CIBA auth_req_id bearer secret the client polls with at
-- the token endpoint; the raw value is never persisted. The adapter
-- computes the digest on Save / Find / state transitions via the
-- shared op/storeadapter/patterns.Digest helper.
CREATE TABLE IF NOT EXISTS oidc_ciba_requests (
    id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    subject TEXT NOT NULL DEFAULT '',
    scope JSONB NOT NULL DEFAULT '[]'::jsonb,
    resource JSONB NOT NULL DEFAULT '[]'::jsonb,
    acr_values JSONB NOT NULL DEFAULT '[]'::jsonb,
    acr TEXT NOT NULL DEFAULT '',
    binding_message TEXT NOT NULL DEFAULT '',
    user_code TEXT NOT NULL DEFAULT '',
    dpop_jkt TEXT NOT NULL DEFAULT '',
    mtls_cert_thumbprint TEXT NOT NULL DEFAULT '',
    poll_interval BIGINT NOT NULL DEFAULT 0,
    status SMALLINT NOT NULL DEFAULT 0,
    auth_time BIGINT NOT NULL DEFAULT 0,
    deny_reason TEXT NOT NULL DEFAULT '',
    poll_violations SMALLINT NOT NULL DEFAULT 0,
    last_polled_at BIGINT,
    expires_at BIGINT NOT NULL,
    issued_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_oidc_ciba_requests_expires ON oidc_ciba_requests(expires_at);

-- Authentication-factor substores.
--
-- These five tables back the factor stores a login flow requires
-- (op.StepTOTP, op.PrimaryPasskey, recovery codes, email OTP, and the
-- cross-factor brute-force counter). They are keyed by subject rather
-- than by a token identifier and carry no foreign key to the embedder's
-- user table: the adapter never joins against it.
--
-- Secret material is stored exactly as the library hands it over.
-- oidc_totp_secrets.secret_ciphertext is an AES-256-GCM blob, the
-- recovery code_hash values are argon2id modular-crypt encodings, and
-- the email-OTP salt / hash are the authenticator's opaque bytes.
-- Nothing here may be logged or parsed by the backend.

CREATE TABLE IF NOT EXISTS oidc_totp_secrets (
    subject TEXT PRIMARY KEY,
    secret_ciphertext BYTEA NOT NULL,
    row_version BIGINT NOT NULL DEFAULT 1,
    failed_count INTEGER NOT NULL DEFAULT 0,
    last_accepted_step BIGINT NOT NULL DEFAULT 0,
    confirmed_at BIGINT NOT NULL DEFAULT 0,
    first_failure_at BIGINT NOT NULL DEFAULT 0,
    locked_until BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS oidc_passkeys (
    credential_id BYTEA PRIMARY KEY,
    subject TEXT NOT NULL,
    public_key BYTEA NOT NULL,
    aaguid BYTEA NOT NULL,
    sign_count BIGINT NOT NULL DEFAULT 0,
    attestation_type TEXT NOT NULL DEFAULT '',
    transports JSONB NOT NULL DEFAULT '[]'::jsonb,
    attachment TEXT NOT NULL DEFAULT '',
    user_present SMALLINT NOT NULL DEFAULT 0,
    user_verified SMALLINT NOT NULL DEFAULT 0,
    backup_eligible SMALLINT NOT NULL DEFAULT 0,
    backup_state SMALLINT NOT NULL DEFAULT 0,
    clone_warning SMALLINT NOT NULL DEFAULT 0,
    created_at BIGINT NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_oidc_passkeys_subject ON oidc_passkeys(subject);

-- One row per recovery-code slot rather than one row per batch: the
-- single-use guarantee is then a conditional UPDATE on the slot itself,
-- so two concurrent redemptions of the same code cannot both win.
-- generated_at is denormalised across the batch's rows because the
-- library reads and writes the batch as a unit.
CREATE TABLE IF NOT EXISTS oidc_recovery_codes (
    subject TEXT NOT NULL,
    slot_index INTEGER NOT NULL,
    code_hash TEXT NOT NULL,
    consumed_at BIGINT NOT NULL DEFAULT 0,
    generated_at BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (subject, slot_index)
);

-- retain_until governs row retention independently of expires_at: the
-- rate-limit and brute-force counters have to outlive the code they
-- were accumulated against, otherwise pacing sends to the code TTL
-- silently resets them.
CREATE TABLE IF NOT EXISTS oidc_email_otps (
    subject TEXT PRIMARY KEY,
    code_salt BYTEA NOT NULL,
    code_hash BYTEA NOT NULL,
    row_version BIGINT NOT NULL DEFAULT 1,
    failed_count INTEGER NOT NULL DEFAULT 0,
    send_count INTEGER NOT NULL DEFAULT 0,
    sent_at BIGINT NOT NULL DEFAULT 0,
    expires_at BIGINT NOT NULL DEFAULT 0,
    retain_until BIGINT NOT NULL DEFAULT 0,
    first_failure_at BIGINT NOT NULL DEFAULT 0,
    locked_until BIGINT NOT NULL DEFAULT 0,
    consumed_at BIGINT NOT NULL DEFAULT 0,
    send_window_start BIGINT NOT NULL DEFAULT 0,
    last_send_attempt_at BIGINT NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_oidc_email_otps_retain ON oidc_email_otps(retain_until);

CREATE TABLE IF NOT EXISTS oidc_authn_lockouts (
    subject TEXT PRIMARY KEY,
    failed_count INTEGER NOT NULL DEFAULT 0,
    record_version BIGINT NOT NULL DEFAULT 0,
    first_failure_at BIGINT NOT NULL DEFAULT 0,
    locked_until BIGINT NOT NULL DEFAULT 0
);
