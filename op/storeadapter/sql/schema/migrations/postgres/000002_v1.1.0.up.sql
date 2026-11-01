ALTER TABLE oidc_registration_access_tokens
    ADD COLUMN allowed_scopes JSONB NULL;
ALTER TABLE oidc_totp_secrets
    ADD COLUMN row_version BIGINT NOT NULL DEFAULT 1;
ALTER TABLE oidc_email_otps
    ADD COLUMN row_version BIGINT NOT NULL DEFAULT 1;
CREATE INDEX IF NOT EXISTS idx_oidc_grants_client_subject
    ON oidc_grants(client_id, subject, updated_at);
CREATE INDEX IF NOT EXISTS idx_oidc_grants_client
    ON oidc_grants(client_id);
CREATE INDEX IF NOT EXISTS idx_oidc_authorization_codes_expires
    ON oidc_authorization_codes(expires_at);
CREATE INDEX IF NOT EXISTS idx_oidc_refresh_tokens_expires
    ON oidc_refresh_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_oidc_access_tokens_expires
    ON oidc_access_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_oidc_sessions_expires
    ON oidc_sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_oidc_par_records_expires
    ON oidc_par_records(expires_at);
CREATE INDEX IF NOT EXISTS idx_oidc_interactions_expires
    ON oidc_interactions(expires_at);
CREATE INDEX IF NOT EXISTS idx_oidc_consumed_jtis_expires
    ON oidc_consumed_jtis(expires_at);
