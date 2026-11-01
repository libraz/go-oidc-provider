ALTER TABLE oidc_registration_access_tokens
    ADD COLUMN allowed_scopes JSON NULL;
ALTER TABLE oidc_totp_secrets
    ADD COLUMN row_version BIGINT NOT NULL DEFAULT 1;
ALTER TABLE oidc_email_otps
    ADD COLUMN row_version BIGINT NOT NULL DEFAULT 1;
ALTER TABLE oidc_grants
    ADD INDEX idx_oidc_grants_client_subject (client_id, subject, updated_at);
ALTER TABLE oidc_grants
    ADD INDEX idx_oidc_grants_client (client_id);
ALTER TABLE oidc_authorization_codes
    ADD INDEX idx_oidc_authorization_codes_expires (expires_at);
ALTER TABLE oidc_refresh_tokens
    ADD INDEX idx_oidc_refresh_tokens_expires (expires_at);
ALTER TABLE oidc_access_tokens
    ADD INDEX idx_oidc_access_tokens_expires (expires_at);
ALTER TABLE oidc_sessions
    ADD INDEX idx_oidc_sessions_expires (expires_at);
ALTER TABLE oidc_par_records
    ADD INDEX idx_oidc_par_records_expires (expires_at);
ALTER TABLE oidc_interactions
    ADD INDEX idx_oidc_interactions_expires (expires_at);
ALTER TABLE oidc_consumed_jtis
    ADD INDEX idx_oidc_consumed_jtis_expires (expires_at);
