ALTER TABLE oidc_authorization_codes
    ADD COLUMN auth_time BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN acr VARCHAR(255) NOT NULL DEFAULT '',
    ADD COLUMN amr JSON NULL,
    ADD COLUMN authorization_details JSON NULL,
    ADD COLUMN claims JSON NULL,
    ADD COLUMN authorization_recorded TINYINT(1) NOT NULL DEFAULT 0;
ALTER TABLE oidc_refresh_tokens
    ADD COLUMN claims JSON NULL,
    ADD COLUMN authorization_recorded TINYINT(1) NOT NULL DEFAULT 0;
ALTER TABLE oidc_opaque_access_tokens
    ADD COLUMN authorization_details JSON NULL,
    ADD COLUMN claims JSON NULL,
    ADD COLUMN authorization_recorded TINYINT(1) NOT NULL DEFAULT 0;
ALTER TABLE oidc_refresh_tokens
    ADD COLUMN chain_id VARCHAR(64) NOT NULL DEFAULT '';
ALTER TABLE oidc_opaque_access_tokens
    ADD COLUMN chain_id VARCHAR(64) NOT NULL DEFAULT '';
ALTER TABLE oidc_grant_revocations
    ADD COLUMN access_revoked_at BIGINT NOT NULL DEFAULT 0;
