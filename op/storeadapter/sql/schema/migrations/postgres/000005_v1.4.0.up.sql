ALTER TABLE oidc_authorization_codes
    ADD COLUMN auth_time BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN acr TEXT NOT NULL DEFAULT '',
    ADD COLUMN amr JSONB NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN authorization_details JSONB NOT NULL DEFAULT 'null'::jsonb,
    ADD COLUMN claims JSONB NOT NULL DEFAULT 'null'::jsonb,
    ADD COLUMN authorization_recorded SMALLINT NOT NULL DEFAULT 0;
ALTER TABLE oidc_refresh_tokens
    ADD COLUMN claims JSONB NOT NULL DEFAULT 'null'::jsonb,
    ADD COLUMN authorization_recorded SMALLINT NOT NULL DEFAULT 0;
ALTER TABLE oidc_opaque_access_tokens
    ADD COLUMN authorization_details JSONB NOT NULL DEFAULT 'null'::jsonb,
    ADD COLUMN claims JSONB NOT NULL DEFAULT 'null'::jsonb,
    ADD COLUMN authorization_recorded SMALLINT NOT NULL DEFAULT 0;
ALTER TABLE oidc_refresh_tokens
    ADD COLUMN chain_id TEXT NOT NULL DEFAULT '';
ALTER TABLE oidc_opaque_access_tokens
    ADD COLUMN chain_id TEXT NOT NULL DEFAULT '';
ALTER TABLE oidc_grant_revocations
    ADD COLUMN access_revoked_at BIGINT NOT NULL DEFAULT 0;
