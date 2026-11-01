CREATE INDEX IF NOT EXISTS idx_oidc_refresh_tokens_client
    ON oidc_refresh_tokens(client_id);
CREATE INDEX IF NOT EXISTS idx_oidc_access_tokens_client
    ON oidc_access_tokens(client_id);
CREATE INDEX IF NOT EXISTS idx_oidc_opaque_access_tokens_client
    ON oidc_opaque_access_tokens(client_id);
