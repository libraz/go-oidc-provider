ALTER TABLE oidc_refresh_tokens
    ADD INDEX idx_oidc_refresh_tokens_client (client_id);
ALTER TABLE oidc_access_tokens
    ADD INDEX idx_oidc_access_tokens_client (client_id);
ALTER TABLE oidc_opaque_access_tokens
    ADD INDEX idx_oidc_opaque_access_tokens_client (client_id);
ALTER TABLE oidc_users
    MODIFY username VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL;
