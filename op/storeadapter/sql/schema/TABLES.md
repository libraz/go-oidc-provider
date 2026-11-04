# SQL adapter tables

<!-- Generated from tables.go by TestTablesDoc; regenerate with `go test -run TestTablesDoc -update .` in op/storeadapter/sql. -->

Two things to do, whatever your configuration:

- **Run `Store.Migrate`, or apply every file from `Store.Migrations()` with
  your migration tool.** Either creates all the tables below; the ones your
  configuration does not use stay empty.
- **Give your users table an opaque subject column, if it lacks one.** It is
  the only change to your own tables. An identifier assigned once and never
  reused already qualifies; an auto-increment id or an email address does not.

With your own user store, `oidc_users` exists but stays empty and needs no
sync: the OP reads users through your `store.UserStore`.

`op.New` checks the tables the configuration uses (the "Checked when"
column) and names every missing one in a single error, so a run against an
empty database lists what the configuration needs. `Store.ValidateSchema`,
the deploy gate, checks every table. `WithTablePrefix` replaces the `oidc_`
prefix of every name and `WithNaming` renames one table through its key; the
columns are fixed.

## Which tables a configuration reads

The default configuration (the `authorization_code` and `refresh_token`
grants, password login against your own user store, every other option at its
default) needs these 13 tables: `oidc_clients`, `oidc_op_metadata`, `oidc_consumed_jtis`, `oidc_access_tokens`, `oidc_opaque_access_tokens`, `oidc_grant_revocations`, `oidc_revoked_jtis`, `oidc_grants`, `oidc_authorization_codes`, `oidc_refresh_tokens`, `oidc_sessions`, `oidc_interactions`, `oidc_authn_lockouts`.

Of these, the following 9 are checked in every configuration, even while the
feature that writes them is unused, so they must exist empty: `oidc_clients`, `oidc_op_metadata`, `oidc_consumed_jtis`, `oidc_access_tokens`, `oidc_opaque_access_tokens`, `oidc_grant_revocations`, `oidc_revoked_jtis`, `oidc_grants`, `oidc_refresh_tokens`. The access-token
tables are among them because revocation and introspection look every presented
token up, although rows appear only under the configuration their row names.

Column types differ by dialect; `schema/<dialect>/v1.sql` is authoritative.
A column marked with a release was added to an existing table in that release;
an existing database applies the matching file under `migrations/<dialect>`.
op.New and `Store.ValidateSchema` check that every column listed here exists.

| Table | `WithNaming` key | Holds | Checked when | Rows appear when |
|---|---|---|---|---|
| `oidc_clients` | `clients` | Client registrations and their secret hashes. | Always. | Always read. Written by `op.WithStaticClients`, dynamic registration, and your own client management. |
| `oidc_authorization_codes` | `authorization_codes` | Authorization codes awaiting redemption, with the authentication context they were issued under. | The `authorization_code` grant is enabled. | The `authorization_code` grant is enabled. |
| `oidc_refresh_tokens` | `refresh_tokens` | Refresh-token rotation chains and the response a retried rotation replays. | Always: `/revocation`, `/introspect`, subject revocation and the client-deletion cascade look refresh tokens up and clear them, whichever grants are enabled. | Written when the `refresh_token` grant is enabled; read by revocation and introspection in every configuration. |
| `oidc_access_tokens` | `access_tokens` | JTI registry of issued JWT access tokens. | Always: verifying a JWT access token issued without a grant, such as a `client_credentials` one, reads it, and deleting a client clears it. | `op.WithAccessTokenRevocationStrategy(op.RevocationStrategyJTIRegistry)`. |
| `oidc_opaque_access_tokens` | `opaque_access_tokens` | Opaque access tokens and the claims introspection returns for them. | Always: `/revocation` looks every presented token up in it and the revocation cascade clears it, so tokens issued before a format change stay revocable. | An opaque format is configured through `op.WithAccessTokenFormat` or `op.WithAccessTokenFormatPerAudience`. |
| `oidc_grant_revocations` | `grant_revocations` | Grant tombstones that invalidate a revoked grant's JWT access tokens. | Always: under the default revocation strategy, every authorization-code and refresh-token redemption and every JWT access-token check reads it. | The default `RevocationStrategyGrantTombstone`, when a grant or its access tokens are revoked. |
| `oidc_revoked_jtis` | `revoked_jtis` | Individually revoked JWT access-token identifiers. | Always: under the default revocation strategy, every JWT access-token check reads it. | The default `RevocationStrategyGrantTombstone`, when `/revocation` revokes a JWT access token. |
| `oidc_grants` | `grants` | The consented grant (client, subject, scopes) that codes and refresh tokens hang off. | Always: `op.New` reads it at construction. | Any grant other than `client_credentials`. |
| `oidc_sessions` | `sessions` | Browser login sessions and their chooser groups. | The `authorization_code` grant is enabled, so logins run through `/auth`. | A browser login runs through `/auth`. |
| `oidc_par_records` | `par_records` | Pushed authorization requests until their `request_uri` is redeemed. | `feature.PAR` is enabled. | `feature.PAR` is enabled. |
| `oidc_interactions` | `interactions` | In-progress login and consent interactions. | The `authorization_code` grant is enabled, so logins run through `/auth`. | A browser login runs through `/auth`. |
| `oidc_consumed_jtis` | `consumed_jtis` | Replay markers for request objects, client assertions and DPoP proofs. | Always: whether a client sends a request object, a `private_key_jwt` assertion or a DPoP proof is the client's choice, not the configuration's. | A client sends a JAR request object, a `private_key_jwt` assertion, or a DPoP proof. |
| `oidc_users` | `users` | The adapter's own user records: subject, claims, optional username and password hash. | The adapter's `Users()` is passed to `PrimaryPassword.Store`, `StepEmailOTP.Users` or `op.WithUserStore`. | Only through your own writes, plus the OP's rehash of a legacy password when the adapter's `Users()` is `PrimaryPassword.Store`. |
| `oidc_initial_access_tokens` | `initial_access_tokens` | Initial access tokens that authorize dynamic client registration. | `op.WithDynamicRegistration` is set. | `op.WithDynamicRegistration`. |
| `oidc_registration_access_tokens` | `registration_access_tokens` | Registration access tokens for RFC 7592 client management. | `op.WithDynamicRegistration` is set. | `op.WithDynamicRegistration`. |
| `oidc_op_metadata` | `op_metadata` | OP-internal markers, such as the subject mode the pairwise gate pins. | Always: `op.New` reads it at construction. | `op.New` reads and writes it at construction. |
| `oidc_device_codes` | `device_codes` | RFC 8628 device authorization records. | The `device_code` grant is enabled or `op.WithDeviceCodeGrant` is set. | The `device_code` grant is enabled. |
| `oidc_ciba_requests` | `ciba_requests` | CIBA backchannel authentication requests. | The CIBA grant is enabled or `op.WithCIBA` is set. | `op.WithCIBA`. |
| `oidc_totp_secrets` | `totp_secrets` | Encrypted TOTP secrets. | The login flow has an `op.StepTOTP` backed by `Store.TOTPs()`. | `Store.TOTPs()` is passed to `op.StepTOTP`. |
| `oidc_passkeys` | `passkeys` | Registered WebAuthn credentials. | The login flow has a passkey step backed by `Store.Passkeys()`. | `Store.Passkeys()` is passed to `op.PrimaryPasskey` or `op/passkeykit`. |
| `oidc_recovery_codes` | `recovery_codes` | Hashed single-use recovery codes. | The login flow has an `op.StepRecoveryCode` backed by `Store.RecoveryCodes()`. | `Store.RecoveryCodes()` is passed to `op.StepRecoveryCode` or `op/recoverykit`. |
| `oidc_email_otps` | `email_otps` | Pending email one-time codes. | The login flow has an `op.StepEmailOTP` backed by `Store.EmailOTPs()`. | `Store.EmailOTPs()` is passed to `op.StepEmailOTP`. |
| `oidc_authn_lockouts` | `authn_lockouts` | Per-subject failure counters of the brute-force gate. | The login flow has a step that counts failures and `op.WithAuthnLockoutStore` names no other store. | The login flow has a password or second-factor step and `op.WithAuthnLockoutStore` names no other store. |
| `oidc_ssf_streams` | `ssf_streams` | Shared Signals Framework streams, one per receiving client. | `op.WithSharedSignals` is set. | `op.WithSharedSignals`. |
| `oidc_ssf_events` | `ssf_events` | Security Event Tokens queued for delivery to a stream, as unsigned claims. | `op.WithSharedSignals` is set. | `op.WithSharedSignals`. |

## Columns

### `oidc_clients`

Substore: `Store.Clients()`

- `id`
- `client_id_issued_at`
- `redirect_uris`
- `post_logout_redirect_uris`
- `backchannel_logout_uri`
- `backchannel_logout_session_required`
- `grant_types`
- `response_types`
- `scopes`
- `resources`
- `token_endpoint_auth_method`
- `token_endpoint_auth_signing_alg`
- `secret_hash`
- `previous_secret_hash` (v1.5.0)
- `previous_secret_expires_at` (v1.5.0)
- `public_client`
- `source`
- `application_type`
- `subject_type`
- `id_token_signed_response_alg`
- `introspection_signed_response_alg`
- `sector_identifier_uri`
- `client_name`
- `client_uri`
- `logo_uri`
- `policy_uri`
- `tos_uri`
- `jwks_uri`
- `jwks`
- `contacts`
- `default_max_age`
- `require_auth_time`
- `default_acr_values`
- `initiate_login_uri`
- `request_uris`
- `request_object_signing_alg`
- `request_object_encryption_alg`
- `request_object_encryption_enc`
- `id_token_encrypted_response_alg`
- `id_token_encrypted_response_enc`
- `userinfo_encrypted_response_alg`
- `userinfo_encrypted_response_enc`
- `authorization_encrypted_response_alg`
- `authorization_encrypted_response_enc`
- `introspection_encrypted_response_alg`
- `introspection_encrypted_response_enc`

### `oidc_authorization_codes`

Substore: `Store.AuthorizationCodes()`

- `id`
- `client_id`
- `grant_id`
- `subject`
- `redirect_uri`
- `scope`
- `resource`
- `code_challenge`
- `code_challenge_method`
- `nonce`
- `state`
- `dpop_jkt`
- `auth_time` (v1.4.0)
- `acr` (v1.4.0)
- `amr` (v1.4.0)
- `authorization_details` (v1.4.0)
- `claims` (v1.4.0)
- `authorization_recorded` (v1.4.0)
- `expires_at`
- `consumed_at`
- `created_at`

### `oidc_refresh_tokens`

Substore: `Store.RefreshTokens()`

- `id`
- `client_id`
- `grant_id`
- `parent_id`
- `subject`
- `subject_public`
- `scope`
- `resource`
- `origin`
- `auth_time`
- `acr`
- `amr`
- `authorization_details`
- `access_token_extra`
- `claims` (v1.4.0)
- `chain_id` (v1.4.0)
- `authorization_recorded` (v1.4.0)
- `dpop_jkt`
- `mtls_cert_thumbprint`
- `nonce`
- `revoked`
- `expires_at`
- `consumed_at`
- `created_at`
- `retry_response`

### `oidc_access_tokens`

Substore: `Store.AccessTokens()`

- `jti`
- `client_id`
- `grant_id`
- `subject`
- `scopes`
- `revoked`
- `expires_at`
- `issued_at`

### `oidc_opaque_access_tokens`

Substore: `Store.OpaqueAccessTokens()`

- `token_hash`
- `grant_id`
- `subject`
- `client_id`
- `audience`
- `scope`
- `acr`
- `amr`
- `auth_time`
- `authorization_details` (v1.4.0)
- `claims` (v1.4.0)
- `chain_id` (v1.4.0)
- `authorization_recorded` (v1.4.0)
- `dpop_jkt`
- `mtls_cert_thumb`
- `issued_at`
- `expires_at`
- `revoked`

### `oidc_grant_revocations`

Substore: `Store.GrantRevocations()`

- `grant_id`
- `access_revoked_at` (v1.4.0)
- `revoked_at`
- `expires_at`
- `reason`

### `oidc_revoked_jtis`

Substore: `Store.GrantRevocations()`

- `jti`
- `grant_id`
- `expires_at`

### `oidc_grants`

Substore: `Store.Grants()`

- `id`
- `client_id`
- `subject`
- `scope`
- `claims`
- `auth_time`
- `acr`
- `amr`
- `authorization_details`
- `updated_at`
- `created_at`

### `oidc_sessions`

Substore: `Store.Sessions()`

- `id`
- `chooser_group_id`
- `subject`
- `auth_time`
- `amr`
- `acr`
- `expires_at`
- `updated_at`
- `created_at`

### `oidc_par_records`

Substore: `Store.PushedAuthRequests()`

- `uri`
- `client_id`
- `raw_params`
- `expires_at`
- `consumed_at`
- `created_at`

### `oidc_interactions`

Substore: `Store.Interactions()`

- `id`
- `client_id`
- `step`
- `raw_state`
- `expires_at`
- `updated_at`
- `created_at`

### `oidc_consumed_jtis`

Substore: `Store.ConsumedJTIs()`

- `jti`
- `expires_at`

### `oidc_users`

Substore: `Store.Users()`

- `subject`
- `claims`
- `updated_at`
- `username`
- `password_hash`

### `oidc_initial_access_tokens`

Substore: `Store.InitialAccessTokens()`

- `id`
- `hashed_value`
- `max_uses`
- `uses`
- `allowed_scopes`
- `tag`
- `expires_at`
- `created_at`

### `oidc_registration_access_tokens`

Substore: `Store.RegistrationAccessTokens()`

- `client_id`
- `hashed_value`
- `allowed_scopes` (v1.1.0)
- `created_at`

### `oidc_op_metadata`

Substore: `Store.Metadata()`

- `meta_key`
- `meta_value`

### `oidc_device_codes`

Substore: `Store.DeviceCodes()`

- `id`
- `client_id`
- `user_code`
- `subject`
- `scope`
- `resource`
- `dpop_jkt`
- `mtls_cert_thumbprint`
- `poll_interval`
- `status`
- `auth_time`
- `deny_reason`
- `user_code_strikes`
- `poll_violations`
- `last_polled_at`
- `expires_at`
- `issued_at`

### `oidc_ciba_requests`

Substore: `Store.CIBARequests()`

- `id`
- `client_id`
- `subject`
- `scope`
- `resource`
- `acr_values`
- `acr`
- `binding_message`
- `user_code`
- `dpop_jkt`
- `mtls_cert_thumbprint`
- `poll_interval`
- `status`
- `auth_time`
- `deny_reason`
- `poll_violations`
- `last_polled_at`
- `expires_at`
- `issued_at`

### `oidc_totp_secrets`

Substore: `Store.TOTPs()`

- `subject`
- `secret_ciphertext`
- `row_version` (v1.1.0)
- `failed_count`
- `last_accepted_step`
- `confirmed_at`
- `first_failure_at`
- `locked_until`

### `oidc_passkeys`

Substore: `Store.Passkeys()`

- `credential_id`
- `subject`
- `public_key`
- `aaguid`
- `sign_count`
- `attestation_type`
- `transports`
- `attachment`
- `user_present`
- `user_verified`
- `backup_eligible`
- `backup_state`
- `clone_warning`
- `created_at`

### `oidc_recovery_codes`

Substore: `Store.RecoveryCodes()`

- `subject`
- `slot_index`
- `code_hash`
- `consumed_at`
- `generated_at`

### `oidc_email_otps`

Substore: `Store.EmailOTPs()`

- `subject`
- `code_salt`
- `code_hash`
- `row_version` (v1.1.0)
- `failed_count`
- `send_count`
- `sent_at`
- `expires_at`
- `retain_until`
- `first_failure_at`
- `locked_until`
- `consumed_at`
- `send_window_start`
- `last_send_attempt_at`

### `oidc_authn_lockouts`

Substore: `Store.AuthnLockouts()`

- `subject`
- `failed_count`
- `record_version`
- `first_failure_at`
- `locked_until`

### `oidc_ssf_streams`

Substore: `Store.SSFStreams()`

- `id`
- `client_id`
- `delivery_method`
- `endpoint_url`
- `sealed_authorization_header`
- `events_requested`
- `events_delivered`
- `description`
- `status`
- `status_reason`
- `updated_at`
- `created_at`

### `oidc_ssf_events`

Substore: `Store.SSFEvents()`

- `jti`
- `stream_id`
- `kind`
- `delivery_method`
- `held`
- `claims`
- `attempts`
- `next_attempt_at`
- `expires_at`
