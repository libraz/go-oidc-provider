package oidcsql

import (
	"context"

	"github.com/libraz/go-oidc-provider/op/store"
)

// Each substore checks only the tables it reads and writes, so op.New can
// check the tables a configuration uses and leave the rest uncreated. The
// checks are those of [Store.ValidateSchema].

var (
	_ store.SchemaValidator = (*clientStore)(nil)
	_ store.SchemaValidator = (*authCodeStore)(nil)
	_ store.SchemaValidator = (*refreshStore)(nil)
	_ store.SchemaValidator = (*accessTokenStore)(nil)
	_ store.SchemaValidator = (*opaqueAccessTokenStore)(nil)
	_ store.SchemaValidator = (*grantRevocationStore)(nil)
	_ store.SchemaValidator = (*grantStore)(nil)
	_ store.SchemaValidator = (*sessionStore)(nil)
	_ store.SchemaValidator = (*parStore)(nil)
	_ store.SchemaValidator = (*interactionStore)(nil)
	_ store.SchemaValidator = (*jtiStore)(nil)
	_ store.SchemaValidator = (*userStore)(nil)
	_ store.SchemaValidator = (*iatStore)(nil)
	_ store.SchemaValidator = (*ratStore)(nil)
	_ store.SchemaValidator = (*metadataStore)(nil)
	_ store.SchemaValidator = (*deviceCodeStore)(nil)
	_ store.SchemaValidator = (*cibaRequestStore)(nil)
	_ store.SchemaValidator = (*totpStore)(nil)
	_ store.SchemaValidator = (*passkeyStore)(nil)
	_ store.SchemaValidator = (*recoveryStore)(nil)
	_ store.SchemaValidator = (*emailOTPStore)(nil)
	_ store.SchemaValidator = (*authnLockoutStore)(nil)
	_ store.SchemaValidator = (*ssfStreamStore)(nil)
	_ store.SchemaValidator = (*ssfEventStore)(nil)
)

// ValidateSchema implements [store.SchemaValidator] for the clients table.
func (s *clientStore) ValidateSchema(ctx context.Context) error {
	return s.parent.validateKeys(ctx, "clients")
}

// ValidateSchema implements [store.SchemaValidator] for the
// authorization_codes table.
func (s *authCodeStore) ValidateSchema(ctx context.Context) error {
	return s.parent.validateKeys(ctx, "authorization_codes")
}

// ValidateSchema implements [store.SchemaValidator] for the refresh_tokens
// table.
func (s *refreshStore) ValidateSchema(ctx context.Context) error {
	return s.parent.validateKeys(ctx, "refresh_tokens")
}

// ValidateSchema implements [store.SchemaValidator] for the access_tokens
// table.
func (s *accessTokenStore) ValidateSchema(ctx context.Context) error {
	return s.parent.validateKeys(ctx, "access_tokens")
}

// ValidateSchema implements [store.SchemaValidator] for the
// opaque_access_tokens table.
func (s *opaqueAccessTokenStore) ValidateSchema(ctx context.Context) error {
	return s.parent.validateKeys(ctx, "opaque_access_tokens")
}

// ValidateSchema implements [store.SchemaValidator] for both tables the
// substore fronts: grant_revocations and revoked_jtis.
func (s *grantRevocationStore) ValidateSchema(ctx context.Context) error {
	return s.parent.validateKeys(ctx, "grant_revocations", "revoked_jtis")
}

// ValidateSchema implements [store.SchemaValidator] for the grants table.
func (s *grantStore) ValidateSchema(ctx context.Context) error {
	return s.parent.validateKeys(ctx, "grants")
}

// ValidateSchema implements [store.SchemaValidator] for the sessions table.
func (s *sessionStore) ValidateSchema(ctx context.Context) error {
	return s.parent.validateKeys(ctx, "sessions")
}

// ValidateSchema implements [store.SchemaValidator] for the par_records
// table.
func (s *parStore) ValidateSchema(ctx context.Context) error {
	return s.parent.validateKeys(ctx, "par_records")
}

// ValidateSchema implements [store.SchemaValidator] for the interactions
// table.
func (s *interactionStore) ValidateSchema(ctx context.Context) error {
	return s.parent.validateKeys(ctx, "interactions")
}

// ValidateSchema implements [store.SchemaValidator] for the consumed_jtis
// table.
func (s *jtiStore) ValidateSchema(ctx context.Context) error {
	return s.parent.validateKeys(ctx, "consumed_jtis")
}

// ValidateSchema implements [store.SchemaValidator] for the users table.
func (s *userStore) ValidateSchema(ctx context.Context) error {
	return s.parent.validateKeys(ctx, "users")
}

// ValidateSchema implements [store.SchemaValidator] for the
// initial_access_tokens table.
func (s *iatStore) ValidateSchema(ctx context.Context) error {
	return s.parent.validateKeys(ctx, "initial_access_tokens")
}

// ValidateSchema implements [store.SchemaValidator] for the
// registration_access_tokens table.
func (s *ratStore) ValidateSchema(ctx context.Context) error {
	return s.parent.validateKeys(ctx, "registration_access_tokens")
}

// ValidateSchema implements [store.SchemaValidator] for the op_metadata
// table.
func (s *metadataStore) ValidateSchema(ctx context.Context) error {
	return s.parent.validateKeys(ctx, "op_metadata")
}

// ValidateSchema implements [store.SchemaValidator] for the device_codes
// table.
func (s *deviceCodeStore) ValidateSchema(ctx context.Context) error {
	return s.parent.validateKeys(ctx, "device_codes")
}

// ValidateSchema implements [store.SchemaValidator] for the ciba_requests
// table.
func (s *cibaRequestStore) ValidateSchema(ctx context.Context) error {
	return s.parent.validateKeys(ctx, "ciba_requests")
}

// ValidateSchema implements [store.SchemaValidator] for the totp_secrets
// table.
func (s *totpStore) ValidateSchema(ctx context.Context) error {
	return s.parent.validateKeys(ctx, "totp_secrets")
}

// ValidateSchema implements [store.SchemaValidator] for the passkeys table.
func (s *passkeyStore) ValidateSchema(ctx context.Context) error {
	return s.parent.validateKeys(ctx, "passkeys")
}

// ValidateSchema implements [store.SchemaValidator] for the recovery_codes
// table.
func (s *recoveryStore) ValidateSchema(ctx context.Context) error {
	return s.parent.validateKeys(ctx, "recovery_codes")
}

// ValidateSchema implements [store.SchemaValidator] for the email_otps
// table.
func (s *emailOTPStore) ValidateSchema(ctx context.Context) error {
	return s.parent.validateKeys(ctx, "email_otps")
}

// ValidateSchema implements [store.SchemaValidator] for the authn_lockouts
// table.
func (s *authnLockoutStore) ValidateSchema(ctx context.Context) error {
	return s.parent.validateKeys(ctx, "authn_lockouts")
}

// ValidateSchema implements [store.SchemaValidator] for the ssf_streams
// table.
func (s *ssfStreamStore) ValidateSchema(ctx context.Context) error {
	return s.parent.validateKeys(ctx, "ssf_streams")
}

// ValidateSchema implements [store.SchemaValidator] for the ssf_events
// table.
func (s *ssfEventStore) ValidateSchema(ctx context.Context) error {
	return s.parent.validateKeys(ctx, "ssf_events")
}
