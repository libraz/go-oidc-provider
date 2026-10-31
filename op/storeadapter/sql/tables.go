package oidcsql

// tableInfo describes one table the adapter owns. schema/TABLES.md is
// generated from tableCatalog, so the published table reference cannot
// drift from the WithNaming keys, the DDL, or the release history below.
type tableInfo struct {
	key      string // WithNaming logical key
	accessor string // *Store method returning the substore
	holds    string
	used     string // when the OP reads or writes the table
}

// minimalTables are the keys of the tables a minimal deployment writes
// rows to: the default authorization_code and refresh_token grants,
// password login against the embedder's own user store, and every other
// option at its default. schema/TABLES.md lists them so the reader can
// tell the tables that fill from the ones created only to exist.
//
//nolint:gochecknoglobals // documentation table; read-only.
var minimalTables = []string{
	"clients", "authorization_codes", "refresh_tokens", "grants",
	"sessions", "interactions", "op_metadata", "authn_lockouts",
}

// tableCatalog lists every table in [knownNamingKeys] order.
//
//nolint:gochecknoglobals // documentation table; read-only.
var tableCatalog = []tableInfo{
	{
		"clients", "Clients", "Client registrations and their secret hashes.",
		"Always read. Written by `op.WithStaticClients`, dynamic registration, and your own client management.",
	},
	{
		"authorization_codes", "AuthorizationCodes", "Authorization codes awaiting redemption, with the authentication context they were issued under.",
		"The `authorization_code` grant is enabled.",
	},
	{
		"refresh_tokens", "RefreshTokens", "Refresh-token rotation chains and the response a retried rotation replays.",
		"The `refresh_token` grant is enabled.",
	},
	{
		"access_tokens", "AccessTokens", "JTI registry of issued JWT access tokens.",
		"`op.WithAccessTokenRevocationStrategy(op.RevocationStrategyJTIRegistry)`.",
	},
	{
		"opaque_access_tokens", "OpaqueAccessTokens", "Opaque access tokens and the claims introspection returns for them.",
		"An opaque format is configured through `op.WithAccessTokenFormat` or `op.WithAccessTokenFormatPerAudience`.",
	},
	{
		"grant_revocations", "GrantRevocations", "Grant tombstones that invalidate a revoked grant's JWT access tokens.",
		"The default `RevocationStrategyGrantTombstone`, when a grant or its access tokens are revoked.",
	},
	{
		"revoked_jtis", "GrantRevocations", "Individually revoked JWT access-token identifiers.",
		"The default `RevocationStrategyGrantTombstone`, when `/revocation` revokes a JWT access token.",
	},
	{
		"grants", "Grants", "The consented grant (client, subject, scopes) that codes and refresh tokens hang off.",
		"Any grant other than `client_credentials`.",
	},
	{
		"sessions", "Sessions", "Browser login sessions and their chooser groups.",
		"A browser login runs through `/auth`.",
	},
	{
		"par_records", "PushedAuthRequests", "Pushed authorization requests until their `request_uri` is redeemed.",
		"`feature.PAR` is enabled.",
	},
	{
		"interactions", "Interactions", "In-progress login and consent interactions.",
		"A browser login runs through `/auth`.",
	},
	{
		"consumed_jtis", "ConsumedJTIs", "Replay markers for request objects, client assertions and DPoP proofs.",
		"A client sends a JAR request object, a `private_key_jwt` assertion, or a DPoP proof.",
	},
	{
		"users", "Users", "The adapter's own user records: subject, claims, optional username and password hash.",
		"Read only when neither `op.WithUserStore` nor `PrimaryPassword.Store` supplies another user store; with your own user store it stays empty. The OP writes it only to rehash a legacy password when it is `PrimaryPassword.Store`.",
	},
	{
		"initial_access_tokens", "InitialAccessTokens", "Initial access tokens that authorize dynamic client registration.",
		"`op.WithDynamicRegistration`.",
	},
	{
		"registration_access_tokens", "RegistrationAccessTokens", "Registration access tokens for RFC 7592 client management.",
		"`op.WithDynamicRegistration`.",
	},
	{
		"op_metadata", "Metadata", "OP-internal markers, such as the subject mode the pairwise gate pins.",
		"Always: `op.New` reads and writes it at construction.",
	},
	{
		"device_codes", "DeviceCodes", "RFC 8628 device authorization records.",
		"The `device_code` grant is enabled.",
	},
	{
		"ciba_requests", "CIBARequests", "CIBA backchannel authentication requests.",
		"`op.WithCIBA`.",
	},
	{
		"totp_secrets", "TOTPs", "Encrypted TOTP secrets.",
		"`Store.TOTPs()` is passed to `op.StepTOTP`.",
	},
	{
		"passkeys", "Passkeys", "Registered WebAuthn credentials.",
		"`Store.Passkeys()` is passed to `op.PrimaryPasskey` or `op/passkeykit`.",
	},
	{
		"recovery_codes", "RecoveryCodes", "Hashed single-use recovery codes.",
		"`Store.RecoveryCodes()` is passed to `op.StepRecoveryCode` or `op/recoverykit`.",
	},
	{
		"email_otps", "EmailOTPs", "Pending email one-time codes.",
		"`Store.EmailOTPs()` is passed to `op.StepEmailOTP`.",
	},
	{
		"authn_lockouts", "AuthnLockouts", "Per-subject failure counters of the brute-force gate.",
		"The login flow has a password or second-factor step and `op.WithAuthnLockoutStore` names no other store.",
	},
}

// tableColumns names columns added to one table, by WithNaming key.
type tableColumns struct {
	key     string
	columns []string
}

// schemaRelease lists the columns a release added to tables that already
// existed. Each entry has a matching "## <version>" section in
// schema/MIGRATIONS.md, and [Store.ValidateSchema] requires every column
// here, naming the section to apply when one is missing. Releases that
// changed only indexes or collations have a section but no entry.
type schemaRelease struct {
	version string
	columns []tableColumns
}

//nolint:gochecknoglobals // schema history; read-only.
var schemaReleases = []schemaRelease{
	{"v1.1.0", []tableColumns{
		{"registration_access_tokens", []string{"allowed_scopes"}},
		{"totp_secrets", []string{"row_version"}},
		{"email_otps", []string{"row_version"}},
	}},
	{"v1.4.0", []tableColumns{
		{"authorization_codes", []string{"auth_time", "acr", "amr", "authorization_details", "claims", "authorization_recorded"}},
		{"refresh_tokens", []string{"claims", "authorization_recorded", "chain_id"}},
		{"opaque_access_tokens", []string{"authorization_details", "claims", "authorization_recorded", "chain_id"}},
		{"grant_revocations", []string{"access_revoked_at"}},
	}},
	{"v1.5.0", []tableColumns{
		{"clients", []string{"previous_secret_hash", "previous_secret_expires_at"}},
	}},
}

// columnAddedIn returns the release that added column to the table with
// the given WithNaming key, or "" for a column present since v1.0.0.
func columnAddedIn(key, column string) string {
	for _, r := range schemaReleases {
		for _, tc := range r.columns {
			if tc.key != key {
				continue
			}
			for _, c := range tc.columns {
				if c == column {
					return r.version
				}
			}
		}
	}
	return ""
}

// byKey returns the physical name for a WithNaming key, or "" for an
// unknown key. [nameMap.all] and [knownNamingKeys] share one order.
func (n nameMap) byKey(key string) string {
	all := n.all()
	for i, k := range knownNamingKeys {
		if k == key {
			return all[i]
		}
	}
	return ""
}
