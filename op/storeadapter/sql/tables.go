package oidcsql

import "strings"

// tableInfo describes one table the adapter owns. schema/TABLES.md is
// generated from tableCatalog, so the published table reference cannot
// drift from the WithNaming keys, the DDL, or the release history below.
type tableInfo struct {
	key      string // WithNaming logical key
	accessor string // *Store method returning the substore
	holds    string
	used     string // when rows appear in the table
	checked  string // when op.New checks the table; a key of [checkedWhen]
}

// checkedWhen describes, by tag, the configuration under which op.New
// checks a table at construction.
//
//nolint:gochecknoglobals,gosec // documentation table; read-only. G101: grant names, not credentials.
var checkedWhen = map[string]string{
	"always":                   "Always",
	"always:construction":      "Always: `op.New` reads it at construction",
	"always:jti-registry":      "Always: verifying a JWT access token issued without a grant, such as a `client_credentials` one, reads it, and deleting a client clears it",
	"always:opaque":            "Always: `/revocation` looks every presented token up in it and the revocation cascade clears it, so tokens issued before a format change stay revocable",
	"always:tombstone":         "Always: under the default revocation strategy, every authorization-code and refresh-token redemption and every JWT access-token check reads it",
	"always:denylist":          "Always: under the default revocation strategy, every JWT access-token check reads it",
	"always:client-jti":        "Always: whether a client sends a request object, a `private_key_jwt` assertion or a DPoP proof is the client's choice, not the configuration's",
	"grant:authorization_code": "The `authorization_code` grant is enabled",
	"always:refresh":           "Always: `/revocation`, `/introspect`, subject revocation and the client-deletion cascade look refresh tokens up and clear them, whichever grants are enabled",
	"authorize":                "The `authorization_code` grant is enabled, so logins run through `/auth`",
	"feature:par":              "`feature.PAR` is enabled",
	"dcr":                      "`op.WithDynamicRegistration` is set",
	"grant:device_code":        "The `device_code` grant is enabled or `op.WithDeviceCodeGrant` is set",
	"grant:ciba":               "The CIBA grant is enabled or `op.WithCIBA` is set",
	"ssf":                      "`op.WithSharedSignals` is set",
	"userstore":                "The adapter's `Users()` is passed to `PrimaryPassword.Store`, `StepEmailOTP.Users` or `op.WithUserStore`",
	"factor:totp":              "The login flow has an `op.StepTOTP` backed by `Store.TOTPs()`",
	"factor:passkey":           "The login flow has a passkey step backed by `Store.Passkeys()`",
	"factor:recovery":          "The login flow has an `op.StepRecoveryCode` backed by `Store.RecoveryCodes()`",
	"factor:email_otp":         "The login flow has an `op.StepEmailOTP` backed by `Store.EmailOTPs()`",
	"lockout":                  "The login flow has a step that counts failures and `op.WithAuthnLockoutStore` names no other store",
}

// tableRequired reports whether every configuration checks the table with
// the given WithNaming key, so it must exist even while it stays empty. A
// table with a condition, and the empty key, report false. GC derives the
// tables it may skip when absent from it.
func tableRequired(key string) bool {
	for _, info := range tableCatalog {
		if info.key == key {
			return strings.HasPrefix(info.checked, "always")
		}
	}
	return false
}

// defaultConfigTables are the keys of the tables op.New checks under the
// default configuration: the `authorization_code` and `refresh_token`
// grants, password login against the embedder's own user store, and every
// other option at its default.
//
//nolint:gochecknoglobals // documentation table; read-only.
var defaultConfigTables = []string{
	"clients", "op_metadata", "consumed_jtis", "access_tokens", "opaque_access_tokens",
	"grant_revocations", "revoked_jtis", "grants", "authorization_codes", "refresh_tokens",
	"sessions", "interactions", "authn_lockouts",
}

// binaryCollationColumns lists, by WithNaming key, the identifier columns
// the MySQL DDL pins to utf8mb4_bin. [Store.ValidateSchema] rejects any
// other collation on them, since a case- or accent-folding one lets two
// distinct identifiers resolve to one row.
//
//nolint:gochecknoglobals // schema invariant table; read-only.
var binaryCollationColumns = map[string][]string{
	"clients":                    {"id"},
	"authorization_codes":        {"client_id", "subject"},
	"refresh_tokens":             {"client_id", "subject"},
	"access_tokens":              {"client_id", "subject"},
	"opaque_access_tokens":       {"subject", "client_id"},
	"grants":                     {"client_id", "subject"},
	"sessions":                   {"subject"},
	"par_records":                {"client_id"},
	"interactions":               {"client_id"},
	"users":                      {"subject", "username"},
	"registration_access_tokens": {"client_id"},
	"device_codes":               {"client_id", "subject"},
	"ciba_requests":              {"client_id", "subject"},
	"totp_secrets":               {"subject"},
	"passkeys":                   {"subject"},
	"recovery_codes":             {"subject"},
	"email_otps":                 {"subject"},
	"authn_lockouts":             {"subject"},
	"ssf_streams":                {"client_id"},
}

// tableCatalog lists every table in [knownNamingKeys] order.
//
//nolint:gochecknoglobals // documentation table; read-only.
var tableCatalog = []tableInfo{
	{
		"clients", "Clients", "Client registrations and their secret hashes.",
		"Always read. Written by `op.WithStaticClients`, dynamic registration, and your own client management.", "always",
	},
	{
		"authorization_codes", "AuthorizationCodes", "Authorization codes awaiting redemption, with the authentication context they were issued under.",
		"The `authorization_code` grant is enabled.", "grant:authorization_code",
	},
	{
		"refresh_tokens", "RefreshTokens", "Refresh-token rotation chains and the response a retried rotation replays.",
		"Written when the `refresh_token` grant is enabled; read by revocation and introspection in every configuration.", "always:refresh",
	},
	{
		"access_tokens", "AccessTokens", "JTI registry of issued JWT access tokens.",
		"`op.WithAccessTokenRevocationStrategy(op.RevocationStrategyJTIRegistry)`.", "always:jti-registry",
	},
	{
		"opaque_access_tokens", "OpaqueAccessTokens", "Opaque access tokens and the claims introspection returns for them.",
		"An opaque format is configured through `op.WithAccessTokenFormat` or `op.WithAccessTokenFormatPerAudience`.", "always:opaque",
	},
	{
		"grant_revocations", "GrantRevocations", "Grant tombstones that invalidate a revoked grant's JWT access tokens.",
		"The default `RevocationStrategyGrantTombstone`, when a grant or its access tokens are revoked.", "always:tombstone",
	},
	{
		"revoked_jtis", "GrantRevocations", "Individually revoked JWT access-token identifiers.",
		"The default `RevocationStrategyGrantTombstone`, when `/revocation` revokes a JWT access token.", "always:denylist",
	},
	{
		"grants", "Grants", "The consented grant (client, subject, scopes) that codes and refresh tokens hang off.",
		"Any grant other than `client_credentials`.", "always:construction",
	},
	{
		"sessions", "Sessions", "Browser login sessions and their chooser groups.",
		"A browser login runs through `/auth`.", "authorize",
	},
	{
		"par_records", "PushedAuthRequests", "Pushed authorization requests until their `request_uri` is redeemed.",
		"`feature.PAR` is enabled.", "feature:par",
	},
	{
		"interactions", "Interactions", "In-progress login and consent interactions.",
		"A browser login runs through `/auth`.", "authorize",
	},
	{
		"consumed_jtis", "ConsumedJTIs", "Replay markers for request objects, client assertions and DPoP proofs.",
		"A client sends a JAR request object, a `private_key_jwt` assertion, or a DPoP proof.", "always:client-jti",
	},
	{
		"users", "Users", "The adapter's own user records: subject, claims, optional username and password hash.",
		"Only through your own writes, plus the OP's rehash of a legacy password when the adapter's `Users()` is `PrimaryPassword.Store`.", "userstore",
	},
	{
		"initial_access_tokens", "InitialAccessTokens", "Initial access tokens that authorize dynamic client registration.",
		"`op.WithDynamicRegistration`.", "dcr",
	},
	{
		"registration_access_tokens", "RegistrationAccessTokens", "Registration access tokens for RFC 7592 client management.",
		"`op.WithDynamicRegistration`.", "dcr",
	},
	{
		"op_metadata", "Metadata", "OP-internal markers, such as the subject mode the pairwise gate pins.",
		"`op.New` reads and writes it at construction.", "always:construction",
	},
	{
		"device_codes", "DeviceCodes", "RFC 8628 device authorization records.",
		"The `device_code` grant is enabled.", "grant:device_code",
	},
	{
		"ciba_requests", "CIBARequests", "CIBA backchannel authentication requests.",
		"`op.WithCIBA`.", "grant:ciba",
	},
	{
		"totp_secrets", "TOTPs", "Encrypted TOTP secrets.",
		"`Store.TOTPs()` is passed to `op.StepTOTP`.", "factor:totp",
	},
	{
		"passkeys", "Passkeys", "Registered WebAuthn credentials.",
		"`Store.Passkeys()` is passed to `op.PrimaryPasskey` or `op/passkeykit`.", "factor:passkey",
	},
	{
		"recovery_codes", "RecoveryCodes", "Hashed single-use recovery codes.",
		"`Store.RecoveryCodes()` is passed to `op.StepRecoveryCode` or `op/recoverykit`.", "factor:recovery",
	},
	{
		"email_otps", "EmailOTPs", "Pending email one-time codes.",
		"`Store.EmailOTPs()` is passed to `op.StepEmailOTP`.", "factor:email_otp",
	},
	{
		"authn_lockouts", "AuthnLockouts", "Per-subject failure counters of the brute-force gate.",
		"The login flow has a password or second-factor step and `op.WithAuthnLockoutStore` names no other store.", "lockout",
	},
	{
		"ssf_streams", "SSFStreams", "Shared Signals Framework streams, one per receiving client.",
		"`op.WithSharedSignals`.", "ssf",
	},
	{
		"ssf_events", "SSFEvents", "Security Event Tokens queued for delivery to a stream, as unsigned claims.",
		"`op.WithSharedSignals`.", "ssf",
	},
}

// tableColumns names columns added to one table, by WithNaming key.
type tableColumns struct {
	key     string
	columns []string
}

// schemaRelease lists the tables a release created and the columns it
// added to tables that already existed. Every release after v1.0.0 that
// changed the schema has an entry, including releases that changed only
// indexes or collations, and a matching migration file per dialect under
// schema/migrations; [Store.ValidateSchema] names the release when one of
// its columns or tables is missing.
type schemaRelease struct {
	version   string
	migration string // file stem under schema/migrations/<dialect>
	columns   []tableColumns
	tables    []string // WithNaming keys
}

// baselineMigration is the file that creates the v1.0.0 schema; every later
// file is one schemaReleases row.
const baselineMigration = "000001_v1.0.0"

//nolint:gochecknoglobals // schema history; read-only.
var schemaReleases = []schemaRelease{
	{"v1.1.0", "000002_v1.1.0", []tableColumns{
		{"registration_access_tokens", []string{"allowed_scopes"}},
		{"totp_secrets", []string{"row_version"}},
		{"email_otps", []string{"row_version"}},
	}, nil},
	{"v1.2.0", "000003_v1.2.0", nil, nil},
	{"v1.3.0", "000004_v1.3.0", nil, nil},
	{"v1.4.0", "000005_v1.4.0", []tableColumns{
		{"authorization_codes", []string{"auth_time", "acr", "amr", "authorization_details", "claims", "authorization_recorded"}},
		{"refresh_tokens", []string{"claims", "authorization_recorded", "chain_id"}},
		{"opaque_access_tokens", []string{"authorization_details", "claims", "authorization_recorded", "chain_id"}},
		{"grant_revocations", []string{"access_revoked_at"}},
	}, nil},
	{"v1.5.0", "000006_v1.5.0", []tableColumns{
		{"clients", []string{
			"previous_secret_hash", "previous_secret_expires_at",
			"tls_client_auth_subject_dn", "tls_client_auth_san_dns", "tls_client_auth_san_uri",
			"tls_client_auth_san_ip", "tls_client_auth_san_email",
		}},
	}, []string{"ssf_streams", "ssf_events"}},
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

// tableAddedIn returns the release that created the table with the given
// WithNaming key, or "" for a table present since v1.0.0.
func tableAddedIn(key string) string {
	for _, r := range schemaReleases {
		for _, k := range r.tables {
			if k == key {
				return r.version
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
