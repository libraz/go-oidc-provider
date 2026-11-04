package oidcsql

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// maxIdentifierBytes is the longest table or index name the adapter accepts.
const maxIdentifierBytes = 63

// validateIdentifier accepts ASCII letters, ASCII digits (except as the
// first byte), and underscore; up to 63 bytes total. The 63-byte ceiling
// matches PostgreSQL's NAMEDATALEN-1 default and stays inside MySQL's
// 64-byte identifier limit. Anything outside this grammar is rejected
// before the adapter will interpolate the byte sequence into a query.
//
// The validator is the first layer of the SQL-injection defence. It is
// reapplied at query-build time (see [buildQueries]) so a name that
// somehow bypasses [WithNaming] still cannot reach a SQL string.
//
// The implementation walks bytes directly rather than going through a
// regex engine: the grammar is regular and finite, the loop is linear,
// and the package gains nothing from a runtime-compiled pattern.
func validateIdentifier(name string) error {
	if name == "" {
		return errors.New("oidcsql: identifier is empty")
	}
	if len(name) > maxIdentifierBytes {
		return fmt.Errorf("oidcsql: identifier %q exceeds %d bytes", name, maxIdentifierBytes)
	}
	for i := range len(name) {
		b := name[i]
		switch {
		case b >= 'a' && b <= 'z':
		case b >= 'A' && b <= 'Z':
		case b == '_':
		case b >= '0' && b <= '9':
			if i == 0 {
				return fmt.Errorf("oidcsql: identifier %q starts with a digit", name)
			}
		default:
			return fmt.Errorf(
				"oidcsql: identifier %q contains invalid byte 0x%02x at index %d", name, b, i,
			)
		}
	}
	return nil
}

// nameMap holds the resolved logical → physical identifier rewrites
// for every table the adapter touches. The struct is built from a
// caller-supplied [WithNaming] map at construction time; missing
// keys fall back to the canonical defaults. Field names mirror the
// substore record kinds so the rest of the adapter can reference
// table names through this struct without rebuilding the resolution
// logic in every query.
type nameMap struct {
	clients            string
	authCodes          string
	refreshes          string
	accessTokens       string
	opaqueAccessTokens string
	grantTombstones    string
	revokedJTIs        string
	grants             string
	sessions           string
	pars               string
	interactions       string
	jtis               string
	users              string
	iats               string
	rats               string
	metadata           string
	deviceCodes        string
	cibaRequests       string
	totpSecrets        string
	passkeys           string
	recoveryCodes      string
	emailOTPs          string
	authnLockouts      string
	ssfStreams         string
	ssfEvents          string

	// versionTable is the table [Store.Migrate] records its progress in. It
	// is named by the "schema_migrations" [WithNaming] key but is not a
	// table of [knownNamingKeys]: the DDL does not create it and the schema
	// checks do not look for it.
	versionTable string
}

// defaultTablePrefix is the prefix the reference DDL carries on every
// table; [WithTablePrefix] replaces it.
const defaultTablePrefix = "oidc_"

// defaultNames returns the canonical table names, the reference DDL's.
// It is also the source side of every [rewriteSchema] substitution.
func defaultNames() nameMap { return namesWithPrefix(defaultTablePrefix) }

// namesWithPrefix returns the table names with prefix in front of each
// logical name. Embedders that already own a table on one of these names
// rewrite it through [WithNaming] on top of the prefix.
func namesWithPrefix(p string) nameMap {
	return nameMap{
		clients:            p + "clients",
		authCodes:          p + "authorization_codes",
		refreshes:          p + "refresh_tokens",
		accessTokens:       p + "access_tokens",
		opaqueAccessTokens: p + "opaque_access_tokens",
		grantTombstones:    p + "grant_revocations",
		revokedJTIs:        p + "revoked_jtis",
		grants:             p + "grants",
		sessions:           p + "sessions",
		pars:               p + "par_records",
		interactions:       p + "interactions",
		jtis:               p + "consumed_jtis",
		users:              p + "users",
		iats:               p + "initial_access_tokens",
		rats:               p + "registration_access_tokens",
		metadata:           p + "op_metadata",
		deviceCodes:        p + "device_codes",
		cibaRequests:       p + "ciba_requests",
		totpSecrets:        p + "totp_secrets",
		passkeys:           p + "passkeys",
		recoveryCodes:      p + "recovery_codes",
		emailOTPs:          p + "email_otps",
		authnLockouts:      p + "authn_lockouts",
		ssfStreams:         p + "ssf_streams",
		ssfEvents:          p + "ssf_events",
		versionTable:       p + versionTableKey,
	}
}

// validateTablePrefix checks a [WithTablePrefix] value against the
// identifier grammar. The empty prefix is valid.
func validateTablePrefix(prefix string) error {
	if prefix == "" {
		return nil
	}
	if err := validateIdentifier(prefix + "x"); err != nil {
		return fmt.Errorf("oidcsql: invalid WithTablePrefix %q: use ASCII letters, digits and underscore, not starting with a digit: %w", prefix, err)
	}
	return nil
}

// applyOverrides validates each override and rewrites the matching
// field on n. Unknown logical keys cause an error; this catches typos
// at construction time rather than silently ignoring them.
//
//nolint:cyclop // flat switch is irreducibly complex; one arm per nameMap field.
func (n *nameMap) applyOverrides(overrides map[string]string) error {
	for logical, physical := range overrides {
		if err := validateIdentifier(physical); err != nil {
			return err
		}
		switch logical {
		case "clients":
			n.clients = physical
		case "authorization_codes":
			n.authCodes = physical
		case "refresh_tokens":
			n.refreshes = physical
		case "access_tokens":
			n.accessTokens = physical
		case "opaque_access_tokens":
			n.opaqueAccessTokens = physical
		case "grant_revocations":
			n.grantTombstones = physical
		case "revoked_jtis":
			n.revokedJTIs = physical
		case "grants":
			n.grants = physical
		case "sessions":
			n.sessions = physical
		case "par_records":
			n.pars = physical
		case "interactions":
			n.interactions = physical
		case "consumed_jtis":
			n.jtis = physical
		case "users":
			n.users = physical
		case "initial_access_tokens":
			n.iats = physical
		case "registration_access_tokens":
			n.rats = physical
		case "op_metadata":
			n.metadata = physical
		case "device_codes":
			n.deviceCodes = physical
		case "ciba_requests":
			n.cibaRequests = physical
		case "totp_secrets":
			n.totpSecrets = physical
		case "passkeys":
			n.passkeys = physical
		case "recovery_codes":
			n.recoveryCodes = physical
		case "email_otps":
			n.emailOTPs = physical
		case "authn_lockouts":
			n.authnLockouts = physical
		case "ssf_streams":
			n.ssfStreams = physical
		case "ssf_events":
			n.ssfEvents = physical
		case versionTableKey:
			n.versionTable = physical
		default:
			return fmt.Errorf("oidcsql: unknown WithNaming key %q (valid keys: %s, %s)",
				logical, strings.Join(knownNamingKeys, ", "), versionTableKey)
		}
	}
	return n.checkCollisions()
}

// checkCollisions rejects a nameMap whose resolved physical names
// are not pairwise distinct. WithNaming lets an embedder rename any
// subset of tables; without this check, two overrides that resolve to
// the same physical name — or an override that collides with a
// logical name the caller left at its default — would silently
// corrupt both the migration DDL ([rewriteSchema]) and the query
// layer ([buildQueries]): every statement targeting the collided name
// would read and write whichever substore's rows happen to share the
// table, with no construction-time signal that anything is wrong.
//
// [nameMap.all] and [knownNamingKeys] are maintained in the same
// field order, so the index into knownNamingKeys names the logical
// key responsible for each resolved physical name in the error
// message.
func (n nameMap) checkCollisions() error {
	names := append(n.all(), n.versionTable)
	seen := make(map[string]string, len(names))
	for i, name := range names {
		label := versionTableKey
		if i < len(knownNamingKeys) {
			label = logicalKeyAt(i)
		}
		// SQLite and unquoted PostgreSQL identifiers compare case-insensitively.
		name = strings.ToLower(name)
		if prior, ok := seen[name]; ok {
			return fmt.Errorf(
				"oidcsql: WithNaming collision: logical tables %q and %q both resolve to physical name %q",
				prior, label, name,
			)
		}
		seen[name] = label
	}
	return nil
}

// logicalKeyAt returns the [knownNamingKeys] entry at i, or a
// placeholder if the two tables have drifted out of sync (guarded by
// TestNameMapFieldOrderMatchesKnownNamingKeys).
func logicalKeyAt(i int) string {
	if i < 0 || i >= len(knownNamingKeys) {
		return fmt.Sprintf("<index %d>", i)
	}
	return knownNamingKeys[i]
}

// all returns the resolved physical names in a stable order. It is the
// single source of truth for code paths that need to iterate every
// table (Layer 4 re-validation, schema rewriting, audit tests) so a
// new field on [nameMap] cannot be silently missed.
func (n nameMap) all() []string {
	return []string{
		n.clients,
		n.authCodes,
		n.refreshes,
		n.accessTokens,
		n.opaqueAccessTokens,
		n.grantTombstones,
		n.revokedJTIs,
		n.grants,
		n.sessions,
		n.pars,
		n.interactions,
		n.jtis,
		n.users,
		n.iats,
		n.rats,
		n.metadata,
		n.deviceCodes,
		n.cibaRequests,
		n.totpSecrets,
		n.passkeys,
		n.recoveryCodes,
		n.emailOTPs,
		n.authnLockouts,
		n.ssfStreams,
		n.ssfEvents,
	}
}

// validateAll re-runs [validateIdentifier] over every resolved name.
// It is invoked at the entry of [buildQueries] as Layer 4 of the
// SQL-injection defence — even if a future code path constructs a
// nameMap without going through [applyOverrides], the query builder
// will refuse to operate on an unvalidated value.
func (n nameMap) validateAll() error {
	for _, name := range append(n.all(), n.versionTable) {
		if err := validateIdentifier(name); err != nil {
			return err
		}
	}
	return nil
}

//nolint:gochecknoglobals // immutable list used by error messages.
var knownNamingKeys = []string{
	"clients",
	"authorization_codes",
	"refresh_tokens",
	"access_tokens",
	"opaque_access_tokens",
	"grant_revocations",
	"revoked_jtis",
	"grants",
	"sessions",
	"par_records",
	"interactions",
	"consumed_jtis",
	"users",
	"initial_access_tokens",
	"registration_access_tokens",
	"op_metadata",
	"device_codes",
	"ciba_requests",
	"totp_secrets",
	"passkeys",
	"recovery_codes",
	"email_otps",
	"authn_lockouts",
	"ssf_streams",
	"ssf_events",
}

// rewriteSchema swaps every default table name in the embedded DDL
// with the override resolved through nameMap. The adapter exposes the
// rewritten schema via [Store.Schema] so embedders can copy-paste it
// for review, and [Store.Migrations] runs the same rewrite over the
// migration files that [Store.Migrate] applies.
//
// The substitution runs as a SINGLE pass built from an alternation of
// the exact default table names, ordered longest-first, applied with
// [regexp.Regexp.ReplaceAllStringFunc]. Matching the exact names — not
// whole identifier tokens — is required because the DDL embeds a table
// name inside its secondary-index names (e.g.
// "idx_oidc_access_tokens_expires"), and those occurrences must be
// rewritten alongside the CREATE TABLE statement so the schema stays
// internally consistent. A sequence of independent strings.ReplaceAll
// calls is unsafe here: if one override's resolved value contains
// another default name as a substring, a later pass would match inside
// the already-substituted text and corrupt it. The single pass cannot
// exhibit that failure mode because replacement text is never handed
// back through the matcher, and longest-first ordering resolves any
// name that is a substring of another at the same start position.
func rewriteSchema(raw []byte, n nameMap) string {
	defaults := defaultNames()
	if n == defaults {
		return string(raw)
	}
	from, to := defaults.all(), n.all()
	replacements := make(map[string]string, len(from))
	for i, name := range from {
		replacements[name] = to[i]
	}
	names := make([]string, 0, len(replacements))
	for from := range replacements {
		names = append(names, from)
	}
	// Longest-first (ties broken alphabetically for a deterministic
	// pattern) so a name that is a substring of another is offered to
	// the alternation first.
	sort.Slice(names, func(i, j int) bool {
		if len(names[i]) != len(names[j]) {
			return len(names[i]) > len(names[j])
		}
		return names[i] < names[j]
	})
	quoted := make([]string, len(names))
	for i, name := range names {
		quoted[i] = regexp.QuoteMeta(name)
	}
	pattern := regexp.MustCompile(strings.Join(quoted, "|"))
	return pattern.ReplaceAllStringFunc(string(raw), func(match string) string {
		if to, ok := replacements[match]; ok {
			return to
		}
		return match
	})
}
