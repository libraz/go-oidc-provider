package oidcsql

import (
	"errors"
	"fmt"
	"strings"
)

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
	if len(name) > 63 {
		return fmt.Errorf("oidcsql: identifier %q exceeds 63 bytes", name)
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
				"oidcsql: identifier %q contains invalid byte 0x%02x at index %d", name, b, i)
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
	grants             string
	sessions           string
	pars               string
	interactions       string
	jtis               string
	users              string
	iats               string
	rats               string
}

// defaultNames returns the canonical table names. Embedders that
// already own a table on one of these names rewrite it through
// [WithNaming]; everyone else keeps the defaults.
//
//nolint:gosec // G101 false positive: the values are SQL table names, not credentials.
func defaultNames() nameMap {
	return nameMap{
		clients:            "oidc_clients",
		authCodes:          "oidc_authorization_codes",
		refreshes:          "oidc_refresh_tokens",
		accessTokens:       "oidc_access_tokens",
		opaqueAccessTokens: "oidc_opaque_access_tokens",
		grants:             "oidc_grants",
		sessions:           "oidc_sessions",
		pars:               "oidc_par_records",
		interactions:       "oidc_interactions",
		jtis:               "oidc_consumed_jtis",
		users:              "oidc_users",
		iats:               "oidc_initial_access_tokens",
		rats:               "oidc_registration_access_tokens",
	}
}

// applyOverrides validates each override and rewrites the matching
// field on n. Unknown logical keys cause an error; this catches typos
// at construction time rather than silently ignoring them.
//
//nolint:cyclop // 12-arm switch is irreducibly complex; one arm per nameMap field.
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
		default:
			return fmt.Errorf("oidcsql: unknown WithNaming key %q (valid keys: %s)",
				logical, strings.Join(knownNamingKeys, ", "))
		}
	}
	return nil
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
		n.grants,
		n.sessions,
		n.pars,
		n.interactions,
		n.jtis,
		n.users,
		n.iats,
		n.rats,
	}
}

// validateAll re-runs [validateIdentifier] over every resolved name.
// It is invoked at the entry of [buildQueries] as Layer 4 of the
// SQL-injection defence — even if a future code path constructs a
// nameMap without going through [applyOverrides], the query builder
// will refuse to operate on an unvalidated value.
func (n nameMap) validateAll() error {
	for _, name := range n.all() {
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
	"grants",
	"sessions",
	"par_records",
	"interactions",
	"consumed_jtis",
	"users",
	"initial_access_tokens",
	"registration_access_tokens",
}

// rewriteSchema swaps every default table name in the embedded DDL
// with the override resolved through nameMap. The adapter exposes the
// rewritten schema via [Store.Schema] so embedders can copy-paste it
// into their migration tooling; the in-process [Store.Migrate]
// helper drives this same string.
func rewriteSchema(raw []byte, n nameMap) string {
	src := string(raw)
	defaults := defaultNames()
	pairs := []struct {
		from, to string
	}{
		{defaults.clients, n.clients},
		{defaults.authCodes, n.authCodes},
		{defaults.refreshes, n.refreshes},
		{defaults.accessTokens, n.accessTokens},
		{defaults.opaqueAccessTokens, n.opaqueAccessTokens},
		{defaults.grants, n.grants},
		{defaults.sessions, n.sessions},
		{defaults.pars, n.pars},
		{defaults.interactions, n.interactions},
		{defaults.jtis, n.jtis},
		{defaults.users, n.users},
		{defaults.iats, n.iats},
		{defaults.rats, n.rats},
	}
	for _, p := range pairs {
		if p.from == p.to {
			continue
		}
		src = strings.ReplaceAll(src, p.from, p.to)
	}
	return src
}
