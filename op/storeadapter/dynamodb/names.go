package oidcdynamo

import (
	"errors"
	"fmt"
	"strings"
)

// validateTableName accepts the grammar DynamoDB documents for table
// names: 3–255 characters drawn from letters, digits, underscore,
// hyphen, and period. It runs before any name reaches a request so a
// caller-supplied override cannot produce a request against an
// unintended table.
func validateTableName(name string) error {
	if name == "" {
		return errors.New("oidcdynamo: table name is empty")
	}
	if len(name) < 3 || len(name) > 255 {
		return fmt.Errorf("oidcdynamo: table name %q must be 3-255 characters", name)
	}
	for i := range len(name) {
		b := name[i]
		switch {
		case b >= 'a' && b <= 'z':
		case b >= 'A' && b <= 'Z':
		case b >= '0' && b <= '9':
		case b == '_' || b == '-' || b == '.':
		default:
			return fmt.Errorf(
				"oidcdynamo: table name %q contains invalid byte 0x%02x at index %d", name, b, i)
		}
	}
	return nil
}

// nameMap holds the resolved physical table name for every substore.
// Field order matches [knownNamingKeys] so a collision error can name
// the logical key responsible.
type nameMap struct {
	clients            string
	authCodes          string
	refreshes          string
	accessTokens       string
	opaqueAccessTokens string
	grantTombstones    string
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
}

//nolint:gochecknoglobals // immutable list used by error messages and collision reporting.
var knownNamingKeys = []string{
	"clients",
	"authorization_codes",
	"refresh_tokens",
	"access_tokens",
	"opaque_access_tokens",
	"grant_revocations",
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
}

// defaultNames returns the canonical table names under prefix.
func defaultNames(prefix string) nameMap {
	return nameMap{
		clients:            prefix + "clients",
		authCodes:          prefix + "authorization_codes",
		refreshes:          prefix + "refresh_tokens",
		accessTokens:       prefix + "access_tokens",
		opaqueAccessTokens: prefix + "opaque_access_tokens",
		grantTombstones:    prefix + "grant_revocations",
		grants:             prefix + "grants",
		sessions:           prefix + "sessions",
		pars:               prefix + "par_records",
		interactions:       prefix + "interactions",
		jtis:               prefix + "consumed_jtis",
		users:              prefix + "users",
		iats:               prefix + "initial_access_tokens",
		rats:               prefix + "registration_access_tokens",
		metadata:           prefix + "op_metadata",
		deviceCodes:        prefix + "device_codes",
		cibaRequests:       prefix + "ciba_requests",
		totpSecrets:        prefix + "totp_secrets",
		passkeys:           prefix + "passkeys",
		recoveryCodes:      prefix + "recovery_codes",
		emailOTPs:          prefix + "email_otps",
		authnLockouts:      prefix + "authn_lockouts",
	}
}

// all returns the resolved names in [knownNamingKeys] order. It is the
// single source of truth for code paths that iterate every table, so a
// new field cannot be silently missed by the collision check.
func (n nameMap) all() []string {
	return []string{
		n.clients,
		n.authCodes,
		n.refreshes,
		n.accessTokens,
		n.opaqueAccessTokens,
		n.grantTombstones,
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
	}
}

//nolint:cyclop // flat switch; one arm per nameMap field.
func (n *nameMap) applyOverrides(overrides map[string]string) error {
	for logical, physical := range overrides {
		if err := validateTableName(physical); err != nil {
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
		default:
			return fmt.Errorf("oidcdynamo: unknown WithNaming key %q (valid keys: %s)",
				logical, strings.Join(knownNamingKeys, ", "))
		}
	}
	return n.checkCollisions()
}

// checkCollisions rejects a nameMap whose resolved names are not
// pairwise distinct. Two substores sharing a table would read and write
// each other's items with no construction-time signal that anything is
// wrong.
func (n nameMap) checkCollisions() error {
	names := n.all()
	seen := make(map[string]string, len(names))
	for i, name := range names {
		label := logicalKeyAt(i)
		if prior, ok := seen[name]; ok {
			return fmt.Errorf(
				"oidcdynamo: WithNaming collision: logical tables %q and %q both resolve to physical name %q",
				prior, label, name)
		}
		seen[name] = label
	}
	return nil
}

func logicalKeyAt(i int) string {
	if i < 0 || i >= len(knownNamingKeys) {
		return fmt.Sprintf("<index %d>", i)
	}
	return knownNamingKeys[i]
}

// validateAll re-runs [validateTableName] over every resolved name at
// construction time, so a nameMap built without going through
// [WithNaming] still cannot reach a request.
func (n nameMap) validateAll() error {
	for _, name := range n.all() {
		if err := validateTableName(name); err != nil {
			return err
		}
	}
	return nil
}
