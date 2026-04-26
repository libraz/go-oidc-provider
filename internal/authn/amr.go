package authn

// registeredAMR is the set of RFC 8176 §2 registered amr values the
// orchestrator accepts from an [op.Authenticator.AMR] return. Any value
// outside the set is dropped (warning audit log) so a custom
// authenticator cannot inject a foreign token into the id_token amr
// claim. The set is closed: new values land here only when the IANA
// registry adds them.
//
// See docs/plans/002-product-design.md §E.2.2 for the orchestrator
// contract and §E.6.1 for the "no acr/amr from request parameters"
// invariant the registry filter exists to defend.
//
//nolint:gochecknoglobals // closed lookup table; the file declares no init() on it.
var registeredAMR = map[string]struct{}{
	"face":   {},
	"fpt":    {},
	"geo":    {},
	"hwk":    {},
	"iris":   {},
	"kba":    {},
	"mca":    {},
	"mfa":    {},
	"otp":    {},
	"pin":    {},
	"pop":    {},
	"pwd":    {},
	"rba":    {},
	"retina": {},
	"sc":     {},
	"sms":    {},
	"swk":    {},
	"tel":    {},
	"user":   {},
	"vbm":    {},
	"wia":    {},
}

// IsRegisteredAMR reports whether v is one of the RFC 8176 §2
// registered amr values. The orchestrator uses it to filter
// [op.Authenticator.AMR] return values before they reach the session
// amr_history; consult the function from a per-method package only
// when the package needs to mirror the orchestrator's drop policy
// locally (e.g., a verifier that aggregates its own audit record).
func IsRegisteredAMR(v string) bool {
	if v == "" {
		return false
	}
	_, ok := registeredAMR[v]
	return ok
}
