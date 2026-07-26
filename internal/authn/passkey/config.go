package passkey

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/libraz/go-oidc-provider/internal/timex"
)

// defaultSessionTTL is the lifetime stamped on every [Session] when the
// caller does not override it via [Config.SessionTTL]. Five minutes
// matches the underlying library default and is long enough that a
// human-paced registration flow (read prompt, touch authenticator,
// confirm) finishes comfortably while keeping the replay window narrow.
const defaultSessionTTL = 5 * time.Minute

// ErrInvalidConfig is returned by [New] when the supplied [Config] is
// missing required fields or carries conflicting values. The error is
// intentionally surfaced at startup time so a misconfigured deployment
// fails before the first registration attempt.
var ErrInvalidConfig = errors.New("passkey: invalid configuration")

// Config carries the Relying Party identity bound into every
// registration and assertion ceremony. The struct mirrors the small
// subset of [webauthn.Config] the library actually exposes today;
// fields that v1.0 deliberately fixes (AttestationPreference,
// AuthenticatorSelection, EncodeUserIDAsString) are NOT surfaced. See
// the package godoc for the rationale.
type Config struct {
	// RPID is the Relying Party Identifier — typically the OP's
	// effective domain (for example "id.example.com" but never a URL
	// or port). It is bound into the credential at registration time
	// and matched at assertion time; changing it invalidates every
	// previously registered credential. Required.
	RPID string

	// RPDisplayName is the human-readable label shown by the user
	// agent during the ceremony (for example "Example Identity"). It
	// has no security effect but every spec-compliant authenticator
	// requires it. Required.
	RPDisplayName string

	// RPOrigins is the list of fully-qualified origins permitted to
	// initiate ceremonies (for example "https://id.example.com").
	// Cross-origin iframe flows MAY require additional entries;
	// embedders SHOULD enumerate every public-facing origin they
	// terminate TLS on. Required to be non-empty.
	RPOrigins []string

	// SessionTTL is the absolute lifetime stamped on the [Session]
	// returned from BeginRegistration / BeginLogin. A zero value
	// falls back to [defaultSessionTTL] (five minutes). Embedders
	// MAY shorten the value to tighten the replay window but SHOULD
	// NOT lengthen it past a few minutes: the cookie that ferries the
	// session is encrypted, but a longer TTL widens the window in
	// which a stolen browser could complete a hijacked ceremony.
	SessionTTL time.Duration

	// AttestationPreference is the WebAuthn conveyance preference
	// requested at registration time. Empty falls back to
	// [protocol.PreferNoAttestation] ("none"); embedders that need
	// to verify the authenticator's AAGUID against [AAGUIDAllowlist]
	// MUST set this to [protocol.PreferDirectAttestation] ("direct")
	// so the user agent forwards the attestation statement.
	//
	// v1.0 supports "none" and "direct" only; "indirect" /
	// "enterprise" return [ErrInvalidConfig] at construction time.
	AttestationPreference protocol.ConveyancePreference

	// AAGUIDAllowlist is the optional set of authenticator-model
	// identifiers (16-byte AAGUIDs encoded as canonical UUID
	// strings, e.g. "fbfc3007-154e-4ecc-8c0b-6e020557d7bd") the
	// registration ceremony will accept. An empty / nil slice
	// disables the check (every AAGUID is allowed); a non-empty
	// slice rejects any registration whose authenticator is not in
	// the set.
	//
	// A non-empty allowlist requires [AttestationPreference] to be
	// [protocol.PreferDirectAttestation]; [New] refuses any other
	// pairing. [Verifier.FinishRegistration] additionally refuses a
	// registration whose attestation does not vouch for the model
	// (self attestation or none), because the allowlist would
	// otherwise be comparing an identifier the caller chose.
	//
	// AAGUID strings are case-insensitive and tolerate canonical
	// UUID formatting only ("xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx").
	// Construction returns [ErrInvalidConfig] for any malformed
	// entry so a typo cannot silently widen the policy.
	AAGUIDAllowlist []string

	// AAGUIDReCheckOnAssertion enables the defence: when true the
	// verifier re-checks the matched credential's AAGUID against the
	// configured [AAGUIDAllowlist] at assertion time so an embedder that
	// narrows the allowlist after registration can revoke credentials
	// whose authenticator model has fallen out of policy. The default
	// (false) preserves the v0.x behaviour where AAGUID was enforced
	// only at registration; embedders that want defence-in-depth flip
	// the bit on. The allowlist itself is shared with the registration
	// check; an empty allowlist short-circuits the assertion-time check
	// (every AAGUID is accepted, mirroring the registration behaviour).
	AAGUIDReCheckOnAssertion bool
}

// Verifier is the package's high-level façade. Construct one via [New]
// and reuse it for the lifetime of the process; the underlying
// [webauthn.WebAuthn] is built once and shared across goroutines.
//
// The zero value is not usable: callers MUST go through [New] so the
// configuration is validated up front.
//
// Verifier is immutable after construction and safe for concurrent use.
type Verifier struct {
	// Clock supplies the wall-clock reading used to stamp Session
	// expiry and to validate that a presented Session has not yet
	// expired. A nil value falls back to [timex.SystemClock]. Tests
	// inject a deterministic [timex.ClockFunc] so the expiry stamp is
	// reproducible.
	Clock timex.Clock

	// SessionTTL is the absolute Session lifetime. It is set from
	// [Config.SessionTTL] in [New]; callers SHOULD treat the field as
	// read-only.
	SessionTTL time.Duration

	// wa is the underlying webauthn instance, built once in [New].
	wa *webauthn.WebAuthn

	// aaguidAllowlist is the canonicalised AAGUID set the verifier
	// enforces at FinishRegistration. The map keys are 16-byte
	// AAGUID strings (canonical lowercase UUID form) so the lookup
	// is O(1). nil means "no allowlist configured" — every AAGUID
	// is accepted.
	aaguidAllowlist map[string]struct{}

	// aaguidReCheckOnAssertion mirrors [Config.AAGUIDReCheckOnAssertion].
	// When true the verifier re-checks the matched credential's
	// AAGUID against [aaguidAllowlist] at FinishLogin time.
	aaguidReCheckOnAssertion bool
}

// New constructs a [Verifier] from cfg. It validates the required
// fields, builds the underlying [webauthn.WebAuthn], and wires the
// fixed-policy choices (AttestationPreference = none, defaulted
// AuthenticatorSelection) the package documents.
//
// The function returns [ErrInvalidConfig] (wrapped via [fmt.Errorf]
// with %w) when RPID or RPDisplayName is empty or RPOrigins is empty.
// Validation is intentionally surfaced as a startup error rather than a
// per-request one: an OP that boots without a valid passkey config
// should refuse to start, not silently downgrade to "no passkey".
func New(cfg Config) (*Verifier, error) {
	if cfg.RPID == "" {
		return nil, fmt.Errorf("%w: RPID is required", ErrInvalidConfig)
	}
	if cfg.RPDisplayName == "" {
		return nil, fmt.Errorf("%w: RPDisplayName is required", ErrInvalidConfig)
	}
	if len(cfg.RPOrigins) == 0 {
		return nil, fmt.Errorf("%w: at least one RPOrigin is required", ErrInvalidConfig)
	}
	if err := validateOrigins(cfg.RPID, cfg.RPOrigins); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	pref, err := resolveAttestationPreference(cfg.AttestationPreference)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	allow, err := normaliseAAGUIDAllowlist(cfg.AAGUIDAllowlist)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	// An AAGUID allowlist only means anything when the attestation
	// statement vouches for the AAGUID. Under "none" conveyance the
	// value is self-asserted by whatever produced the response, so the
	// allowlist would decide policy on an attacker-chosen string. The
	// pairing is enforced here rather than documented as a caller
	// obligation: a deployment that gets it wrong reads as "only
	// approved authenticator models may register" while accepting any.
	if len(allow) > 0 && pref != protocol.PreferDirectAttestation {
		return nil, fmt.Errorf(
			"%w: AAGUIDAllowlist requires AttestationPreference %q (got %q); "+
				"under any other conveyance the AAGUID is self-asserted and the allowlist cannot be enforced",
			ErrInvalidConfig, protocol.PreferDirectAttestation, pref)
	}
	ttl := cfg.SessionTTL
	if ttl <= 0 {
		ttl = defaultSessionTTL
	}

	waCfg := &webauthn.Config{
		RPID:                  cfg.RPID,
		RPDisplayName:         cfg.RPDisplayName,
		RPOrigins:             append([]string(nil), cfg.RPOrigins...),
		AttestationPreference: pref,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementPreferred,
			UserVerification: protocol.VerificationPreferred,
		},
		// EncodeUserIDAsString is left at the library default
		// (false). The user handle round-trips through the JSON as a
		// base64url-encoded string per the W3C WebAuthn convention
		// for BufferSource fields; SPAs decode it through the
		// standard PublicKeyCredential.parseCreationOptionsFromJSON
		// helpers. Setting the flag would skip the encoding and
		// produce a raw UTF-8 string that older browser libraries
		// would mishandle.
		// Timeouts.Enforce is hard-coded to false: the library
		// drives the freshness check through its own clock-aware
		// [Verifier.checkSessionFresh] / [Session.Expires] path and
		// then zeroes Expires before handing the decoded session to
		// the upstream library. Letting go-webauthn enforce its own
		// timeout under that arrangement combines two clocks (the
		// upstream wall-clock vs. our injected [timex.Clock]) and a
		// known upstream regression (Enforce=true with Expires=0
		// surfaces an immediate-fail path on certain library versions).
		// Leaving the timeout values populated still lets the user
		// agent surface a sensible "timed out" UX while the
		// authoritative freshness gate stays under the OP's clock.
		Timeouts: webauthn.TimeoutsConfig{
			Registration: webauthn.TimeoutConfig{
				Enforce:    false,
				Timeout:    ttl,
				TimeoutUVD: ttl,
			},
			Login: webauthn.TimeoutConfig{
				Enforce:    false,
				Timeout:    ttl,
				TimeoutUVD: ttl,
			},
		},
	}

	wa, err := webauthn.New(waCfg)
	if err != nil {
		return nil, fmt.Errorf("%w: build webauthn: %w", ErrInvalidConfig, err)
	}
	return &Verifier{
		SessionTTL:               ttl,
		wa:                       wa,
		aaguidAllowlist:          allow,
		aaguidReCheckOnAssertion: cfg.AAGUIDReCheckOnAssertion,
	}, nil
}

// clock returns the verifier's [timex.Clock], defaulting to
// [timex.SystemClock] when the field is nil.
func (v *Verifier) clock() timex.Clock {
	if v.Clock == nil {
		return timex.SystemClock
	}
	return v.Clock
}

// validateOrigins enforces the WebAuthn L3 §13.4.6 binding between
// RPID and the registrable suffix of every accepted origin. The check
// is intentionally strict: a misconfigured origin (a different
// registrable domain, a non-https scheme outside localhost) is the
// kind of mistake that silently widens the credential's redemption
// surface, and surfacing it at New keeps the deployment from booting
// into a broken posture.
//
// Rules:
//   - Each origin MUST parse as an absolute URL with a non-empty Host.
//   - Scheme MUST be "https"; the only allowed exception is "http"
//     when the host is "localhost" or "127.0.0.1" (or an IPv6
//     loopback). Browsers grant the same exception so the WebAuthn
//     ceremony works on a developer's machine without TLS.
//   - The host (excluding port) MUST equal RPID OR end with
//     "."+RPID. The dot-prefixed suffix check prevents a confusing
//     match where RPID="example.com" and origin host="badexample.com"
//     happen to share the literal suffix.
//
// Errors flow through [ErrInvalidConfig] in the caller.
func validateOrigins(rpID string, origins []string) error {
	rp := strings.ToLower(rpID)
	for _, raw := range origins {
		u, err := url.Parse(raw)
		if err != nil {
			return fmt.Errorf("RPOrigin %q: parse: %w", raw, err)
		}
		if u.Host == "" {
			return fmt.Errorf("RPOrigin %q: host is empty", raw)
		}
		scheme := strings.ToLower(u.Scheme)
		host := strings.ToLower(u.Hostname())
		switch scheme {
		case "https":
			// allowed
		case "http":
			if !isLoopbackHost(host) {
				return fmt.Errorf("RPOrigin %q: scheme http is only permitted for loopback hosts", raw)
			}
		default:
			return fmt.Errorf("RPOrigin %q: scheme must be https (or http for loopback)", raw)
		}
		if isLoopbackHost(host) {
			// Loopback origins do not need to match RPID — the
			// browser treats them as same-origin to whatever RPID
			// the developer is testing against.
			continue
		}
		if host != rp && !strings.HasSuffix(host, "."+rp) {
			return fmt.Errorf("RPOrigin %q: host %q is not a registrable suffix of RPID %q", raw, host, rpID)
		}
	}
	return nil
}

// isLoopbackHost reports whether host is one of the textual loopback
// identifiers browsers grant the http-without-TLS exception. The list
// is closed: "localhost" (the canonical name), "127.0.0.1" (IPv4
// loopback), and "[::1]"/"::1" (IPv6 loopback). Anything else returns
// false so a typo such as "127.0.0.2" is rejected.
func isLoopbackHost(host string) bool {
	switch host {
	case "localhost", "127.0.0.1", "::1":
		return true
	default:
		return false
	}
}

// resolveAttestationPreference normalises the [Config.AttestationPreference]
// value into the upstream library's enum form. Empty falls back to
// [protocol.PreferNoAttestation]; v1.0 supports "none" and "direct"
// only — "indirect" / "enterprise" return an error so an embedder
// cannot accidentally request a policy the verifier does not enforce.
func resolveAttestationPreference(p protocol.ConveyancePreference) (protocol.ConveyancePreference, error) {
	switch p {
	case "":
		return protocol.PreferNoAttestation, nil
	case protocol.PreferNoAttestation, protocol.PreferDirectAttestation:
		return p, nil
	default:
		return "", fmt.Errorf("AttestationPreference %q is not supported (use \"none\" or \"direct\")", p)
	}
}

// normaliseAAGUIDAllowlist parses the caller-supplied list of UUID
// strings into the canonical map representation [Verifier] consumes.
// Empty input returns nil to signal "no allowlist configured"; any
// malformed entry returns an error so a typo cannot silently widen
// the policy. The function is case-insensitive: the canonical form
// is the lowercase UUID string with the standard hyphen layout.
func normaliseAAGUIDAllowlist(raw []string) (map[string]struct{}, error) {
	if len(raw) == 0 {
		// Returning (nil, nil) is the documented "no allowlist
		// configured" signal; the caller (Verifier.New) treats nil
		// as "every AAGUID accepted". A typed sentinel would force
		// a less direct API.
		return nil, nil //nolint:nilnil // documented "no allowlist configured" signal; nil map + nil error is the API contract.
	}
	out := make(map[string]struct{}, len(raw))
	for _, s := range raw {
		canonical := strings.ToLower(strings.TrimSpace(s))
		if !isCanonicalUUID(canonical) {
			return nil, fmt.Errorf("AAGUIDAllowlist entry %q is not a canonical UUID", s)
		}
		out[canonical] = struct{}{}
	}
	return out, nil
}

// isCanonicalUUID reports whether s matches the UUID textual form
// xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx with lowercase hex characters.
// We avoid pulling github.com/google/uuid (already an indirect
// dependency) to keep the passkey package's import surface minimal;
// the regex-equivalent check below is faster anyway.
func isCanonicalUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !isHexLower(c) {
				return false
			}
		}
	}
	return true
}

func isHexLower(c rune) bool {
	switch {
	case c >= '0' && c <= '9':
		return true
	case c >= 'a' && c <= 'f':
		return true
	default:
		return false
	}
}

// AAGUIDAllowed reports whether the supplied 16-byte AAGUID is
// permitted under the verifier's configured allowlist. Returns true
// when no allowlist is configured (empty / nil [Config.AAGUIDAllowlist]).
// AAGUID values shorter than 16 bytes return false unconditionally;
// production authenticators always emit a full 16-byte identifier.
func (v *Verifier) AAGUIDAllowed(aaguid []byte) bool {
	if len(v.aaguidAllowlist) == 0 {
		return true
	}
	if len(aaguid) != 16 {
		return false
	}
	canonical := formatAAGUID(aaguid)
	_, ok := v.aaguidAllowlist[canonical]
	return ok
}

// formatAAGUID renders a 16-byte AAGUID as the canonical lowercase
// UUID string. Inlined rather than depending on github.com/google/uuid
// to keep the package's import surface narrow.
func formatAAGUID(b []byte) string {
	const hex = "0123456789abcdef"
	if len(b) != 16 {
		return ""
	}
	out := make([]byte, 36)
	for i, j := 0, 0; i < 16; i++ {
		switch j {
		case 8, 13, 18, 23:
			out[j] = '-'
			j++
		}
		out[j] = hex[b[i]>>4]
		out[j+1] = hex[b[i]&0x0f]
		j += 2
	}
	return string(out)
}
