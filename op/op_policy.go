package op

import (
	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/jose"
	"github.com/libraz/go-oidc-provider/op/profile"
)

// anyProfile reports whether pred holds for at least one active
// [profile.Profile]. Every "the active set mandates X" gate resolves
// through it, so a disjunctive set ("FAPI 2.0 Baseline OR something
// looser") answers true as soon as one profile does.
func (c *config) anyProfile(pred func(profile.Profile) bool) bool {
	for _, p := range c.profiles {
		if pred(p) {
			return true
		}
	}
	return false
}

// requireSenderConstrainedTokens reports whether the active
// [profile.Profile] set forbids the issuance of bearer access
// tokens. FAPI 2.0 §3.1.4 imposes the mandate on the FAPI 2.0
// family, and FAPI-CIBA inherits it verbatim (FAPI-CIBA-ID1 §5);
// the build-time profile validator already requires either DPoP or
// mTLS feature to be enabled when one of those profiles is active,
// so the runtime path returning true here means "an /token (or
// /bc-authorize) request must present a proof or a cert".
func (c *config) requireSenderConstrainedTokens() bool {
	return c.anyProfile(profile.RequiresSenderConstrainedTokens)
}

// requirePKCE reports whether the active [profile.Profile] set
// mandates that every authorization-code request carry a
// code_challenge. The library's overall posture is OAuth 2.1 — PKCE
// is good practice on every flow — but the OpenID Connect Basic
// certification profile drives the OP without PKCE because OIDC
// Core 1.0 predates RFC 7636. Treating PKCE as profile-conditional
// resolves the conflict: vanilla deployments accept the spec-
// compliant non-PKCE path, while every FAPI 2.0 deployment keeps
// the stronger MUST the profile mandates.
//
// Multiple profiles MAY be active simultaneously; the helper
// returns true on the first profile that requires PKCE so a
// disjunctive set ("FAPI 2.0 Baseline OR something looser") still
// resolves to "PKCE required".
func (c *config) requirePKCE() bool {
	return c.anyProfile(profile.RequiresPKCE)
}

// requireNonce reports whether the active [profile.Profile] set
// mandates that every authorization request carry a nonce. OIDC
// Core 1.0 makes nonce OPTIONAL for code-flow; no shipping profile
// currently elevates this to a strict MUST (FAPI 2.0 satisfies its
// replay-mitigation rule via [config.requireStateOrNonce] instead).
// The disjunctive resolution mirrors [config.requirePKCE] so
// embedders that wire a custom profile keep the same surface.
func (c *config) requireNonce() bool {
	return c.anyProfile(profile.RequiresNonce)
}

// requireStateOrNonce reports whether the active [profile.Profile]
// set mandates that every authorization request carry at least one
// of state / nonce. FAPI 2.0 §5.3.2.1.1 is the canonical source.
// The disjunctive resolution mirrors [config.requirePKCE].
func (c *config) requireStateOrNonce() bool {
	return c.anyProfile(profile.RequiresStateOrNonce)
}

// requirePAR reports whether the active [profile.Profile] set
// mandates that every /authorize request reach the OP via a PAR
// request_uri. FAPI 2.0 §5.3.1 requires PAR; vanilla OIDC Core does
// not. The disjunctive resolution mirrors [config.requirePKCE].
func (c *config) requirePAR() bool {
	return c.anyProfile(profile.RequiresPAR)
}

// requireSignedRequestObject reports whether the active
// [profile.Profile] set mandates that every /authorize and /par
// request carry a signed JAR request object. FAPI 2.0 Message
// Signing §5.6 (the "signed_non_repudiation" request method) is
// the only profile today that imposes this; FAPI 2.0 Baseline
// permits plain form requests. The build-time profile validator
// requires [feature.JAR] to be enabled when
// [profile.FAPI2MessageSigning] is active, so the runtime path
// returning true here means "a JAR verifier is guaranteed to be
// wired".
func (c *config) requireSignedRequestObject() bool {
	return c.anyProfile(profile.RequiresSignedRequestObject)
}

// requireSignedBackchannelRequest reports whether the active
// [profile.Profile] set mandates that every /bc-authorize request
// carry a signed JAR request object. FAPI-CIBA-ID1 §5.2.2 ("the
// authentication request MUST be a signed authentication request")
// is the canonical source. The build-time profile validator
// requires [feature.JAR] to be enabled when [profile.FAPICIBA] is
// active, so the runtime path returning true here means "a JAR
// verifier is guaranteed to be wired" at /bc-authorize. The
// helper mirrors the disjunctive shape of [config.requirePKCE]:
// any one active profile that mandates signed backchannel
// requests resolves the answer to true.
func (c *config) requireSignedBackchannelRequest() bool {
	return c.anyProfile(profile.RequiresSignedBackchannelRequest)
}

// fapiCIBAProfileActive reports whether [profile.FAPICIBA] is in the
// active profile set. The /bc-authorize handler consults the flag to
// flip the requested_expiry gate from the legacy "clamp silently"
// posture to the FAPI-CIBA-ID1 §5 / FAPI 2.0 §3.1.9 hard-reject
// posture (any value above ten minutes surfaces as invalid_request
// rather than being clamped down without notice). The helper mirrors
// the disjunctive shape of [config.requirePKCE]; the inner switch
// names every other profile so an exhaustive linter flags a future
// addition that needs to revisit the FAPI-CIBA distinction.
func (c *config) fapiCIBAProfileActive() bool {
	return c.anyProfile(func(p profile.Profile) bool { return p == profile.FAPICIBA })
}

// requireJARMResponseMode reports whether the active
// [profile.Profile] set mandates that every /authorize response be
// JARM-wrapped. FAPI 2.0 Message Signing §5.5 is the only profile
// today that imposes this; FAPI 2.0 Baseline leaves response_mode
// to the client and does not require response signing. The
// build-time profile validator already requires [feature.JARM] to
// be enabled when [profile.FAPI2MessageSigning] is active, so the
// runtime path returning true here means "the JARM signer is
// guaranteed to be wired".
func (c *config) requireJARMResponseMode() bool {
	return c.anyProfile(profile.RequiresJARMResponseMode)
}

// requireSignedIntrospection reports whether the active
// [profile.Profile] set forces every successful /introspect response
// onto the RFC 9701 JWT envelope. FAPI 2.0 Message Signing §5 is the
// only profile today that imposes this; FAPI 2.0 Baseline leaves
// introspection format negotiation to RFC 9701 §5 (client metadata
// plus Accept). The signing key the handler uses is the OP active key,
// which op.New requires unconditionally — so true here means a
// non-nil signer is guaranteed at request time.
func (c *config) requireSignedIntrospection() bool {
	return c.anyProfile(profile.RequiresSignedIntrospection)
}

// clientSecretVerifier returns the [clientauth.SecretVerifier] every
// client-authenticating endpoint installs. Nil means "the endpoint's
// own default", which is the Argon2id verifier; that is the value
// returned unless [WithHighEntropyClientSecrets] is set.
//
// The verifier is the single place the two linked costs are decided.
// It answers both "what does checking a secret cost" and, through
// [clientauth.DummyVerifier], "what does a rejection cost" — and those
// have to agree, so they are not separate knobs. Returning one object
// from one place is what keeps a future endpoint from wiring half the
// pair.
func (c *config) clientSecretVerifier() clientauth.SecretVerifier { //nolint:ireturn // the Deps field is the interface, and a nil means "endpoint default".
	if !c.highEntropyClientSecrets {
		return nil
	}
	return clientauth.HighEntropy{}
}

// allowedClientAuthMethods returns the [clientauth.Method] subset the
// active [profile.Profile] set imposes on every client-authenticating
// endpoint and on the clients static seeding and dynamic registration
// may persist, or nil when no profile constrains client authentication.
//
// Profile values that name authentication methods outside the
// [clientauth] enum (tls_client_auth, self_signed_tls_client_auth)
// do not appear in the returned slice because they are handled
// outside the package; the FAPI 2.0 §3.1.3 enforcement ladder for
// those methods lives in internal/mtls.
func (c *config) allowedClientAuthMethods() []clientauth.Method {
	allowedNames := c.profileAllowedAuthMethodNames()
	if allowedNames == nil {
		return nil
	}
	out := make([]clientauth.Method, 0, len(allowedNames))
	for _, name := range allowedNames {
		switch clientauth.Method(name) {
		case clientauth.MethodNone, clientauth.MethodSecretBasic,
			clientauth.MethodSecretPost, clientauth.MethodPrivateKeyJWT:
			out = append(out, clientauth.Method(name))
		}
	}
	return out
}

// profileAllowedAuthMethodNames returns the intersection of every
// active [profile.Profile]'s [profile.AllowedClientAuthMethods] as
// raw method names, suitable for [discovery.Input]. Returns nil
// when no profile constrains client authentication.
//
// When multiple profiles are active the result is the intersection
// of every profile's allowed list — the most restrictive policy
// wins, matching the "stricter MAY override looser" posture used
// elsewhere in the configuration. The returned list excludes the mTLS
// methods (tls_client_auth / self_signed_tls_client_auth): mTLS client
// authentication is tracked as v1.x work, the runtime client-auth
// verifier does not negotiate it, and discovery must not advertise — nor
// the static-client gate admit — a method the runtime cannot enforce.
// The exclusion is applied here so every consumer of this list inherits
// it, independent of the global support allowlist in the registration
// validator.
func (c *config) profileAllowedAuthMethodNames() []string {
	allowed := c.profileIntersection(profile.AllowedClientAuthMethods)
	if allowed == nil {
		return nil
	}
	return withoutMTLSAuthMethods(allowed)
}

// clientSigningAlgs returns the JWS alg set the active profiles admit on
// client-signed input (client assertions, request objects, CIBA signed
// requests), or nil when no profile narrows the library allow-list. It
// is the single source every verifier, the discovery advertisement and
// the registration validator read, so the three cannot disagree.
func (c *config) clientSigningAlgs() []string {
	return c.profileIntersection(profile.AllowedClientSigningAlgs)
}

// clientSigningJOSEAlgs is [config.clientSigningAlgs] in the typed form
// the internal verifiers take.
func (c *config) clientSigningJOSEAlgs() []jose.Algorithm {
	names := c.clientSigningAlgs()
	if names == nil {
		return nil
	}
	out := make([]jose.Algorithm, 0, len(names))
	for _, name := range names {
		out = append(out, jose.Algorithm(name))
	}
	return out
}

// profileIntersection returns the intersection of list over every active
// profile that constrains it, or nil when none does. The most
// restrictive policy wins when several profiles are active.
func (c *config) profileIntersection(list func(profile.Profile) []string) []string {
	var allowed []string
	first := true
	for _, p := range c.profiles {
		values := list(p)
		if values == nil {
			continue
		}
		if first {
			allowed = values
			first = false
			continue
		}
		allowed = intersectStrings(allowed, values)
	}
	if first {
		return nil
	}
	return allowed
}

// withoutMTLSAuthMethods returns names with the RFC 8705 mTLS client-auth
// methods removed, preserving order. The OP advertises and admits only the
// methods its runtime verifier negotiates; mTLS client authentication is not
// yet among them.
func withoutMTLSAuthMethods(names []string) []string {
	out := make([]string, 0, len(names))
	for _, name := range names {
		switch AuthMethod(name) {
		case AuthTLSClientAuth, AuthSelfSignedTLSClientAuth:
			continue
		default:
			out = append(out, name)
		}
	}
	return out
}

// intersectStrings returns the elements of a that also appear in b,
// preserving a's order. It exists as a free function so
// [config.profileAllowedAuthMethodNames] stays under the gocognit
// budget while remaining readable.
func intersectStrings(a, b []string) []string {
	out := make([]string, 0, len(a))
	for _, x := range a {
		for _, y := range b {
			if x == y {
				out = append(out, x)
				break
			}
		}
	}
	return out
}
