package profile

import (
	"time"

	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/grant"
)

// RequiredFeatures returns the conjunctive set of [feature.Flag]
// values an [op.Provider] MUST have enabled for p to be a valid
// configuration. The slice is freshly allocated on each call; callers
// may mutate it freely.
//
// The mapping mirrors the MUST clauses from each profile spec:
//
//   - [FAPI2Baseline]: PAR (FAPI 2.0 §3.1.1) and JAR (§3.1.11). The
//     sender-constrained-token requirement (§3.1.4) is conjunctive
//     across the profile but disjunctive across DPoP / mTLS, so it
//     lives on [RequiredAnyOf] rather than here.
//   - [FAPI2MessageSigning]: every [FAPI2Baseline] requirement plus
//     JARM (Message Signing §5).
//   - [FAPICIBA]: JAR (FAPI-CIBA-ID1 §5.2.2 mandates that every
//     /bc-authorize request be a signed authentication request). The
//     sender-constrained-token requirement is inherited from the
//     FAPI 2.0 family and lives on [RequiredAnyOf] like FAPI 2.0
//     Baseline / Message Signing.
//   - [Baseline]: none. Its PKCE mandate is a policy predicate
//     ([RequiresPKCE]), not a routable extension — [feature.PKCE]
//     only affects discovery metadata and per-client policy.
func RequiredFeatures(p Profile) []feature.Flag {
	switch p {
	case FAPI2Baseline:
		return []feature.Flag{feature.PAR, feature.JAR}
	case FAPI2MessageSigning:
		return []feature.Flag{feature.PAR, feature.JAR, feature.JARM}
	case FAPICIBA:
		return []feature.Flag{feature.JAR}
	case Baseline, profileUnspecified:
		return nil
	default:
		return nil
	}
}

// RequiredGrants returns the [grant.Type] values p cannot be served
// without. The slice is freshly allocated on each call; callers may
// mutate it freely.
//
// [FAPICIBA] returns grant.CIBA: the profile's entire subject matter
// is the /bc-authorize ceremony, and that endpoint is mounted from
// the grant set rather than the profile set. Without the constraint a
// deployment could declare the profile, have JAR and DPoP switched on
// for it, and still answer 404 to every backchannel-authentication
// request. Every other profile returns nil — FAPI 2.0 Baseline and
// Message Signing constrain how the authorization-code grant behaves
// rather than which grants exist, and [Baseline] adds no grant of its
// own.
//
// Unlike [RequiredFeatures], the option layer does NOT auto-enable a
// missing grant; [op.New] fails instead. Enabling a grant drags in
// collaborators the embedder must supply (CIBA needs a
// [store.CIBARequestStore] substore and a hint resolver), so
// auto-enabling would replace a precise "you declared CIBA but did
// not wire it" error with a substore complaint about a grant the
// embedder never asked for. Features carry no such requirement, which
// is why they default in and grants do not.
func RequiredGrants(p Profile) []grant.Type {
	switch p {
	case FAPICIBA:
		return []grant.Type{grant.CIBA}
	case Baseline, FAPI2Baseline, FAPI2MessageSigning, profileUnspecified:
		return nil
	default:
		return nil
	}
}

// RequiredAnyOf returns the disjunctive constraint sets layered on
// top of [RequiredFeatures]. The outer slice is conjunctive: every
// set MUST be satisfied. The inner slice is disjunctive: at least one
// listed [feature.Flag] satisfies the set.
//
// FAPI 2.0 §3.1.4 mandates a sender-constrained access token but
// lets the deployment choose between DPoP (RFC 9449) and mTLS
// (RFC 8705), so the constraint is "DPoP OR MTLS" rather than the
// stronger "DPoP AND MTLS" — pinning a single binding mechanism would
// reject conformant deployments that picked the other. FAPI-CIBA
// inherits the FAPI 2.0 §3.1.4 mandate verbatim (FAPI-CIBA-ID1 §5).
//
// Order is significant: callers that want a default for the
// disjunctive set (the option layer auto-enables it when no member
// is already configured) treat the FIRST element as the canonical
// pick. For the FAPI family DPoP is listed first because it has no
// infrastructure prerequisite — embedders requiring mTLS opt in via
// [feature.MTLS] explicitly so the default steps aside.
func RequiredAnyOf(p Profile) [][]feature.Flag {
	switch p {
	case FAPI2Baseline, FAPI2MessageSigning, FAPICIBA:
		return [][]feature.Flag{{feature.DPoP, feature.MTLS}}
	case Baseline, profileUnspecified:
		return nil
	default:
		return nil
	}
}

// MaxAccessTokenTTL returns the upper bound the profile imposes on
// access token lifetime, or 0 when p does not constrain it. The
// rule is one-directional: an embedder MAY configure a stricter
// (smaller) TTL but MUST NOT configure a value above this bound.
//
// FAPI 2.0 Baseline and Message Signing cap access tokens at 10
// minutes (FAPI 2.0 §3.1.9); FAPI-CIBA inherits the same cap by
// reference (FAPI-CIBA-ID1 §5).
func MaxAccessTokenTTL(p Profile) time.Duration {
	switch p {
	case FAPI2Baseline, FAPI2MessageSigning, FAPICIBA:
		return 10 * time.Minute
	case Baseline, profileUnspecified:
		return 0
	default:
		return 0
	}
}

// RequiresPKCE reports whether p mandates that every authorization-
// code request carries a code_challenge. The library's overall posture
// is OAuth 2.1 / RFC 9700 — PKCE is good practice on every flow — but
// the OpenID Connect Basic certification suite drives the OP without
// PKCE because OIDC Core 1.0 predates RFC 7636 and the certified
// shape stays compatible with that vintage. Treating PKCE as
// profile-conditional resolves the conflict: OIDC vanilla deployments
// (and the Basic certification run) accept the spec-compliant non-
// PKCE path, while every FAPI 2.0 deployment keeps the stronger MUST
// the profile mandates (FAPI 2.0 §2.1.1, citing RFC 7636).
//
// [Baseline] returns true: mandatory PKCE is the one requirement that
// profile carries, and it is what separates an explicit OAuth 2.1
// declaration from the permissive default.
//
// [FAPICIBA] returns false because the CIBA flow has no /authorize
// redirect — the client posts directly to /bc-authorize and there is
// no code_challenge step the gate could attach to. The helper is
// intentionally conservative: a future profile that needs PKCE will be
// added here rather than relied on as the default.
func RequiresPKCE(p Profile) bool {
	switch p {
	case Baseline, FAPI2Baseline, FAPI2MessageSigning:
		return true
	case FAPICIBA, profileUnspecified:
		return false
	default:
		return false
	}
}

// RequiresNonce reports whether p mandates that every authorization
// request carries a non-empty nonce parameter. The library's overall
// posture follows OIDC Core 1.0: nonce is OPTIONAL for code-flow and
// REQUIRED for response_types that emit an id_token from the
// authorization endpoint. The OIDC Basic certification suite drives
// the OP without nonce in code-flow per the OIDC Core errata draft
// (see https://openid.net/specs/openid-connect-core-1_0-27.html#NonceNotes),
// so default deployments and the Basic run accept the omission.
//
// FAPI 2.0 Baseline §5.3.2.1.1 mandates "either a state or a nonce",
// not "nonce". The "state OR nonce" rule lives on [RequiresStateOrNonce]
// because the OFCS conformance suite verifies it via two separate
// modules (-without-nonce-success and -without-state-success): each
// removes one of the parameters and expects success when the other
// is present. A profile that mandated nonce alone would fail the
// "without-nonce-success" module.
//
// No shipping profile currently sets RequiresNonce. The helper exists
// so embedders that want a strict nonce-on-every-request stance can
// wire their own [Policy.NonceRequired]; a future profile that needs
// it will be added here rather than relied on as the default.
//
// [FAPICIBA] returns false because the CIBA flow has no /authorize
// redirect — there is no nonce parameter on the wire.
func RequiresNonce(p Profile) bool {
	switch p {
	case Baseline, FAPICIBA, profileUnspecified, FAPI2Baseline, FAPI2MessageSigning:
		return false
	default:
		return false
	}
}

// RequiresStateOrNonce reports whether p mandates that every
// authorization request carry at least one of the state / nonce
// parameters. FAPI 2.0 §5.3.2.1.1 ("include either a state or a
// nonce parameter") is the canonical source. Vanilla OIDC Core
// leaves this false because state is RECOMMENDED but not REQUIRED.
//
// [Baseline] also returns false. OAuth 2.1 keeps state RECOMMENDED,
// and the CSRF property state supplies is already covered once
// [RequiresPKCE] holds — elevating it here would reject conformant
// OAuth 2.1 clients for no security gain.
//
// [FAPICIBA] returns false because the CIBA flow has no /authorize
// redirect — there is no state or nonce parameter on the wire.
func RequiresStateOrNonce(p Profile) bool {
	switch p {
	case FAPI2Baseline, FAPI2MessageSigning:
		return true
	case Baseline, FAPICIBA, profileUnspecified:
		return false
	default:
		return false
	}
}

// RequiresPAR reports whether p mandates that every authorization
// request reach /authorize via a [RFC 9126] pushed authorization
// request_uri. Bare-wire-form and JAR-only (request= without
// request_uri=) requests are rejected with invalid_request when
// this is true.
//
// FAPI 2.0 Baseline §5.3.1 and Message Signing both require PAR;
// the profile elevates RFC 9126's optional opt-in to a MUST. Vanilla
// OIDC Core deployments — and [Baseline], which takes the OAuth 2.1
// posture without the financial-grade requirements — leave this false
// so the direct-form /authorize path stays functional.
//
// [FAPICIBA] returns false because the CIBA flow does not exercise
// /authorize at all — there is no PAR push step in CIBA.
func RequiresPAR(p Profile) bool {
	switch p {
	case FAPI2Baseline, FAPI2MessageSigning:
		return true
	case Baseline, FAPICIBA, profileUnspecified:
		return false
	default:
		return false
	}
}

// AllowedClientAuthMethods returns the closed set of client
// authentication methods p accepts at the token endpoint, or nil
// when p imposes no restriction. Returned values are the canonical
// `token_endpoint_auth_methods_supported` strings used in
// discovery and dynamic client registration (RFC 8414 / RFC 7591).
//
// FAPI 2.0 §3.1.3 mandates one of [private_key_jwt],
// [tls_client_auth] (RFC 8705), or [self_signed_tls_client_auth]
// (RFC 8705 §2.2). Public clients ("none") and shared-secret
// methods ("client_secret_basic", "client_secret_post",
// "client_secret_jwt") are forbidden. Baseline, Message Signing,
// and FAPI-CIBA inherit the same set; Message Signing's additional
// constraints concern response signing rather than client auth, and
// FAPI-CIBA inherits the FAPI 2.0 §3.1.3 set verbatim.
//
// [Baseline] returns nil: OAuth 2.1 keeps every registered client
// authentication method available, including public clients, and
// narrowing the set would make the profile unusable for the native
// and single-page applications it is meant to cover.
//
// The slice is freshly allocated on each call; callers may mutate
// it freely.
func AllowedClientAuthMethods(p Profile) []string {
	switch p {
	case FAPI2Baseline, FAPI2MessageSigning, FAPICIBA:
		return []string{"private_key_jwt", "tls_client_auth", "self_signed_tls_client_auth"}
	case Baseline, profileUnspecified:
		return nil
	default:
		return nil
	}
}
