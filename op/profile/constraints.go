package profile

import (
	"time"

	"github.com/libraz/go-oidc-provider/op/feature"
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
//
// [FAPICIBA] and [IGovHigh] return nil because their option surfaces
// are scheduled for v1.x / v2+; returning nil keeps the switch
// exhaustive without the library claiming requirements it cannot yet
// enforce.
func RequiredFeatures(p Profile) []feature.Flag {
	switch p {
	case FAPI2Baseline:
		return []feature.Flag{feature.PAR, feature.JAR}
	case FAPI2MessageSigning:
		return []feature.Flag{feature.PAR, feature.JAR, feature.JARM}
	case FAPICIBA, IGovHigh, profileUnspecified:
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
// reject conformant deployments that picked the other.
func RequiredAnyOf(p Profile) [][]feature.Flag {
	switch p {
	case FAPI2Baseline, FAPI2MessageSigning:
		return [][]feature.Flag{{feature.DPoP, feature.MTLS}}
	case FAPICIBA, IGovHigh, profileUnspecified:
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
// Both FAPI 2.0 Baseline and Message Signing cap access tokens at
// 10 minutes (FAPI 2.0 §3.1.9). [FAPICIBA] and [IGovHigh] return 0
// because their option surfaces are scheduled for v1.x / v2+.
func MaxAccessTokenTTL(p Profile) time.Duration {
	switch p {
	case FAPI2Baseline, FAPI2MessageSigning:
		return 10 * time.Minute
	case FAPICIBA, IGovHigh, profileUnspecified:
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
// [FAPICIBA] and [IGovHigh] return false because their option
// surfaces are scheduled for v1.x / v2+; the helper is intentionally
// conservative — a future profile that needs PKCE will be added here
// rather than relied on as the default.
func RequiresPKCE(p Profile) bool {
	switch p {
	case FAPI2Baseline, FAPI2MessageSigning:
		return true
	case FAPICIBA, IGovHigh, profileUnspecified:
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
// FAPI 2.0 Baseline §5.3.2.1.1 and Message Signing both require
// every authorization request to contain a nonce — the profile
// upgrades the OIDC OPTIONAL to a MUST regardless of response_type.
//
// [FAPICIBA] and [IGovHigh] return false because their option
// surfaces are scheduled for v1.x / v2+; the helper is intentionally
// conservative — a future profile that needs nonce will be added
// here rather than relied on as the default.
func RequiresNonce(p Profile) bool {
	switch p {
	case FAPI2Baseline, FAPI2MessageSigning:
		return true
	case FAPICIBA, IGovHigh, profileUnspecified:
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
// OIDC Core deployments leave this false so the legacy direct-form
// /authorize path stays functional.
//
// [FAPICIBA] and [IGovHigh] return false because their option
// surfaces are scheduled for v1.x / v2+.
func RequiresPAR(p Profile) bool {
	switch p {
	case FAPI2Baseline, FAPI2MessageSigning:
		return true
	case FAPICIBA, IGovHigh, profileUnspecified:
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
// "client_secret_jwt") are forbidden. Both Baseline and Message
// Signing inherit the same set; Message Signing's additional
// constraints concern response signing rather than client auth.
//
// The slice is freshly allocated on each call; callers may mutate
// it freely.
func AllowedClientAuthMethods(p Profile) []string {
	switch p {
	case FAPI2Baseline, FAPI2MessageSigning:
		return []string{"private_key_jwt", "tls_client_auth", "self_signed_tls_client_auth"}
	case FAPICIBA, IGovHigh, profileUnspecified:
		return nil
	default:
		return nil
	}
}
