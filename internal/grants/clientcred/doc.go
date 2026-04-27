// Package clientcred implements the authorization layer of the
// client_credentials grant from RFC 6749 §4.4. The grant exists for
// machine-to-machine flows where the client itself IS the protected
// resource's authenticated principal: there is no end-user, no
// authorization endpoint round-trip, and the act of authenticating
// the client at the token endpoint IS the act of authorizing the
// access token.
//
// The package is deliberately a policy-only authorizer: callers
// (the token endpoint) hand it the already-authenticated
// [op/store.Client] record plus the requested scope, and the
// package returns the granted scope set or a typed sentinel that
// the HTTP layer maps to an OAuth wire code. Token minting, sender
// constraints (DPoP / mTLS), and persistence stay where they
// already live in [internal/tokenendpoint] / [internal/tokens] /
// [internal/grants/refresh] so the decision logic on this grant
// can be inspected and tested in isolation.
//
// Two specific posture choices the package encodes:
//
//   - No refresh token. RFC 6749 §4.4.3 says "A refresh token
//     SHOULD NOT be included." The library treats this as MUST NOT:
//     a client that needs a fresh access token re-authenticates and
//     re-mints, which is cheap by construction (the credential is
//     in-process) and avoids accumulating long-lived bearer
//     material that survives a credential rotation.
//
//   - No id_token. The OIDC "openid" scope drives id_token issuance,
//     which has no meaning when there is no end-user identity. The
//     package rejects the scope explicitly so a configuration
//     mistake (an embedder lazily reusing a client's scope set)
//     cannot mint identity assertions about a non-existent subject.
package clientcred
