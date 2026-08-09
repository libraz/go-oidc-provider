// Package jarm implements JWT Secured Authorization Response Mode (JARM)
// per the OpenID Foundation FAPI WG specification "JWT Secured
// Authorization Response Mode for OAuth 2.0", which RFC 9101 §10.2
// references informationally.
//
// JARM packages the authorization response as a single signed JWT
// delivered through the redirect (or a form post). This protects the
// response from tampering and replay at the network layer: the OP signs
// the final code / error envelope and the RP verifies the signature
// against the OP's published JWKS.
//
// This package produces the signed JWT only. A client that registered
// authorization_encrypted_response_alg / _enc receives that JWT wrapped
// in a JWE, but the wrap is applied by the authorize endpoint on top of
// what this package returns, against a key from the client's own JWKS —
// so the encryption path needs nothing from here.
//
// # Response modes
//
// The package recognises four response_mode values:
//
//   - "query.jwt"     — JWT in the query string of redirect_uri.
//   - "fragment.jwt"  — JWT in the URL fragment of redirect_uri.
//   - "form_post.jwt" — JWT in an auto-submitted HTML form.
//   - "jwt"           — bare alias resolved to one of the above based on
//     the request's response_type. Because the OP only supports the
//     Code flow, the bare alias always lands on "query.jwt".
//
// # Claim set
//
// Every JARM JWT carries:
//
//   - "iss" — the OP issuer URL (matches discovery's "issuer").
//   - "aud" — the client_id of the requesting RP.
//   - "exp" — short-lived expiry; the package defaults to 60 seconds.
//
// On the success path the JWT additionally carries "code" (and "state"
// when the request supplied one). On the error path it carries "error",
// "error_description" (when set), "error_uri" (when set), and "state".
//
// # Algorithm policy
//
// JARM responses are signed with ES256, using the OP's existing
// access-token / id-token signing key. No new keyset is introduced —
// including for the encrypted variant, whose recipient key is the
// client's, not the OP's.
//
// # Feature gating
//
// The HTTP layer is responsible for checking the [feature.JARM] flag
// before consulting this package. The package itself encodes and
// dispatches; it does not know whether the feature is enabled.
package jarm
