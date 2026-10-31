// Package assertiongrant verifies the assertion of an RFC 7523 §2.1 JWT
// bearer grant, including the Identity Assertion JWT Authorization Grant
// (ID-JAG, draft-ietf-oauth-identity-assertion-authz-grant-06) profile.
//
// Trust is declared per issuer: an exact iss, the issuer's keys (inline JWKS
// or a jwks_uri resolved through the shared relying-party fetcher), and a
// [Profile]. Verification runs in a fixed order and a rejection names the
// stage that failed ([Reason]): parse, issuer, typ, signature, claims, idjag,
// replay. The jti is consumed last, after every other check has passed, so a
// rejected assertion never burns its identifier.
//
// Error contract: an [*Error] is a defect of the assertion (invalid_grant);
// an error wrapping [ErrKeySourceUnavailable] is a transient issuer-JWKS
// outage (503); anything else is a server-side fault.
package assertiongrant
