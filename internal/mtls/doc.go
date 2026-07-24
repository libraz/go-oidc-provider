// Package mtls implements RFC 8705 "OAuth 2.0 Mutual-TLS Client
// Authentication and Certificate-Bound Access Tokens". It provides:
//
//   - Cert thumbprint computation (RFC 8705 §3.1) — the value bound to
//     issued tokens as the "x5t#S256" member of the "cnf" claim.
//
//   - Client-cert extraction from [*http.Request], with optional support
//     for a trusted reverse-proxy header carrying the URL-encoded PEM.
//
//   - The two §2 client-authentication shapes:
//
//   - "tls_client_auth": a CA-issued cert whose subject DN or one of
//     its SANs (DNS / URI / IP / email) matches a value the embedder
//     registered against the client.
//
//   - "self_signed_tls_client_auth": a cert (typically self-signed)
//     whose public-key JWK thumbprint matches a key in the client's
//     registered JWKS.
//
//   - High-level §3 binding helpers consumed by the token endpoint and
//     the resource server (userinfo): the [Verifier] holds the proxy
//     configuration once at startup and the request-scoped helpers
//     ([Verifier.CertificateFromRequest], [Verifier.ThumbprintFromRequest])
//     return either the leaf cert / its thumbprint or a typed sentinel
//     the HTTP layer maps onto a wire response.
//
// The package never reads the wall clock and never touches storage.
// Trust-anchor verification can be performed by the direct TLS server,
// by the trusted proxy before it rewrites the forwarding header, or by
// [VerifierConfig.RootCAs]. A proxy-to-OP TLS certificate authenticates
// that transport hop and is deliberately distinct from the forwarded
// OAuth client leaf used for RFC 8705 matching and token binding.
package mtls
