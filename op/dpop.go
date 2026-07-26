package op

// DPoPNonceSource is the embedder-supplied component that drives the
// RFC 9449 §8 / §9 server-supplied nonce flow. The single interface
// bundles both halves of the contract — issuance (the value the
// `DPoP-Nonce` response header carries) and validation (whether the
// nonce a client sent is currently acceptable) — because the typical
// embedder owns one rotation pipeline that does both. Callers who
// need to split issuance from validation across two components can
// supply a small adapter that delegates each method to the
// appropriate backend.
//
// When a [Provider] is constructed with [WithDPoPNonceSource]:
//
//   - The /token, /par, and /userinfo handlers reject DPoP proofs
//     that do not carry an acceptable "nonce" claim, returning the
//     RFC 9449 `use_dpop_nonce` challenge so the client can retry.
//   - Every challenge response stamps a fresh value from
//     [IssueNonce] into the `DPoP-Nonce` response header.
//
// When [WithDPoPNonceSource] is not called the gate is off: proofs
// without a nonce claim are accepted and the challenge is never
// emitted.
//
// Implementations MUST be safe for concurrent use; the provider
// invokes both methods from every request goroutine. An empty
// [IssueNonce] return value is treated as "issuer offline": the
// challenge is emitted without a `DPoP-Nonce` header so the client
// can still see the gate fired. Implementations SHOULD never return
// empty in normal operation.
//
// Stable since v1.0.
type DPoPNonceSource interface {
	// IssueNonce returns a fresh nonce value to stamp into the
	// `DPoP-Nonce` response header. Implementations typically
	// rotate values periodically; the dpop verifier consults
	// [Validate] to decide whether a presented nonce is still
	// acceptable, so the rotation cadence is the source's policy.
	IssueNonce() string

	// Validate reports whether nonce is currently acceptable. The
	// dpop verifier short-circuits on empty input before this
	// method is invoked, but implementations MAY reject empty
	// directly so they can be embedded outside the verifier
	// without duplicating the guard.
	Validate(nonce string) bool
}
