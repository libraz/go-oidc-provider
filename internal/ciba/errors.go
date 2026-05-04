package ciba

import "errors"

// Sentinel errors returned by the helpers in this package. The
// /bc-authorize handler and the token-endpoint CIBA grant translate
// each value into the matching OIDC CIBA Core 1.0 §13 / RFC 6749
// §5.2 wire code; the mapping is documented at the call site rather
// than encoded as a method on the sentinel so each translation can
// carry context-specific extras into the audit stream.
//
// The wire-code mapping each call site applies:
//
//   - ErrSubstoreUnavailable      → server_error (op.New refuses to
//     construct; runtime sibling for defensive paths).
//   - ErrInvalidHintCombination   → invalid_request.
//   - ErrUnknownHint              → unknown_user_id.
//   - ErrMissingScope             → invalid_request.
//   - ErrScopeMissingOpenID       → invalid_scope.
//   - ErrBindingMessageTooLong    → invalid_binding_message.
//   - ErrInvalidRequestedExpiry   → invalid_request.
//   - ErrUnboundUnderFAPI         → invalid_request.
//   - ErrInvalidResource          → invalid_target.
//   - ErrPollAbuseLockout         → access_denied (record locked).
var (
	// ErrSubstoreUnavailable signals that the [CIBARequestStore]
	// substore is missing from the configured backend. The library
	// detects this at op.New time and refuses to construct the
	// provider; this sentinel is the runtime sibling for code paths
	// that must check defensively.
	ErrSubstoreUnavailable = errors.New("ciba: ciba-request substore is not provisioned")

	// ErrInvalidHintCombination signals that the request did not
	// supply exactly one of login_hint, id_token_hint, or
	// login_hint_token. CIBA Core §7.1 mandates exactly-one. Maps
	// to invalid_request.
	ErrInvalidHintCombination = errors.New("ciba: exactly one of login_hint, id_token_hint, login_hint_token is required")

	// ErrUnknownHint signals that the supplied hint did not resolve
	// to a known end-user via the embedder's resolver. CIBA Core §13
	// reserves the unknown_user_id wire code for this condition.
	ErrUnknownHint = errors.New("ciba: hint did not resolve to a known end-user")

	// ErrMissingScope signals that the scope parameter was absent or
	// blank. The OP requires scope to be present so the
	// authentication device can render the consent ceremony. Maps
	// to invalid_request.
	ErrMissingScope = errors.New("ciba: scope parameter is required")

	// ErrScopeMissingOpenID signals that the scope parameter was
	// supplied but did not contain the openid value. CIBA Core §7.1
	// requires openid to be a member of scope. Maps to invalid_scope.
	ErrScopeMissingOpenID = errors.New("ciba: scope must contain openid")

	// ErrBindingMessageTooLong signals that the supplied
	// binding_message exceeds the 50-rune cap the OP enforces before
	// passing the value to the authentication device. CIBA Core §7.1
	// allows the OP to enforce a length limit; this is the limit.
	// Maps to invalid_binding_message.
	ErrBindingMessageTooLong = errors.New("ciba: binding_message exceeds 50 characters")

	// ErrInvalidRequestedExpiry signals that the requested_expiry
	// parameter was supplied but failed to parse as a positive
	// base-10 integer (in seconds). Maps to invalid_request.
	ErrInvalidRequestedExpiry = errors.New("ciba: requested_expiry is not a positive integer")

	// ErrUnboundUnderFAPI signals that the request reached
	// /bc-authorize without a DPoP proof or mTLS leaf while the
	// active profile set requires sender-constraint at the
	// issued-token level (FAPI 2.0 baseline). Maps to invalid_request.
	ErrUnboundUnderFAPI = errors.New("ciba: unbound bc-authorize request rejected under FAPI 2.0 baseline")

	// ErrInvalidResource signals that one of the supplied resource
	// indicators failed RFC 8707 §2 normalisation. Maps to
	// invalid_target.
	ErrInvalidResource = errors.New("ciba: resource parameter is not a valid absolute URI")

	// ErrPollAbuseLockout signals that the poll-violation counter
	// reached [MaxPollViolations] and the record was locked to
	// access_denied. The token endpoint records the lockout via
	// CIBARequestStore.Deny with reason="poll_abuse" and surfaces
	// access_denied on the wire.
	ErrPollAbuseLockout = errors.New("ciba: poll-violation count exceeded; record locked")
)
