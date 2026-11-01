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
//   - ErrInvalidHintCombination   → invalid_request.
//   - ErrMissingScope             → invalid_request.
//   - ErrScopeMissingOpenID       → invalid_scope.
//   - ErrBindingMessageTooLong    → invalid_binding_message.
//   - ErrBindingMessageInvalidChar → invalid_binding_message.
//   - ErrInvalidRequestedExpiry   → invalid_request.
var (
	// ErrInvalidHintCombination signals that the request did not
	// supply exactly one of login_hint, id_token_hint, or
	// login_hint_token. CIBA Core §7.1 mandates exactly-one. Maps
	// to invalid_request.
	ErrInvalidHintCombination = errors.New("ciba: exactly one of login_hint, id_token_hint, login_hint_token is required")

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

	// ErrBindingMessageInvalidChar signals that the supplied
	// binding_message contains a Unicode control character. CIBA
	// Core §7.1's anti-phishing interlock depends on the
	// authentication and consumption devices displaying an
	// identical string; control characters could be used to spoof
	// or truncate the rendered message. Maps to
	// invalid_binding_message.
	ErrBindingMessageInvalidChar = errors.New("ciba: binding_message contains a control character")

	// ErrInvalidRequestedExpiry signals that the requested_expiry
	// parameter was supplied but failed to parse as a positive
	// base-10 integer (in seconds). Maps to invalid_request.
	ErrInvalidRequestedExpiry = errors.New("ciba: requested_expiry is not a positive integer")
)
