package devicecode

import "errors"

// Sentinel errors returned by the helpers in this package. The
// /device_authorization handler and the token-endpoint device_code
// grant translate each value into the matching RFC 8628 §3.5 / RFC
// 6749 §5.2 wire code; the mapping is documented at the call site
// rather than encoded as a method on the sentinel so each
// translation can carry context-specific extras into the audit
// stream.
var (
	// ErrSubstoreUnavailable signals that the [DeviceCodeStore]
	// substore is missing from the configured backend. The library
	// detects this at op.New time and refuses to construct the
	// provider; this sentinel is the runtime sibling for code
	// paths that must check defensively.
	ErrSubstoreUnavailable = errors.New("devicecode: device-code substore is not provisioned")

	// ErrUserCodeCollision signals that a freshly generated
	// user_code clashed with a still-active record. The handler
	// retries up to a small bound; reaching the bound is treated
	// as a fatal randomness fault.
	ErrUserCodeCollision = errors.New("devicecode: user_code collided with an existing active record")

	// ErrClientGrantNotPermitted signals that the authenticated
	// client is not registered for the device_code grant. The
	// /device_authorization handler maps this to invalid_grant; a
	// poll at /token surfaces the same value as
	// unauthorized_client.
	ErrClientGrantNotPermitted = errors.New("devicecode: client is not authorised for the device_code grant")

	// ErrUnboundUnderFAPI signals that the request reached
	// /device_authorization without a DPoP proof or mTLS leaf
	// while the active profile set requires sender-constraint at
	// the issued-token level (FAPI 2.0 baseline). Maps to
	// invalid_request.
	ErrUnboundUnderFAPI = errors.New("devicecode: unbound device-authorization request rejected under FAPI 2.0 baseline")

	// ErrInvalidResource signals that one of the supplied
	// resource indicators failed RFC 8707 §2 normalisation. Maps
	// to invalid_target.
	ErrInvalidResource = errors.New("devicecode: resource parameter is not a valid absolute URI")
)
