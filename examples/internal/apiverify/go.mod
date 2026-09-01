// Module github.com/libraz/go-oidc-provider/examples/internal/apiverify
// is an examples-only test harness that boots the non-browser examples
// (client_credentials, device-code, CIBA, token-exchange, discovery-only
// servers, …) under the "example" build tag and asserts each comes up and
// performs its advertised API round-trip.
//
// It is the API-level counterpart of internal/browserverify: where that
// harness drives an HTML/SPA login with headless Chrome, this one speaks
// plain HTTP. Its only dependency is the library itself, for the
// test-only WebAuthn authenticator in internal/testutil/softkey — a
// passkey ceremony cannot be driven without something that signs, and
// that is an authenticator rather than a browser. Nothing in the
// published library imports this module.
module github.com/libraz/go-oidc-provider/examples/internal/apiverify

go 1.26

toolchain go1.27.0

require github.com/libraz/go-oidc-provider v1.2.0

require (
	github.com/fxamacker/cbor/v2 v2.9.3 // indirect
	github.com/x448/float16 v0.8.4 // indirect
)

replace github.com/libraz/go-oidc-provider => ../../..
