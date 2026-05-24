// Module github.com/libraz/go-oidc-provider/examples/internal/apiverify
// is an examples-only test harness that boots the non-browser examples
// (client_credentials, device-code, CIBA, token-exchange, discovery-only
// servers, …) under the "example" build tag and asserts each comes up and
// performs its advertised API round-trip.
//
// It is the API-level counterpart of internal/browserverify: where that
// harness drives an HTML/SPA login with headless Chrome, this one speaks
// plain HTTP, so it needs nothing beyond the standard library and stays a
// dependency-free sub-module. Nothing in the published library imports it.
module github.com/libraz/go-oidc-provider/examples/internal/apiverify

go 1.26
