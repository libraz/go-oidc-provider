// Package op provides an OpenID Connect Provider (Authorization Server) that
// can be embedded in a Go HTTP server as a standard [http.Handler].
//
// The package is framework-agnostic: [New] returns an [http.Handler] that you
// can mount on net/http, chi, gin, or any other router. The library does not
// own user accounts, persistent storage, or the consent UI; users plug in
// those pieces through small interfaces in op/store and op/interaction.
//
// # Status
//
// go-oidc-provider is pre-v1.0. Public API may change in any minor release
// until v1.0.0. Breaking changes are documented in CHANGELOG.md. APIs whose
// godoc starts with "Experimental:" may change without a major bump even
// after v1.0.
//
// # Quickstart
//
//	handler, err := op.New(
//	    op.WithIssuer("https://idp.example.com"),
//	    op.WithKeyset(myKeyset),
//	    op.WithStore(myStore),
//	    op.WithCookieKeys(myAES256GCMKey),
//	)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	http.ListenAndServe(":8080", handler)
//
// # Local development
//
// The defaults are tuned for production (https-only, public-network-only).
// Two opt-in options widen the gates for demos and CI fixtures bound to
// the loopback interface:
//
//   - [WithAllowLocalhostLoopback] admits the textual "localhost" host in
//     redirect_uri values (the IP literals 127.0.0.1 and [::1] are always
//     admitted on the http loopback carve-out).
//   - [WithAllowInsecureBackchannelLogoutForDev] admits http:// loopback
//     URLs for backchannel_logout_uri at registration time and disables
//     the deliverer's SSRF gate so a stub RP on 127.0.0.1 can receive the
//     logout token POST.
//
// Production embedders leave both off and front their RPs over TLS.
//
// # Standards
//
// The library targets OpenID Connect Core 1.0, OAuth 2.0 (RFC 6749) and the
// OAuth 2.0 Security Best Current Practices (RFC 9700). v1.0 also targets
// FAPI 2.0 Baseline and Message Signing profiles.
package op
