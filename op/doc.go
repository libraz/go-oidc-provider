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
// The public API follows Semantic Versioning: a breaking change to anything
// documented here requires a major version, and every such change is recorded
// in CHANGELOG.md.
//
// There is one exemption, and it is enumerated rather than described. A symbol
// whose godoc begins with "Experimental:" may change in a minor release; the
// same marker on a package doc exempts everything that package declares. The
// complete set is generated from those markers into api/experimental.txt and
// diffed by the build, so the exemption cannot grow without the diff showing
// it. Everything absent from that file is stable. The exempt surface today is
// the authentication-step seam ([LoginFlow] and the options that populate it),
// the interaction UI hooks, and Grant Management, which tracks an IETF draft,
// plus two packages in full: op/interaction, whose Driver seam is still
// settling, and the DynamoDB storage adapter.
//
// # Quickstart
//
//	handler, err := op.New(
//	    op.WithIssuer("https://idp.example.com"),
//	    op.WithKeyset(myKeyset),
//	    op.WithStore(myStore),
//	    op.WithCookieKeys(myAES256GCMKey),
//	    op.WithLoginFlow(op.LoginFlow{
//	        Primary: op.PrimaryPassword{Store: myUserPasswordStore},
//	    }),
//	)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	http.ListenAndServe(":8080", handler)
//
// [New] returns a [*Provider], which serves as the [http.Handler] above and
// carries the one lifecycle seam the library has: [Provider.Shutdown] waits
// for back-channel logout deliveries that are still in flight. /end_session
// answers the user without waiting for the relying parties to be notified, so
// a process that exits the moment its listener closes can drop signed Logout
// Tokens that were already queued. Stop accepting requests first, then drain:
//
//	srv.Shutdown(ctx)      // stop accepting
//	provider.Shutdown(ctx) // then drain
//
// It is safe to call on any provider, including one that never mounts
// /end_session, so it costs nothing to wire in unconditionally.
//
// [WithLoginFlow] declares how a browser session authenticates. It is outside
// the required set because an OP serving only client_credentials has no user
// to authenticate. A provider that mounts the authorize endpoint without one
// still constructs, but it has no credential to prompt for: the first request
// that needs an interaction answers server_error ("interaction is not
// configured"). [PrimaryPassword] is the usual starting point; further factors
// attach as [Rule] entries.
//
// # Local development
//
// The defaults are tuned for production (https-only, public-network-only).
// Two opt-in options widen the gates for demos and CI fixtures bound to
// the loopback interface:
//
//   - [WithAllowLocalhostLoopback] admits the textual "localhost" host in
//     redirect_uri values and in the issuer (the IP literals 127.0.0.1 and
//     [::1] are always admitted on the http loopback carve-out). A local
//     WebAuthn deployment needs the issuer half: a Relying Party ID must
//     be a domain, so an http issuer on an IP literal has none to pair
//     with.
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
// OAuth 2.0 Security Best Current Practices (RFC 9700), and the FAPI 2.0
// Baseline and Message Signing profiles.
package op
