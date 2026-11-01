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
// Grant Management ([GrantManagementAction] and [WithGrantManagement]), Client
// ID Metadata Documents ([WithClientIDMetadataDocuments]), the ID-JAG profile
// of the JWT bearer grant together with ID-JAG issuance through token
// exchange, and the RISC event types ([AccountDisabled] and its siblings)
// delivered through Shared Signals: each tracks an external draft whose wire
// shape may still change, so its stability is not this library's to promise.
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
//	    op.WithProfile(profile.Baseline),
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
// to authenticate. Enable the authorization_code grant without one, however,
// and [New] refuses to construct: an OP that can start an authorization it has
// no credential to finish is exactly the zero-value start the boot contract
// exists to exclude. [PrimaryPassword] is the usual starting point; further
// factors attach as [Rule] entries.
//
// # Where to start
//
// Most options in this package serve one feature each. A typical deployment
// sets these and leaves the rest at their defaults:
//
//   - [WithIssuer], [WithStore], [WithKeyset]: always required.
//   - [WithCookieKeys]: required while the authorization_code grant is enabled.
//   - [WithLoginFlow]: how a user signs in; [PrimaryPassword] reads your own
//     users table, and the claims come from the same store.
//   - [WithStaticClients]: the relying parties known at deploy time.
//   - [WithProfile]: the security profile, checked against everything else;
//     without one, New warns that a confidential client may skip PKCE.
//   - [WithLogger]: start-up and claim diagnostics, discarded without it.
//   - [WithMountPrefix], [WithTrustedProxies]: where the OP mounts and which
//     reverse proxies it trusts.
//   - [WithSPAUI] or [WithConsentUI]: your own login and consent pages in
//     place of the built-in ones.
//
// [WithUserStore] is needed only when claims come from records other than
// the ones [PrimaryPassword] authenticates against. [NewReloadable] replaces
// [New] when keys or options change without a restart.
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
//     URLs for backchannel_logout_uri at registration time and narrows the
//     deliverer's SSRF gate to loopback so a stub RP on 127.0.0.1 can
//     receive the logout token POST. Every other private range stays
//     refused; reaching one is [WithAllowPrivateNetworkBackchannel].
//
// Production embedders leave both off and front their RPs over TLS.
//
// # Standards
//
// The library targets OpenID Connect Core 1.0, OAuth 2.0 (RFC 6749) and the
// OAuth 2.0 Security Best Current Practices (RFC 9700), and the FAPI 2.0
// Baseline and Message Signing profiles.
package op
