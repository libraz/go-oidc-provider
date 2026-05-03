// Package netsec hosts the SSRF deny-list and the hardened
// [*http.Client] every outbound RP-controlled fetcher in the OP shares.
//
// The library reaches RP-controlled URLs from three independent paths:
//
//   - JWKS / JAR request_uri fetcher in [internal/jar].
//   - sector_identifier_uri fetcher in [internal/sector].
//   - back-channel logout deliverer in [internal/backchannel].
//
// All three converge here so the deny-list cannot drift between
// fetchers and so a single audit can locate every outbound socket the
// OP opens against an attacker-influenced URL.
//
// # Threat model
//
// The fetchers defend against three escalations of the same SSRF
// pattern:
//
//  1. The RP registers a URL whose host is a literal private address
//     (127.0.0.1, 10.0.0.0/8, 169.254.169.254). Caught by the syntactic
//     check on [*url.URL.Hostname].
//  2. The RP registers a URL whose host is a public name that resolves
//     (at registration time) to a private address. Caught by the
//     pre-dial DNS lookup ([net.DefaultResolver.LookupIPAddr]).
//  3. The RP serves a public name whose authoritative DNS hands out a
//     public IP at lookup time and then a private IP a millisecond
//     later — the "DNS rebinding" pattern. Caught by [Dialer.Control],
//     which re-checks the resolved address at the moment the kernel
//     hands the socket to the runtime.
//
// The cloud-metadata addresses (169.254.169.254, fd00:ec2::254) are
// rejected even when [Options.AllowPrivate] is true. The opt-in is
// scoped to lab / on-prem private networks; unrestricting metadata
// addresses would expose every cloud deployment to credential
// disclosure via SSRF, which is the opposite of the option's intent.
//
// # Redirects
//
// [NewHTTPClient] caps redirects at [Options.MaxRedirects] (default 0)
// and re-runs the deny-list against every Location target so a peer
// cannot use a 30x to bypass the gate. A redirect to a deny-listed
// host returns a non-nil error from [http.Client.CheckRedirect] so the
// caller surfaces the rejection rather than silently following.
//
// # Body cap
//
// The package does not cap response body size — that responsibility
// stays with the fetcher because the right limit varies by document
// type. Callers wrap the response body in [io.LimitReader].
package netsec
