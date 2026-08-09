//go:build example

// Example 33-token-exchange-delegation demonstrates RFC 8693 OAuth 2.0
// Token Exchange in the canonical on-behalf-of (delegation) shape.
// Three actors live in one process:
//
//   - The OP (gated by [op.RegisterTokenExchange]) on :8090.
//   - Service A — the "exchanger". A confidential client that already
//     holds a user's access_token (issued for service-a's audience)
//     and wants to call service-b on the user's behalf with a
//     downscoped credential.
//   - Service B — the "resource server". A passive client whose only
//     purpose is to own the audience name; the example RS-side
//     verifier reads issuer / audience / sub / act off the JWT.
//
// What the round-trip proves:
//
//  1. Service A drives the authorization_code flow against the OP and
//     receives an access_token whose sub is "user-42" and aud is
//     service-a.
//  2. Service A POSTs that token back to /oidc/token under the
//     token-exchange grant_type, asks for audience=service-b and a
//     downscoped scope.
//  3. The OP runs structural checks (audience narrowing, scope
//     downscope, TTL ceiling) and then calls the supplied
//     [op.TokenExchangePolicy] for the business decision.
//  4. The OP mints a new access_token whose JWT claims include
//     act={"sub":"service-a"} (RFC 8693 §4.1), sub="user-42",
//     aud=["service-b"], and the narrowed scope.
//  5. The Service-B verifier inspects the act chain and prints
//     "User user-42 (acting via service-a) has api:read access to
//     service-b".
//
// Run with the example build tag:
//
//	(cd examples/33-token-exchange-delegation && GOWORK=off go run -tags example .)
//
// The example is self-contained: a single binary stands up the OP on
// :8090, runs a self-verify probe in-process, and exits 0 on success.
// End-to-end runtime is well under five seconds.
//
// The codebase is split by role across this directory:
//
//   - main.go      — entrypoint, package godoc, OP listener
//     (probe + public). Owns the high-level run() sequence and the
//     httptest probe-OP boot helper.
//   - op.go        — OP-side wiring: buildProvider plus the
//     [op.TokenExchangePolicy] implementation the OP dispatches the
//     business decision to.
//   - probe.go     — self-verify probe: the three-step assertion
//     orchestration (obtain → exchange → service-b verify).
//   - service_a.go — exchanger-side actions: auth-code flow + PKCE +
//     consent driver + token-exchange POST. This is the half a real
//     service-a binary would lift into production.
//   - service_b.go — resource-server-side: JWT claim inspection,
//     audience match, act chain walk.
//   - util.go      — shared HTTP plumbing (doGET, decodeJSONBody,
//     findCookie) that the role files reach for.
//
// Why "act" matters: RFC 8693 §4.1 makes the act claim the
// delegation chain's primary auditing artifact. A resource server
// that ignores act sees a token whose sub is the original user and
// silently participates in delegation it cannot observe. The
// Service-B verifier in this example explicitly walks the chain so
// the read pattern is observable next to the write.
//
// PRODUCTION CAVEATS:
//   - Keys: ephemeral; load from a vault / KMS in production.
//   - Store: in-memory; use op/storeadapter/sql or composite.
//   - Listener: plain HTTP; front behind TLS-terminating ingress.
//   - Authentication: this example wires
//     [testkit.SubjectAuthenticator], which trusts whatever
//     subject the SPA submits. Production OPs run a real password /
//     WebAuthn / OIDC-federation primary factor here.
//   - Policy seam: the example policy admits every exchange between
//     the demo's two clients. Production embedders consult tenant
//     allowlists, rate-of-exchange budgets, and request-context risk
//     before returning nil.
//   - act-aware RS: a resource server that does not consume the act
//     chain is participating in delegation it cannot see. The
//     verifier in this example is the minimal read pattern; library
//     consumers should treat the chain as an audit primary, not an
//     advisory hint.
package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"time"
)

const (
	// frontendID is the client that obtains the user's subject_token
	// via the authorization_code flow. Real deployments typically
	// have a SPA / mobile / first-party RP in this slot; the example
	// pins a confidential client purely so the auth-code flow has a
	// secret to bind. The frontend never performs the exchange; the
	// token it receives is what service-a presents as subject_token.
	frontendID     = "frontend"
	frontendSecret = "tx-frontend-secret-rotate-me"

	// serviceAID is the calling client — the one performing the
	// exchange. The OP authenticates it via client_secret_post. The
	// impersonation chain names this client as act.sub on the issued
	// token (the OP injects the calling client when no actor_token is
	// supplied, per RFC 8693 §1.3).
	serviceAID     = "service-a"
	serviceASecret = "tx-svc-a-secret-rotate-me"

	// serviceBID is the resource server's identifier. The OP never
	// authenticates this client for the exchange; service-b's role is
	// owning the audience name and parsing JWTs the OP issued for it.
	serviceBID = "service-b"

	// serviceAResource and serviceBResource are the RFC 8707 resource
	// indicators the example treats as the audience values. Token-
	// exchange's audience parameter feeds into the same allowlist as
	// /authorize's resource parameter; both must be absolute URIs the
	// client registered. Example clients register the URI form, so the
	// final aud claim on the issued JWT is also URI-shaped.
	serviceAResource = "https://api.service-a.example/"
	serviceBResource = "https://api.service-b.example/"

	// userSubject is the end-user the subject_token was issued to.
	// The auth-code flow's [testkit.SubjectAuthenticator] echoes back
	// whatever subject the helper submits; we pin a fixed value so the
	// final assertion has something stable to read.
	userSubject = "user-42"

	// rpRedirectURI is the URL the OP redirects to after the
	// authorization-code round-trip. The example never actually
	// listens on this host — the helper inspects the redirect's
	// query parameters directly, mirroring the scenariokit pattern.
	rpRedirectURI = "https://service-a.example.invalid/callback"

	// scopeFull is the original access_token's scope set; scopeNarrow
	// is what service-a downscopes to when calling service-b. The
	// OP enforces RequestedScope ⊆ subject_token scope structurally;
	// the policy may narrow further.
	scopeFull   = "openid api:read api:write"
	scopeNarrow = "api:read"

	tokenExchangeGrantType   = "urn:ietf:params:oauth:grant-type:token-exchange"
	subjectTokenTypeAT       = "urn:ietf:params:oauth:token-type:access_token"
	requestedTokenTypeAT     = "urn:ietf:params:oauth:token-type:access_token"
	tokenExchangeMaxLifetime = 5 * time.Minute
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	if err := run(logger); err != nil {
		logger.Error("token-exchange example failed", slog.String("err", err.Error()))
		os.Exit(1)
	}
}

// run boots the OP, runs the in-process self-verify probe, and (on
// success) opens a public listener on :8090 so an embedder can curl
// the discovery endpoint. The probe is the canonical assertion the
// example ships; the listener is convenience for ad-hoc inspection.
func run(logger *slog.Logger) error {
	probeIssuer, probeShutdown, err := startProbeOP(logger)
	if err != nil {
		return err
	}
	defer probeShutdown()

	if err := selfVerify(logger, probeIssuer); err != nil {
		fmt.Println("✗ self-verify: " + err.Error())
		return err
	}
	fmt.Println("✓ self-verify: token-exchange round-trip OK with act-chain verified")

	// The probe OP and its listener are torn down by the deferred
	// shutdown above. The public listener below is a fresh OP bound
	// to :8090 so an embedder running `go run -tags example ...` can
	// curl the discovery endpoint after the probe prints its summary.
	logger.Info("opening public listener", slog.String("addr", ":8090"))
	return runPublicListener(logger)
}

// startProbeOP boots an OP backed by an httptest.NewServer (so it
// uses an ephemeral port) wired with the token-exchange policy, the
// auth-code subject authenticator, and two static clients. The
// returned shutdown closure tears the server down deterministically.
//
// The provider's issuer is the httptest URL so the discovery
// document (and the iss claim on every issued token) match the
// listener the probe actually drives. Embedders running a real
// listener pass the public issuer to [buildProvider].
func startProbeOP(logger *slog.Logger) (issuer string, shutdown func(), err error) {
	// httptest.NewUnstartedServer reserves a port without serving so
	// we can read the listener address before constructing the OP.
	// op.WithIssuer rejects mismatched issuers at request time, so the
	// option needs the final URL the listener exposes.
	srv := httptest.NewUnstartedServer(nil)
	probeIssuer := "http://" + srv.Listener.Addr().String()
	provider, err := buildProvider(probeIssuer)
	if err != nil {
		srv.Close()
		return "", nil, fmt.Errorf("build provider: %w", err)
	}
	srv.Config.Handler = provider
	srv.Start()
	logger.Info("probe OP listening", slog.String("issuer", srv.URL))
	return srv.URL, srv.Close, nil
}

// runPublicListener boots a fresh OP on :8090 (the issuer the
// package banner advertises) and blocks until SIGINT. The block is
// short — examples run as one-shot demos — so the surface here is
// intentionally minimal.
func runPublicListener(logger *slog.Logger) error {
	const addr = ":8090"
	const issuer = "http://127.0.0.1:8090"
	provider, err := buildProvider(issuer)
	if err != nil {
		return fmt.Errorf("build provider: %w", err)
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           provider,
		ReadHeaderTimeout: 10 * time.Second,
	}
	logger.Info("OP listening", slog.String("addr", addr))
	logger.Info("hint: curl http://127.0.0.1:8090/.well-known/openid-configuration | jq")
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
