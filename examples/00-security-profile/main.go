//go:build example

// Example 00 demonstrates [op.WithProfile] as a declaration: what a
// security profile changes, and why declaring none is a different
// thing from declaring the permissive one.
//
// Two OPs run side by side in the same process with identical
// options except for one line:
//
//   - :8080 — no profile declared. This is the OpenID Connect Core
//     1.0 shape. OIDC Core predates RFC 7636, so a confidential
//     client MAY omit code_challenge and the OP admits the request.
//   - :8081 — op.WithProfile(profile.Baseline). The OAuth 2.1 /
//     RFC 9700 posture: PKCE is mandatory on every authorization-code
//     request, and the same request is refused.
//
// Both answers are spec-correct. That is the problem the profile
// solves: without a declaration, "we admit legacy relying parties on
// purpose" and "nobody ever thought about it" produce byte-identical
// configurations. profile.Baseline is how a deployment says the
// former in the type system, and op.New then holds it to that.
//
// Run with the example build tag:
//
//	(cd examples/00-security-profile && go run -tags example .)
//
// # 1. Read the posture off the audit stream
//
// Each OP emits one "startup.profile" audit record at construction.
// Both records print to stdout on boot; compare their extras:
//
//	"profiles": []          "pkce_required": false   ← :8080
//	"profiles": ["baseline"] "pkce_required": true   ← :8081
//
// The record carries the resolved policy, not just the declaration —
// which sender-constraint mechanism won, which client-auth methods
// survive, the token TTLs — so an operator can answer "what is this
// OP running" without re-deriving it from the option list.
//
// # 2. Watch the same request get two answers
//
// An authorization request from a confidential client, with no
// code_challenge. Ask each OP for the redirect it would issue:
//
//	AUTHZ='client_id=profile-demo-rp&response_type=code&redirect_uri=http://localhost:5173/cb&scope=openid&state=xyz'
//
//	# :8080 — admitted. Location points at the OP's login prompt.
//	curl -si "http://127.0.0.1:8080/oidc/auth?${AUTHZ}" | grep -i '^location:'
//
//	# :8081 — refused. Location points back at the RP carrying
//	#         error=invalid_request and the state, per RFC 6749 §4.1.2.1.
//	curl -si "http://127.0.0.1:8081/oidc/auth?${AUTHZ}" | grep -i '^location:'
//
// Add a PKCE pair and the profiled OP behaves exactly like the other
// one — the profile mandates the parameter, it does not change the
// flow:
//
//	VERIFIER='security-profile-example-verifier-0123456789-ABCDEFG'
//	CHALLENGE="$(printf %s "$VERIFIER" | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')"
//	curl -si "http://127.0.0.1:8081/oidc/auth?${AUTHZ}&code_challenge=${CHALLENGE}&code_challenge_method=S256" | grep -i '^location:'
//
// # Why the demo client is confidential
//
// A public client MUST use PKCE under RFC 9700 §2.1.1 whatever the OP
// declares, so a public-client demo would show no difference at all.
// The profile-conditional gate only has room to move on confidential
// clients, which is where the OIDC Core compatibility question
// actually lives.
//
// # Choosing
//
// Declare profile.Baseline unless PKCE-incapable relying parties are
// still connected. It costs nothing else: it caps no token lifetime,
// restricts no client-authentication method, and requires neither PAR
// nor sender-constrained tokens. Those belong to the FAPI profiles —
// see 03-fapi2. During a migration, run without a profile and declare
// it once the last legacy RP is gone; the startup record is how you
// confirm the switch landed.
//
// PRODUCTION CAVEATS:
//   - Keys: ephemeral; load from a vault / KMS in production.
//   - Store: in-memory; use op/storeadapter/sql or composite.
//   - Listener: plain HTTP; front behind TLS-terminating ingress.
//   - Two OPs in one process is a teaching device; a deployment runs one OP with one declared posture.
//   - User seed: the demo username / password are hard-coded; production embedders enrol users through their own management plane.
//   - Client secrets: hardcoded for the demo; rotate confidential secrets through the embedder's secret manager.
package main

import (
	"context"
	"log"
	"log/slog"
	"net/http"
	"os"

	"github.com/libraz/go-oidc-provider/examples/internal/devkeys"
	"github.com/libraz/go-oidc-provider/examples/internal/opkit"
	"github.com/libraz/go-oidc-provider/examples/internal/serve"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/profile"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

const (
	unprofiledAddr = ":8080"
	baselineAddr   = ":8081"

	clientID    = "profile-demo-rp"
	redirectURI = "http://localhost:5173/cb"

	demoUsername = "demo"
	demoPassword = "demo"
	demoSubject  = "profile-demo-user"
)

func main() {
	// One JSON audit stream for both OPs. The startup.profile records
	// land here at construction time, which is the point of the demo:
	// the posture is readable before the first request arrives.
	auditLogger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	unprofiled, err := buildProvider("http://127.0.0.1"+unprofiledAddr, auditLogger)
	if err != nil {
		log.Fatalf("unprofiled OP: %v", err)
	}
	// The single line that separates the two OPs.
	baseline, err := buildProvider("http://127.0.0.1"+baselineAddr, auditLogger, op.WithProfile(profile.Baseline))
	if err != nil {
		log.Fatalf("baseline OP: %v", err)
	}

	log.Printf("no profile declared  → http://127.0.0.1%s (admits a confidential client without PKCE)", unprofiledAddr)
	log.Printf("profile.Baseline     → http://127.0.0.1%s (refuses the same request)", baselineAddr)
	log.Printf("demo user: username=%q password=%q", demoUsername, demoPassword)

	errCh := make(chan error, 2)
	go func() { errCh <- serve.Listen(unprofiledAddr, mount(unprofiled)) }()
	go func() { errCh <- serve.Listen(baselineAddr, mount(baseline)) }()
	log.Fatal(<-errCh)
}

// buildProvider assembles one OP. Every option is identical across
// the two instances; the caller supplies the profile declaration (or
// does not) through extra.
func buildProvider(issuer string, auditLogger *slog.Logger, extra ...op.Option) (*op.Provider, error) {
	keys := devkeys.MustEphemeral("security-profile-" + issuer)

	st := inmem.New()
	if err := seedDemoUser(st); err != nil {
		return nil, err
	}

	opts := []op.Option{
		op.WithIssuer(issuer),
		op.WithStore(st),
		op.WithKeyset(keys.Keyset()),
		op.WithCookieKeys(keys.CookieKey),
		// The demo redirect_uri uses the textual "localhost" host.
		op.WithAllowLocalhostLoopback(),
		op.WithLoginFlow(opkit.DefaultLoginFlow(st.UserPasswords())),
		// Routes startup.profile — and every later business event —
		// to the audit stream. Without it the record is discarded and
		// the OP's posture is only readable from the source.
		op.WithAuditLogger(auditLogger),
		op.WithStaticClients(op.ConfidentialClient{
			ID: clientID,
			// Inline rather than a shared constant so
			// scripts/check_example_secrets.sh sees the literal and
			// can prove no two examples ship the same demo secret.
			Secret:       "security-profile-demo-secret-rotate-me",
			AuthMethod:   op.AuthClientSecretBasic,
			RedirectURIs: []string{redirectURI},
			GrantTypes:   []string{"authorization_code", "refresh_token"},
			Scopes:       []string{"openid", "profile"},
		}),
	}
	return op.New(append(opts, extra...)...)
}

func mount(provider *op.Provider) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/", provider)
	return mux
}

func seedDemoUser(st *inmem.Store) error {
	hash, err := op.HashPassword(demoPassword)
	if err != nil {
		return err
	}
	st.PutUserWithPassword(context.Background(), &store.User{
		Subject: demoSubject,
		Claims: map[string]any{
			"name":  "Demo User",
			"email": "demo@example.com",
		},
	}, demoUsername, hash)
	return nil
}
