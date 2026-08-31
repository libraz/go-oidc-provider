//go:build example

// Example 42 demonstrates OpenID Connect Back-Channel Logout 1.0.
// When the OP terminates a session — RP-Initiated Logout via
// /end_session — it walks
// every client whose store.Client.BackchannelLogoutURI is non-empty
// and POSTs a signed Logout Token to that URL. Delivery is
// best-effort and parallel across RPs.
//
// Run with the example build tag:
//
//	(cd examples/42-back-channel-logout && GOWORK=off go run -tags example .)
//
// The example boots two HTTP servers in the same process:
//
//   - :8080 — the OP, with one seeded password user and one
//     confidential client registered whose backchannel_logout_uri
//     points at the RP stub on :9090.
//   - :9090 — a tiny RP that prints every Logout Token it receives.
//
// To trigger a delivery, establish a session and then end it. The
// registered redirect_uri (:5173) is a placeholder that nothing
// serves — the browser lands on a connection error, which is fine:
// the authorization code is in the address bar.
//
//  1. Open the authorize URL in a browser and sign in as
//     "demo" / "demo-password":
//
//     http://127.0.0.1:8080/oidc/auth?response_type=code&client_id=demo-rp&redirect_uri=http://127.0.0.1:5173/callback&scope=openid+profile&state=xyz
//
//  2. Copy the "code" query parameter off the failed redirect and
//     exchange it, keeping the id_token from the response:
//
//     curl -s -u demo-rp:bcl-demo-secret-rotate-me \
//     -d grant_type=authorization_code -d code=$CODE \
//     -d redirect_uri=http://127.0.0.1:5173/callback \
//     http://127.0.0.1:8080/oidc/token
//
//  3. End the session, IN THE SAME BROWSER — paste the URL below into
//     the address bar of the window that signed in at step 1:
//
//     http://127.0.0.1:8080/oidc/end_session?id_token_hint=$ID_TOKEN
//
//     The session cookie is what tells the OP which session to
//     terminate. A bare curl carries none, so the OP resolves no
//     session, answers 200, and delivers nothing — the fail-secure
//     outcome, not a delivery failure. To drive step 3 from the shell,
//     share one cookie jar across steps 1 and 3 (curl -c/-b jar.txt).
//
// The RP stub on :9090 prints the Logout Token the OP POSTs to it.
//
// Wiring details:
//
//   - ConfidentialClient surfaces BackchannelLogoutURI alongside the
//     rest of the spec-standard metadata, so the client lands through
//     the typed WithStaticClients seam without an embedder reaching
//     into store.ClientRegistry. The OP advertises session support as
//     false and sends sub-only Logout Tokens until it can persist an
//     RP-specific SID lineage.
//   - WithBackchannelLogoutHTTPClient is OPTIONAL — the package
//     default applies WithBackchannelLogoutTimeout to a fresh client
//     and refuses 3xx redirects on the POST. Override only when the
//     deployment ships a shared outbound transport.
//   - WithBackchannelLogoutTimeout caps the per-RP wait; a slow RP
//     does not delay deliveries to its peers.
//
// PRODUCTION CAVEATS:
//   - Keys: ephemeral; load from a vault / KMS in production.
//   - Store: in-memory; use op/storeadapter/sql or composite.
//   - User seed: the demo username / password are hard-coded, and one [op.PrimaryPassword] step stands in for the whole login flow; production embedders enrol users through their own management plane and compose their own factors.
//   - Listener: plain HTTP; OIDC Back-Channel Logout 1.0 §2.2 requires https for backchannel_logout_uri in production.
//   - Delivery integrity: this example uses inmem (durable for the process lifetime). Swapping SessionStore to Redis without persistence narrows OIDC Back-Channel Logout 1.0 §2.7's best-effort floor — a session evicted before /end_session leaves the coordinator with no RPs to notify. Declare the posture via op.WithSessionDurabilityPosture and watch op.AuditBCLNoSessionsForSubject in the audit stream.
package main

import (
	"context"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/libraz/go-oidc-provider/examples/internal/devkeys"
	"github.com/libraz/go-oidc-provider/examples/internal/opkit"
	"github.com/libraz/go-oidc-provider/examples/internal/serve"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

const (
	opAddr   = ":8080"
	rpAddr   = ":9090"
	clientID = "demo-rp"

	demoUsername = "demo"
	demoPassword = "demo-password"
	demoSubject  = "demo-user"
)

func main() {
	keys := devkeys.MustEphemeral("bcl-1")

	memStore := inmem.New()
	if err := seedUser(memStore); err != nil {
		log.Fatalf("seed demo user: %v", err)
	}

	provider, err := op.New(
		op.WithIssuer("http://127.0.0.1"+opAddr),
		op.WithStore(memStore),
		op.WithKeyset(keys.Keyset()),
		op.WithCookieKeys(keys.CookieKey),
		// Back-channel logout terminates a session, so the demo needs a
		// way to establish one first: the authorize round-trip that
		// seeds the session runs through this password step.
		op.WithLoginFlow(opkit.DefaultLoginFlow(memStore.UserPasswords())),
		// Dev / CI-only: narrow the deliverer's SSRF gate to the loopback
		// hosts so the http://127.0.0.1 backchannel_logout_uri below is
		// admitted and the in-process stub RP receives the logout token
		// POST. Every other private destination stays blocked — the
		// link-local / RFC 1918 / IPv6 ULA deny-list still applies at the
		// URL check, the DNS lookup, the dial and every redirect hop.
		// Production deployments leave this off; OIDC Back-Channel Logout
		// 1.0 §2.2 requires https for backchannel_logout_uri on the public
		// Internet.
		op.WithAllowInsecureBackchannelLogoutForDev(),
		op.WithStaticClients(op.ConfidentialClient{
			ID:                   clientID,
			Secret:               "bcl-demo-secret-rotate-me",
			RedirectURIs:         []string{"http://127.0.0.1:5173/callback"},
			Scopes:               []string{"openid", "profile"},
			BackchannelLogoutURI: "http://127.0.0.1" + rpAddr + "/backchannel-logout",
			ApplicationType:      "web",
		}),
		// Override the default 5-second per-RP timeout. A short
		// budget is the right posture for back-channel logout — the
		// flow is best-effort and a long wait merely keeps the OP
		// holding state on a likely-broken RP.
		op.WithBackchannelLogoutTimeout(2*time.Second),
	)
	if err != nil {
		log.Fatalf("op.New: %v", err)
	}

	// Start the RP stub on :9090 first so the OP coordinator finds
	// the endpoint up the moment a logout fires.
	rpMux := http.NewServeMux()
	rpMux.HandleFunc("/backchannel-logout", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		log.Printf("RP received Logout Token (Content-Type=%s):\n%s",
			r.Header.Get("Content-Type"), body)
		// OIDC BCL 1.0 §2.8: respond 200 within the timeout, and the
		// OP records the delivery. Any non-2xx is logged as a delivery
		// failure on the OP side.
		w.WriteHeader(http.StatusOK)
	})
	go func() {
		log.Printf("RP stub listening on %s/backchannel-logout", rpAddr)
		if err := serve.Listen(rpAddr, rpMux); err != nil {
			log.Fatalf("RP listen: %v", err)
		}
	}()

	mux := http.NewServeMux()
	mux.Handle("/", provider)

	log.Printf("OP listening on %s — client %q registered with backchannel_logout_uri=http://127.0.0.1%s/backchannel-logout (dev-mode http loopback)",
		opAddr, clientID, rpAddr)
	log.Printf("demo user: username=%q password=%q", demoUsername, demoPassword)
	log.Println("drive /authorize → /token to seed a session, then call /oidc/end_session with the id_token_hint to fire delivery")
	if err := serve.Listen(opAddr, mux); err != nil {
		log.Fatalf("OP listen: %v", err)
	}
}

// seedUser materialises the demo subject whose session the logout
// delivery terminates. In a real deployment the user record comes from
// the embedder's identity backend.
func seedUser(st *inmem.Store) error {
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
