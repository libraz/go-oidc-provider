//go:build example

// Example 42 demonstrates OpenID Connect Back-Channel Logout 1.0.
// When the OP terminates a session (RP-Initiated Logout via
// /end_session, or an admin tool calling Provider.Logout) it walks
// every client whose store.Client.BackchannelLogoutURI is non-empty
// and POSTs a signed Logout Token to that URL. Delivery is
// best-effort and parallel across RPs.
//
// Run with the example build tag:
//
//	go run -tags example ./examples/42-back-channel-logout
//
// The example boots two HTTP servers in the same process:
//
//   - :8080 — the OP, with one confidential client registered whose
//     backchannel_logout_uri points at the RP stub on :9090.
//   - :9090 — a tiny RP that prints every Logout Token it receives.
//
// To trigger a delivery, drive a normal authorize / token round-trip
// to establish a session, then hit /oidc/end_session with the
// id_token_hint. This example ships the wiring; the round-trip is
// out of scope (see example 02-bundle for an end-to-end driver).
//
// Wiring details:
//
//   - ConfidentialClient surfaces BackchannelLogoutURI and
//     BackchannelLogoutSessionRequired alongside the rest of the
//     spec-standard metadata, so the client lands through the typed
//     WithStaticClients seam without an embedder reaching into
//     store.ClientRegistry. PostLogoutRedirectURIs would join the
//     same shape if the example exercised RP-Initiated Logout
//     redirects.
//   - WithBackchannelLogoutHTTPClient is OPTIONAL — the package
//     default applies WithBackchannelLogoutTimeout to a fresh client
//     and refuses 3xx redirects on the POST. Override only when the
//     deployment ships a shared outbound transport.
//   - WithBackchannelLogoutTimeout caps the per-RP wait; a slow RP
//     does not delay deliveries to its peers.
//
// PRODUCTION CAVEATS: this example uses ephemeral keys, an in-memory
// store, and plain HTTP for both the OP and the RP. RFC 7592 / OIDC
// BCL 1.0 require https:// for backchannel_logout_uri in production
// (the validator enforces it on registration); the relaxed posture
// here is so a developer can run the demo without TLS scaffolding.
package main

import (
	"io"
	"log"
	"net/http"
	"time"

	"github.com/libraz/go-oidc-provider/examples/internal/devkeys"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

const (
	opAddr   = ":8080"
	rpAddr   = ":9090"
	clientID = "demo-rp"
)

func main() {
	keys := devkeys.MustEphemeral("bcl-1")

	provider, err := op.New(
		op.WithIssuer("http://localhost"+opAddr),
		op.WithStore(inmem.New()),
		op.WithKeyset(keys.Keyset()),
		op.WithCookieKey(keys.CookieKey),
		op.WithStaticClients(op.ConfidentialClient{
			ID:                               clientID,
			Secret:                           "rotate-me-via-secret-manager",
			RedirectURIs:                     []string{"http://localhost:5173/callback"},
			Scopes:                           []string{"openid", "profile"},
			BackchannelLogoutURI:             "http://localhost" + rpAddr + "/backchannel-logout",
			BackchannelLogoutSessionRequired: true,
			ApplicationType:                  "web",
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
		if err := http.ListenAndServe(rpAddr, rpMux); err != nil {
			log.Fatalf("RP listen: %v", err)
		}
	}()

	mux := http.NewServeMux()
	mux.Handle("/", provider)

	log.Printf("OP listening on %s — client %q registered with backchannel_logout_uri=http://localhost%s/backchannel-logout",
		opAddr, clientID, rpAddr)
	log.Println("drive /authorize → /token to seed a session, then call /oidc/end_session with the id_token_hint to fire delivery")
	if err := http.ListenAndServe(opAddr, mux); err != nil {
		log.Fatalf("OP listen: %v", err)
	}
}
