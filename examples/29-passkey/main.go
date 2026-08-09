//go:build example

// Example 29 covers the passkey lifecycle end to end: enrol a device on
// a page the embedder owns, then sign in with it through the OP.
//
// The two halves are deliberately on opposite sides of the library
// boundary. [op.PrimaryPasskey] performs the assertion during login and
// lives inside the OP's login flow; [op/passkeykit] performs the
// registration ceremony and is called from an ordinary HTTP handler this
// example writes itself. That split is not an omission. Registration has
// to happen on a page where the user is already signed in, and the OP
// has no view of the embedder's account management — so the library
// hands over the challenge and takes back a record, and the handler in
// between is yours.
//
// # The flow
//
// Password is the primary step. A rule adds the passkey step, but only
// for a subject that has one enrolled — a passkey step demanded of a
// user with no credential has nothing to assert against and would strand
// the login. Enrol a device and the same login gains a second factor;
// that transition is the thing this example exists to show.
//
// # What the library will not do for you
//
// **Authentication before enrolment is yours.** A registration endpoint
// reachable without a session lets an attacker add their own
// authenticator to someone else's account, which is a full account
// takeover with no password involved. passkeykit authenticates nobody:
// it registers whatever subject the handler names. Here the "already
// signed in" part is a password check against a constant, because the
// example has no account system of its own; in a real deployment it is
// whatever your account pages already use, and it must be at least as
// strong as the factor being added.
//
// **The ceremony session is yours to ferry.** The challenge and the
// finish call arrive on two separate requests, and the session that
// links them has to survive the gap. This example keeps it server-side
// in a map keyed by a random cookie value, which is the shape that needs
// no further reasoning: the browser holds an opaque identifier and
// cannot influence what the ceremony is bound to. A cookie carrying the
// session itself works too, but only if it is encrypted — see the
// package documentation.
//
// **Relying Party identity is shared, not duplicated.** The RP ID is
// bound into every credential at registration and re-checked at
// assertion, so a registration configured under a different RPID or
// origin list produces credentials that fail at first login, silently
// and much later. passkeykit.New takes the same op.PrimaryPasskey value
// the login flow installs, so the two cannot drift.
//
// # Why localhost and not 127.0.0.1
//
// Every other example binds 127.0.0.1. This one cannot: a WebAuthn RP ID
// must be a domain, and browsers reject an IP address. "localhost" is
// the one name that is both a valid RP ID and a secure context over
// plain HTTP, which is what makes a local demo possible at all.
//
// # Running
//
//	cd examples/29-passkey && GOWORK=off go run -tags example .
//
// Two listeners come up in the same process:
//
//   - :8080 — the OP, with the SPA bundle at /login and the enrolment
//     page at /account.
//   - :9090 — the RP, exposing /, /login, /callback, /me.
//
// Manual verification (needs a browser with a platform authenticator, or
// Chrome DevTools → WebAuthn → add a virtual authenticator):
//
//  1. Open http://localhost:8080/account and sign in as demo / demo.
//  2. Click "Register a passkey" and complete the browser prompt. The
//     page confirms the credential ID that was stored.
//  3. Open http://localhost:9090/ and click "Log in via the OP".
//  4. Sign in as demo / demo. The SPA now asks for the passkey — the
//     rule fired because a credential exists.
//  5. Approve the browser's passkey prompt, then approve consent; /me
//     shows the ID Token with "amr" containing "swk" and "mfa".
//
// Without step 1–2 the login is password-only, which is the same
// example demonstrating the rule from the other side.
//
// PRODUCTION CAVEATS:
//   - Keys: ephemeral; load from a vault / KMS in production.
//   - Store: in-memory; use op/storeadapter/sql or composite. A passkey record that does not survive a restart is a device the user has to enrol again.
//   - Listener: plain HTTP; front behind TLS-terminating ingress. WebAuthn requires a secure context everywhere except localhost.
//   - Enrolment auth: a password compared against a constant. Real deployments gate registration behind their existing session and re-authentication.
//   - Ceremony sessions: held in a process-local map that never expires entries early. A deployment with more than one instance needs shared storage, and should evict on the session's own expiry.
//   - RPOrigins: "http://localhost:8080" only. Enumerate every origin that terminates TLS for the OP, and nothing else — an extra entry is an extra page allowed to mint credentials.
package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/libraz/go-oidc-provider/examples/internal/devkeys"
	"github.com/libraz/go-oidc-provider/examples/internal/rpkit"
	"github.com/libraz/go-oidc-provider/examples/internal/seedkit"
	"github.com/libraz/go-oidc-provider/examples/internal/serve"
	"github.com/libraz/go-oidc-provider/examples/internal/webui"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/passkeykit"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

const (
	opAddr      = ":8080"
	rpAddr      = ":9090"
	issuer      = "http://localhost" + opAddr
	rpBase      = "http://localhost" + rpAddr
	clientID    = "demo-rp"
	redirectURI = rpBase + "/callback"

	// rpID is the WebAuthn Relying Party Identifier: the OP's effective
	// domain, with no scheme and no port. It is bound into every
	// credential, so changing it invalidates every device already
	// enrolled.
	rpID = "localhost"

	demoUsername = "demo"
	demoPassword = "demo"
	demoSubject  = "demo-user"

	// staticDir is the SPA bundle every example shares; accountDir is
	// this example's own — the enrolment page and the script that runs
	// the registration ceremony, which no other example has. The split
	// is the point: what is shared sits in one place, and what makes
	// this example different sits in its own directory.
	staticDir  = webui.StaticDir
	accountDir = "./web/account"

	// enrolCookie names the opaque handle to the server-side ceremony
	// session. It carries no ceremony state itself, so a browser that
	// tampers with it can only fail to find a session.
	enrolCookie = "enrol_sid"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	for _, dir := range []string{staticDir, accountDir} {
		if _, err := os.Stat(dir); err != nil {
			return errors.New("static directory " + dir + " missing — run from the example directory so both it and the shared SPA bundle resolve")
		}
	}

	keys := devkeys.MustEphemeral("passkey-1")
	st := inmem.New()
	ctx := context.Background()

	if _, err := seedkit.Seed(ctx, st, seedkit.SeedOptions{
		Subject:  demoSubject,
		Username: demoUsername,
		Password: demoPassword,
		Claims:   map[string]any{"name": "Demo User"},
	}); err != nil {
		return err
	}

	// One value, both ceremonies. The login flow below installs this
	// step; the enrolment handlers register against a passkeykit built
	// from the very same value, so the RP identity the credential is
	// bound to and the one it is later checked against are the same by
	// construction rather than by review.
	passkeys := op.PrimaryPasskey{
		Store:                 st.Passkeys(),
		RPID:                  rpID,
		RPDisplayName:         "Example Identity",
		RPOrigins:             []string{issuer},
		CloneDetectionHandler: logCloneWarning{},
	}

	registrar, err := passkeykit.New(passkeys)
	if err != nil {
		return err
	}

	flow := op.LoginFlow{
		Primary: op.PrimaryPassword{Store: st.UserPasswords()},
		Rules: []op.Rule{
			// The predicate is what makes this example runnable before
			// anything is enrolled. A passkey step demanded of a subject
			// with no registered credential has nothing to build an
			// assertion against, so the rule asks the store first. It is
			// also the honest shape for a real deployment: a factor the
			// user has not set up cannot be required of them.
			op.RuleWhen(hasPasskey(st.Passkeys()), passkeys),
		},
	}

	provider, err := op.New(
		op.WithIssuer(issuer),
		op.WithStore(st),
		op.WithKeyset(keys.Keyset()),
		op.WithCookieKeys(keys.CookieKey),
		op.WithLoginFlow(flow),
		// Both halves of this example need it. The issuer is
		// http://localhost:8080 and the RP's redirect_uri is on
		// localhost too, and neither is admitted by default: the
		// textual host can be DNS-hijacked, so the library restricts
		// plain http to IP literals. WebAuthn leaves no other option
		// locally — an RP ID must be a domain, and browsers reject an
		// IP. Production fronts the OP with TLS and this option comes
		// back off.
		op.WithAllowLocalhostLoopback(),
		op.WithSPAUI(op.SPAUI{
			LoginMount: "/login",
			StaticDir:  staticDir,
		}),
		op.WithStaticClients(op.PublicClient{
			ID:           clientID,
			RedirectURIs: []string{redirectURI},
			Scopes:       []string{"openid", "profile"},
		}),
	)
	if err != nil {
		return err
	}

	enrol := &enrolment{registrar: registrar, sessions: map[string]*passkeykit.Session{}}

	// The enrolment surface is mounted next to the OP rather than inside
	// it. It is the embedder's page: the OP neither renders it nor
	// guards it, and swapping it for a route in an existing account
	// service changes nothing about the library wiring.
	opMux := http.NewServeMux()
	opMux.HandleFunc("GET /account", serveAccountPage)
	opMux.Handle("GET /account/assets/", http.StripPrefix("/account", http.FileServer(http.Dir(accountDir))))
	opMux.HandleFunc("POST /account/register/begin", enrol.begin)
	opMux.HandleFunc("POST /account/register/finish", enrol.finish)
	opMux.Handle("/", provider)

	opErrCh := make(chan error, 1)
	go func() {
		log.Printf("OP listening on %s (issuer %s, SPA at /login, enrolment at /account)", opAddr, issuer)
		opErrCh <- serve.Listen(opAddr, opMux)
	}()

	waitCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := serve.WaitForIssuer(waitCtx, issuer); err != nil {
		return err
	}

	rp, err := rpkit.New(ctx, rpkit.Options{
		Issuer:      issuer,
		ClientID:    clientID,
		RedirectURL: redirectURI,
		Scopes:      []string{"openid", "profile"},
	})
	if err != nil {
		return err
	}

	rpMux := http.NewServeMux()
	rpMux.Handle("/", rp.Handler())

	log.Printf("RP listening on %s — open %s/", rpAddr, rpBase)
	log.Printf("enrol a passkey first at %s/account (username=%q password=%q)", issuer, demoUsername, demoPassword)

	rpErrCh := make(chan error, 1)
	go func() { rpErrCh <- serve.Listen(rpAddr, rpMux) }()

	select {
	case err := <-opErrCh:
		return err
	case err := <-rpErrCh:
		return err
	}
}

// hasPasskey builds the rule predicate that asks whether the subject
// established by the primary step has a credential to assert with.
//
// Predicates are synchronous and carry no context, which is the
// library's way of saying they are meant to read cheap in-memory state.
// A store lookup here is fine for a demo and would be a per-login round
// trip in production; a deployment that minds caches the answer on the
// user record the primary step already loaded.
func hasPasskey(passkeys store.PasskeyStore) func(op.LoginContext) bool {
	return func(lc op.LoginContext) bool {
		if lc.Identity.Subject == "" {
			return false
		}
		records, err := passkeys.ListBySubject(context.Background(), string(lc.Identity.Subject))
		if err != nil {
			// A store fault is not a reason to skip a factor: the safe
			// reading of "I cannot tell whether this user has a passkey"
			// is to demand it, and let the ceremony fail loudly.
			log.Printf("passkey lookup failed for %q: %v", string(lc.Identity.Subject), err)
			return true
		}
		return len(records) > 0
	}
}

// enrolment is the embedder-owned half of the lifecycle: two handlers
// and the short-lived state that links them.
type enrolment struct {
	registrar *passkeykit.Registrar

	mu       sync.Mutex
	sessions map[string]*passkeykit.Session
}

// begin authenticates the user, starts the ceremony, and hands the
// browser the creation options.
//
// The session goes into the server-side map and the browser gets only a
// random handle. That is the arrangement that makes the "integrity
// protected" requirement trivially satisfied: there is nothing in the
// cookie for an attacker to rewrite.
func (e *enrolment) begin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "malformed request")
		return
	}

	// Stand-in for the embedder's existing sign-in. A real account page
	// has a session by this point and does not re-collect a password —
	// or re-collects it deliberately, as re-authentication before adding
	// a factor.
	if !validDemoCredentials(body.Username, body.Password) {
		writeJSONError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	opts, session, err := e.registrar.Begin(r.Context(), passkeykit.User{
		Subject:     demoSubject,
		Name:        demoUsername,
		DisplayName: "Demo User",
	})
	if err != nil {
		log.Printf("passkey enrolment begin: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "could not start registration")
		return
	}

	sid, err := newSessionID()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "could not start registration")
		return
	}
	e.mu.Lock()
	e.sessions[sid] = session
	e.mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     enrolCookie,
		Value:    sid,
		Path:     "/account",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		// Secure is omitted only because the demo runs on plain HTTP
		// over localhost. Set it anywhere else.
		Expires: session.ExpiresAt(),
	})

	// Only the creation options go to the browser. The session is the
	// other return value precisely so it cannot end up here by accident.
	writeJSON(w, http.StatusOK, opts)
}

// finish verifies the browser's response and stores the credential.
func (e *enrolment) finish(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(enrolCookie)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "no registration in progress")
		return
	}

	// Take the session out of the map before using it. A ceremony
	// session is single-use, and the challenge it carries is the whole
	// replay defence — leaving it available for a second attempt would
	// undo the round trip that established it.
	e.mu.Lock()
	session := e.sessions[cookie.Value]
	delete(e.sessions, cookie.Value)
	e.mu.Unlock()
	if session == nil {
		writeJSONError(w, http.StatusBadRequest, "no registration in progress")
		return
	}

	response, err := io.ReadAll(io.LimitReader(r.Body, 16<<10))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "malformed request")
		return
	}

	record, err := e.registrar.Register(r.Context(), session, passkeykit.User{
		Subject:     demoSubject,
		Name:        demoUsername,
		DisplayName: "Demo User",
	}, response)
	switch {
	case errors.Is(err, passkeykit.ErrCredentialAlreadyExists):
		writeJSONError(w, http.StatusConflict, "that device is already registered")
		return
	case errors.Is(err, passkeykit.ErrChallengeExpired):
		writeJSONError(w, http.StatusBadRequest, "registration timed out — start again")
		return
	case err != nil:
		// The detail goes to the operator, not to the browser: it
		// describes what the authenticator got wrong, and the user can
		// do nothing with it but a probe can.
		log.Printf("passkey enrolment finish: %v", err)
		writeJSONError(w, http.StatusBadRequest, "registration failed")
		return
	}

	log.Printf("registered passkey %s for %s", base64.RawURLEncoding.EncodeToString(record.CredentialID), record.Subject)
	writeJSON(w, http.StatusOK, map[string]any{
		"credential_id": base64.RawURLEncoding.EncodeToString(record.CredentialID),
	})
}

// validDemoCredentials compares against the seeded constants in constant
// time. It is not a password verifier; it is the smallest thing that
// stands where a real deployment's session check goes.
func validDemoCredentials(username, password string) bool {
	u := subtle.ConstantTimeCompare([]byte(username), []byte(demoUsername))
	p := subtle.ConstantTimeCompare([]byte(password), []byte(demoPassword))
	return u&p == 1
}

// newSessionID mints the opaque handle the enrolment cookie carries.
func newSessionID() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// logCloneWarning is the demo's [op.PasskeyCloneDetectionHandler]. The
// signal means an authenticator replayed a signature counter, which is
// what a duplicated device looks like from the OP's side. A deployment
// disables the credential and tells the user; printing it is the least
// a demo can do without pretending to a policy it does not have.
type logCloneWarning struct{}

func (logCloneWarning) HandleCloneDetected(_ context.Context, subject string, credentialID []byte, signCount uint32) error {
	log.Printf("CLONE WARNING: subject=%s credential=%s signCount=%d",
		subject, base64.RawURLEncoding.EncodeToString(credentialID), signCount)
	return nil
}

// serveAccountPage serves the embedder's enrolment page. It is a plain
// file because nothing about it belongs to the library — the OP has no
// account surface and never renders one.
func serveAccountPage(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, accountDir+"/account.html")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": msg})
}
