//go:build example

package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/libraz/go-oidc-provider/op/totpkit"
)

// maxFormBytes caps what the application's own forms may submit. The OP's
// interaction endpoint applies its own bound; this one covers signup,
// password change, and enrolment, which are reachable without an
// interaction and therefore need their own ceiling.
const maxFormBytes = 32 << 10

// appSessionCookie is the application's own session cookie. It is separate
// from the OP's session cookie by design: the library never touches this
// one, and signing out of the application does not by itself end the OP
// session. Keeping the two distinct is what lets an embedder own its
// session model.
const appSessionCookie = "sample_session"

// appCSRFCookie is one half of the double-submit pair guarding the
// application's own POSTs. The OP defends its interaction endpoint; the
// pages outside that flow are the embedder's to defend, and SameSite=Lax
// alone is a browser-version-dependent defence rather than one this
// application states and enforces.
//
// The cookie is HttpOnly because nothing on the page reads it: the
// server renders the matching hidden field itself.
const appCSRFCookie = "sample_csrf"

// csrfField is the form field carrying the other half of the pair. It is
// the same name the OP's interaction forms use, which keeps one CSRF
// vocabulary across every form the process serves.
const csrfField = "csrf_token"

// appSession is what the application remembers about a signed-in member.
//
// Every field is reached through the [sessions] methods below rather than
// through the pointer get hands back: two tabs on the enrolment page are
// two requests writing the same struct, and a demonstration that races
// there is teaching the race.
type appSession struct {
	Subject string
	// PendingTOTP holds an enrolment between the page that shows the
	// secret and the page that confirms it. It stays server-side rather
	// than riding a hidden form field so the sealed secret never reaches
	// the browser, and so an abandoned enrolment expires with the session
	// instead of lingering as a half-configured factor.
	PendingTOTP *totpkit.Pending
	Expires     time.Time
}

// sessions is an in-process session store. A deployment running more than
// one instance moves this to shared storage; it is in memory here because
// the application's session design is the embedder's to make and this is
// the smallest choice that does not distract from the OP wiring. The OP's
// own sessions are in Redis, which is the part that matters for the
// library's behaviour.
type sessions struct {
	mu sync.Mutex
	m  map[string]*appSession
}

// sessionSweepAt is the size at which put reclaims expired sessions. get
// drops a session it finds expired, but a session nobody comes back for
// is never looked up again, so without this the map only grows. A
// deployment holding sessions in a store gets the expiry from the store;
// an in-process map has to do it somewhere, and the insert path is where
// the pressure is.
const sessionSweepAt = 1024

func newSessions() *sessions {
	return &sessions{m: make(map[string]*appSession)}
}

func (s *sessions) get(id string, now time.Time) *appSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.m[id]
	if !ok {
		return nil
	}
	if now.After(sess.Expires) {
		delete(s.m, id)
		return nil
	}
	return sess
}

func (s *sessions) put(id string, sess *appSession, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.m) >= sessionSweepAt {
		for key, held := range s.m {
			if now.After(held.Expires) {
				delete(s.m, key)
			}
		}
	}
	s.m[id] = sess
}

func (s *sessions) drop(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, id)
}

// setPendingTOTP records an enrolment in progress.
func (s *sessions) setPendingTOTP(id string, pending *totpkit.Pending) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess, ok := s.m[id]; ok {
		sess.PendingTOTP = pending
	}
}

// takePendingTOTP returns the enrolment in progress and clears it, so a
// submitted code consumes it. Reading and clearing under one lock is also
// what stops two concurrent confirmations from both persisting the
// factor; the caller puts the enrolment back when the code was wrong, so
// the member retries against the secret they already scanned.
func (s *sessions) takePendingTOTP(id string) *totpkit.Pending {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.m[id]
	if !ok {
		return nil
	}
	pending := sess.PendingTOTP
	sess.PendingTOTP = nil
	return pending
}

// newOpaqueID returns a 256-bit random identifier for session and subject
// values. Both are handed out to callers, so neither may be guessable.
func newOpaqueID() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// appUI serves the application's own pages — everything outside the OP's
// interaction flow.
type appUI struct {
	tmpl     *template.Template
	members  memberDirectory
	sessions *sessions
	totp     totpEnrolment
	now      func() time.Time
	// origin is this application's own scheme://host, which every
	// state-changing POST must name in its Origin header.
	origin string
	rpURL  string
	secure bool
	logger *slog.Logger
}

// memberDirectory is the slice of the application's account table these
// pages use, stated as an interface for the same reason totpStore below
// is one: the pages are the part worth reading, and narrowing what they
// reach keeps the account table's other columns out of them.
type memberDirectory interface {
	find(ctx context.Context, subject string) (*member, error)
	signUp(ctx context.Context, email, displayName, password string, now time.Time) (string, error)
	verifyPassword(ctx context.Context, subject, password string) error
	changePassword(ctx context.Context, subject, password string, now time.Time) error
	setTOTPEnabled(ctx context.Context, subject string, enabled bool, now time.Time) error
}

// totpEnrolment is the slice of TOTP wiring the account pages need: the
// codec that seals secrets and the substore that persists confirmed
// enrolments.
type totpEnrolment struct {
	codec  *totpkit.Codec
	store  totpStore
	issuer string
}

// totpStore is the subset of store.TOTPStore the account pages use.
type totpStore interface {
	Put(ctx context.Context, r *totpRecord) error
}

// pageView is the context the application's templates render against.
type pageView struct {
	Title      string
	Error      string
	Notice     string
	Member     *member
	Form       signupForm
	RPURL      string
	Secret     string
	OTPAuthURI string
	Pending    string
	CSRFToken  string
}

type signupForm struct {
	Email       string
	DisplayName string
}

func newAppUI(
	members memberDirectory,
	sess *sessions,
	enrol totpEnrolment,
	now func() time.Time,
	origin string,
	rpURL string,
	secure bool,
	logger *slog.Logger,
) (*appUI, error) {
	tmpl, err := template.New("app").Parse(appTemplates)
	if err != nil {
		return nil, err
	}
	return &appUI{
		tmpl: tmpl, members: members, sessions: sess, totp: enrol,
		now: now, origin: origin, rpURL: rpURL, secure: secure, logger: logger,
	}, nil
}

// routes mounts the application's pages. The OP handler is mounted
// separately by the caller; nothing here overlaps its routes.
func (a *appUI) routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /{$}", a.home)
	mux.HandleFunc("GET /signup", a.signupForm)
	mux.HandleFunc("POST /signup", a.signupSubmit)
	mux.HandleFunc("GET /account", a.account)
	mux.HandleFunc("POST /account/password", a.changePassword)
	mux.HandleFunc("GET /account/totp", a.totpStart)
	mux.HandleFunc("POST /account/totp", a.totpConfirm)
	mux.HandleFunc("POST /signout", a.signOut)
	mux.HandleFunc("GET /assets/app.css", a.stylesheet)
}

func (a *appUI) stylesheet(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write([]byte(appCSS))
}

// render writes one page. It also issues the CSRF token every form on
// that page echoes back, so a page cannot be added without one. A
// template failure is logged rather than surfaced, because by then the
// response is partially written.
func (a *appUI) render(w http.ResponseWriter, r *http.Request, status int, name string, view pageView) {
	view.RPURL = a.rpURL
	view.CSRFToken = a.issueCSRFToken(w, r)
	stampHeaders(w)
	w.WriteHeader(status)
	if err := a.tmpl.ExecuteTemplate(w, name, view); err != nil {
		a.logger.Error("render page", "template", name, "err", err)
	}
}

// issueCSRFToken returns the token this browser's forms carry, minting
// and setting one when the request arrives without it. The token is per
// browser rather than per form: it is the value the cookie half of the
// double-submit pair is compared against, and rotating it per page would
// invalidate a form the member left open in another tab.
func (a *appUI) issueCSRFToken(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(appCSRFCookie); err == nil && c.Value != "" {
		return c.Value
	}
	token, err := newOpaqueID()
	if err != nil {
		// Rendering a page with no token leaves every form on it
		// unsubmittable, which is the safe direction: the alternative is
		// a form that posts without the defence.
		a.logger.Error("mint csrf token", "err", err)
		return ""
	}
	//nolint:gosec // G124: Secure is configuration-driven rather than a literal, which the rule cannot follow.
	http.SetCookie(w, &http.Cookie{
		Name:     appCSRFCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   a.secure,
		SameSite: http.SameSiteLaxMode,
	})
	return token
}

// checkCSRF gates every state-changing POST the application serves. It
// runs two independent checks and requires both:
//
//   - The Origin header must name this application. A browser sends it on
//     every POST, so an absent header is a request no form this
//     application served produced.
//   - The submitted csrf_token must equal the cookie's, which a cross-site
//     page cannot read.
//
// SameSite=Lax on the session cookie already stops a cross-site POST in a
// current browser. It is not stated anywhere in the request, though, so
// it is a property of whoever is browsing rather than a defence this
// application applies — which is why it is not the only one here.
//
// The caller must have parsed the form already.
func (a *appUI) checkCSRF(r *http.Request) bool {
	if r.Header.Get("Origin") != a.origin {
		return false
	}
	c, err := r.Cookie(appCSRFCookie)
	if err != nil || c.Value == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(c.Value), []byte(r.PostForm.Get(csrfField))) == 1
}

// current returns the signed-in member, or nil.
func (a *appUI) current(r *http.Request) (string, *appSession) {
	c, err := r.Cookie(appSessionCookie)
	if err != nil {
		return "", nil
	}
	sess := a.sessions.get(c.Value, a.now())
	if sess == nil {
		return "", nil
	}
	return c.Value, sess
}

func (a *appUI) home(w http.ResponseWriter, r *http.Request) {
	view := pageView{Title: "go-oidc-provider sample"}
	if _, sess := a.current(r); sess != nil {
		if m, err := a.members.find(r.Context(), sess.Subject); err == nil {
			view.Member = m
		}
	}
	a.render(w, r, http.StatusOK, "home", view)
}

func (a *appUI) signupForm(w http.ResponseWriter, r *http.Request) {
	a.render(w, r, http.StatusOK, "signup", pageView{Title: "Create an account"})
}

// signupSubmit creates the account and signs the member in. Signing in
// immediately is what makes the arc continuous: the member goes straight
// from here to the relying party without a second credential prompt.
func (a *appUI) signupSubmit(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		a.render(w, r, http.StatusBadRequest, "signup",
			pageView{Title: "Create an account", Error: "That form could not be read."})
		return
	}
	if !a.checkCSRF(r) {
		http.Error(w, "that request did not come from this application", http.StatusForbidden)
		return
	}
	form := signupForm{
		Email:       r.PostForm.Get("email"),
		DisplayName: r.PostForm.Get("display_name"),
	}
	password := r.PostForm.Get("password")
	if form.Email == "" || form.DisplayName == "" || len(password) < 8 {
		a.render(w, r, http.StatusBadRequest, "signup", pageView{
			Title: "Create an account", Form: form,
			Error: "Every field is required, and the password must be at least 8 characters.",
		})
		return
	}

	subject, err := a.members.signUp(r.Context(), form.Email, form.DisplayName, password, a.now())
	switch {
	case errors.Is(err, errEmailTaken):
		a.render(w, r, http.StatusConflict, "signup", pageView{
			Title: "Create an account", Form: form, Error: err.Error(),
		})
		return
	case err != nil:
		a.logger.Error("signup", "err", err)
		a.render(w, r, http.StatusInternalServerError, "signup", pageView{
			Title: "Create an account", Form: form,
			Error: "Something went wrong creating that account.",
		})
		return
	}
	if err := a.startSession(w, subject); err != nil {
		a.logger.Error("start session", "err", err)
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/account", http.StatusSeeOther)
}

// startSession issues the application's session cookie. Secure is set from
// configuration rather than hardcoded so the loopback demo works over
// plain http while a TLS deployment gets the flag.
func (a *appUI) startSession(w http.ResponseWriter, subject string) error {
	id, err := newOpaqueID()
	if err != nil {
		return err
	}
	now := a.now()
	a.sessions.put(id, &appSession{Subject: subject, Expires: now.Add(12 * time.Hour)}, now)
	//nolint:gosec // G124: Secure is configuration-driven rather than a literal, which the rule cannot follow.
	http.SetCookie(w, &http.Cookie{
		Name:     appSessionCookie,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		Secure:   a.secure,
		SameSite: http.SameSiteLaxMode,
	})
	return nil
}

func (a *appUI) signOut(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil || !a.checkCSRF(r) {
		http.Error(w, "that request did not come from this application", http.StatusForbidden)
		return
	}
	if id, _ := a.current(r); id != "" {
		a.sessions.drop(id)
	}
	//nolint:gosec // G124: Secure is configuration-driven rather than a literal, which the rule cannot follow.
	http.SetCookie(w, &http.Cookie{
		Name: appSessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// requireMember resolves the signed-in member or redirects to signup. It
// returns the session identifier rather than the session itself, so the
// caller reaches session state through the store's methods.
func (a *appUI) requireMember(w http.ResponseWriter, r *http.Request) (string, *member, bool) {
	id, sess := a.current(r)
	if sess == nil {
		http.Redirect(w, r, "/signup", http.StatusSeeOther)
		return "", nil, false
	}
	m, err := a.members.find(r.Context(), sess.Subject)
	if err != nil {
		a.logger.Error("load member", "err", err)
		http.Error(w, "account unavailable", http.StatusInternalServerError)
		return "", nil, false
	}
	return id, m, true
}

func (a *appUI) account(w http.ResponseWriter, r *http.Request) {
	_, m, ok := a.requireMember(w, r)
	if !ok {
		return
	}
	a.render(w, r, http.StatusOK, "account", pageView{Title: "Account", Member: m})
}

// reauthenticate reads the current_password field and checks it against
// the member's stored hash.
//
// Every credential change goes through it. The session cookie alone says
// only that this browser signed in at some point in the last twelve
// hours, and both operations behind it replace a credential: a password
// change locks the member out, and confirming a fresh TOTP enrolment
// overwrites whatever second factor was there. Without this, one stolen
// cookie is the whole of an account takeover.
func (a *appUI) reauthenticate(r *http.Request, subject string) bool {
	current := r.PostForm.Get("current_password")
	if current == "" {
		return false
	}
	switch err := a.members.verifyPassword(r.Context(), subject, current); {
	case err == nil:
		return true
	case errors.Is(err, errPasswordMismatch):
		return false
	default:
		// A backend fault resolves toward refusing the change: the
		// alternative is letting a credential be replaced while the store
		// that holds the old one is unreachable.
		a.logger.Error("verify current password", "err", err)
		return false
	}
}

func (a *appUI) changePassword(w http.ResponseWriter, r *http.Request) {
	_, m, ok := a.requireMember(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		a.render(w, r, http.StatusBadRequest, "account",
			pageView{Title: "Account", Member: m, Error: "That form could not be read."})
		return
	}
	if !a.checkCSRF(r) {
		http.Error(w, "that request did not come from this application", http.StatusForbidden)
		return
	}
	password := r.PostForm.Get("password")
	if len(password) < 8 {
		a.render(w, r, http.StatusBadRequest, "account", pageView{
			Title: "Account", Member: m,
			Error: "The password must be at least 8 characters.",
		})
		return
	}
	if !a.reauthenticate(r, m.ID) {
		a.render(w, r, http.StatusForbidden, "account", pageView{
			Title: "Account", Member: m,
			Error: "That is not your current password.",
		})
		return
	}
	if err := a.members.changePassword(r.Context(), m.ID, password, a.now()); err != nil {
		a.logger.Error("change password", "err", err)
		a.render(w, r, http.StatusInternalServerError, "account", pageView{
			Title: "Account", Member: m, Error: "Something went wrong updating that password.",
		})
		return
	}
	a.render(w, r, http.StatusOK, "account", pageView{
		Title: "Account", Member: m, Notice: "Password updated.",
	})
}

// totpStart generates an enrolment and holds it in the session. Nothing is
// persisted yet: an enrolment that is never confirmed must not become a
// factor the next sign-in demands, or an abandoned setup locks the member
// out of their own account.
func (a *appUI) totpStart(w http.ResponseWriter, r *http.Request) {
	sessID, m, ok := a.requireMember(w, r)
	if !ok {
		return
	}
	pending, err := totpkit.NewEnrolment(a.totp.codec, m.ID, a.totp.issuer, m.Email)
	if err != nil {
		a.logger.Error("totp enrolment", "err", err)
		a.render(w, r, http.StatusInternalServerError, "account", pageView{
			Title: "Account", Member: m, Error: "Could not start enrolment.",
		})
		return
	}
	a.sessions.setPendingTOTP(sessID, pending)
	a.render(w, r, http.StatusOK, "enrol", pageView{
		Title:      "Set up two-factor",
		Member:     m,
		Secret:     pending.SecretBase32,
		OTPAuthURI: pending.OTPAuthURI,
	})
}

// totpConfirm verifies the first code and only then persists the factor.
// Confirming replaces whatever second factor the account already had, so
// it asks for the password the same way a password change does.
func (a *appUI) totpConfirm(w http.ResponseWriter, r *http.Request) {
	sessID, m, ok := a.requireMember(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		a.render(w, r, http.StatusBadRequest, "account",
			pageView{Title: "Account", Member: m, Error: "That form could not be read."})
		return
	}
	if !a.checkCSRF(r) {
		http.Error(w, "that request did not come from this application", http.StatusForbidden)
		return
	}
	pending := a.sessions.takePendingTOTP(sessID)
	if pending == nil {
		http.Redirect(w, r, "/account/totp", http.StatusSeeOther)
		return
	}
	if !a.reauthenticate(r, m.ID) {
		a.sessions.setPendingTOTP(sessID, pending)
		a.render(w, r, http.StatusForbidden, "enrol", pageView{
			Title:      "Set up two-factor",
			Member:     m,
			Secret:     pending.SecretBase32,
			OTPAuthURI: pending.OTPAuthURI,
			Error:      "That is not your current password.",
		})
		return
	}
	record, err := totpkit.Confirm(a.totp.codec, pending, r.PostForm.Get("code"), a.now())
	if err != nil {
		// The enrolment goes back so the member retries the code against
		// the secret they already scanned rather than a fresh one.
		a.sessions.setPendingTOTP(sessID, pending)
		a.render(w, r, http.StatusBadRequest, "enrol", pageView{
			Title:      "Set up two-factor",
			Member:     m,
			Secret:     pending.SecretBase32,
			OTPAuthURI: pending.OTPAuthURI,
			Error:      "That code was not accepted. Check your authenticator and try again.",
		})
		return
	}
	if err := a.totp.store.Put(r.Context(), record); err != nil {
		a.logger.Error("persist totp", "err", err)
		a.sessions.setPendingTOTP(sessID, pending)
		a.render(w, r, http.StatusInternalServerError, "account", pageView{
			Title: "Account", Member: m, Error: "Could not save that enrolment.",
		})
		return
	}
	if err := a.members.setTOTPEnabled(r.Context(), m.ID, true, a.now()); err != nil {
		a.logger.Error("flag totp", "err", err)
	}
	m.TOTPEnabled = true
	a.render(w, r, http.StatusOK, "account", pageView{
		Title: "Account", Member: m,
		Notice: "Two-factor is on. Your next sign-in will ask for a code.",
	})
}
