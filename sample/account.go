//go:build example

package main

import (
	"context"
	"crypto/rand"
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

// appSession is what the application remembers about a signed-in member.
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

func (s *sessions) put(id string, sess *appSession) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[id] = sess
}

func (s *sessions) drop(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, id)
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
	members  *memberStore
	sessions *sessions
	totp     totpEnrolment
	now      func() time.Time
	rpURL    string
	secure   bool
	logger   *slog.Logger
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
}

type signupForm struct {
	Email       string
	DisplayName string
}

func newAppUI(
	members *memberStore,
	sess *sessions,
	enrol totpEnrolment,
	now func() time.Time,
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
		now: now, rpURL: rpURL, secure: secure, logger: logger,
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

// render writes one page. A template failure is logged rather than
// surfaced, because by then the response is partially written.
func (a *appUI) render(w http.ResponseWriter, status int, name string, view pageView) {
	view.RPURL = a.rpURL
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "same-origin")
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'")
	w.WriteHeader(status)
	if err := a.tmpl.ExecuteTemplate(w, name, view); err != nil {
		a.logger.Error("render page", "template", name, "err", err)
	}
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
	a.render(w, http.StatusOK, "home", view)
}

func (a *appUI) signupForm(w http.ResponseWriter, _ *http.Request) {
	a.render(w, http.StatusOK, "signup", pageView{Title: "Create an account"})
}

// signupSubmit creates the account and signs the member in. Signing in
// immediately is what makes the arc continuous: the member goes straight
// from here to the relying party without a second credential prompt.
func (a *appUI) signupSubmit(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		a.render(w, http.StatusBadRequest, "signup",
			pageView{Title: "Create an account", Error: "That form could not be read."})
		return
	}
	form := signupForm{
		Email:       r.PostForm.Get("email"),
		DisplayName: r.PostForm.Get("display_name"),
	}
	password := r.PostForm.Get("password")
	if form.Email == "" || form.DisplayName == "" || len(password) < 8 {
		a.render(w, http.StatusBadRequest, "signup", pageView{
			Title: "Create an account", Form: form,
			Error: "Every field is required, and the password must be at least 8 characters.",
		})
		return
	}

	subject, err := a.members.signUp(r.Context(), form.Email, form.DisplayName, password, a.now())
	switch {
	case errors.Is(err, errEmailTaken):
		a.render(w, http.StatusConflict, "signup", pageView{
			Title: "Create an account", Form: form, Error: err.Error(),
		})
		return
	case err != nil:
		a.logger.Error("signup", "err", err)
		a.render(w, http.StatusInternalServerError, "signup", pageView{
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
	a.sessions.put(id, &appSession{Subject: subject, Expires: a.now().Add(12 * time.Hour)})
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
	if id, _ := a.current(r); id != "" {
		a.sessions.drop(id)
	}
	http.SetCookie(w, &http.Cookie{
		Name: appSessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// requireMember resolves the signed-in member or redirects to signup.
func (a *appUI) requireMember(w http.ResponseWriter, r *http.Request) (*appSession, *member, bool) {
	_, sess := a.current(r)
	if sess == nil {
		http.Redirect(w, r, "/signup", http.StatusSeeOther)
		return nil, nil, false
	}
	m, err := a.members.find(r.Context(), sess.Subject)
	if err != nil {
		a.logger.Error("load member", "err", err)
		http.Error(w, "account unavailable", http.StatusInternalServerError)
		return nil, nil, false
	}
	return sess, m, true
}

func (a *appUI) account(w http.ResponseWriter, r *http.Request) {
	_, m, ok := a.requireMember(w, r)
	if !ok {
		return
	}
	a.render(w, http.StatusOK, "account", pageView{Title: "Account", Member: m})
}

func (a *appUI) changePassword(w http.ResponseWriter, r *http.Request) {
	_, m, ok := a.requireMember(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		a.render(w, http.StatusBadRequest, "account",
			pageView{Title: "Account", Member: m, Error: "That form could not be read."})
		return
	}
	password := r.PostForm.Get("password")
	if len(password) < 8 {
		a.render(w, http.StatusBadRequest, "account", pageView{
			Title: "Account", Member: m,
			Error: "The password must be at least 8 characters.",
		})
		return
	}
	if err := a.members.changePassword(r.Context(), m.ID, password, a.now()); err != nil {
		a.logger.Error("change password", "err", err)
		a.render(w, http.StatusInternalServerError, "account", pageView{
			Title: "Account", Member: m, Error: "Something went wrong updating that password.",
		})
		return
	}
	a.render(w, http.StatusOK, "account", pageView{
		Title: "Account", Member: m, Notice: "Password updated.",
	})
}

// totpStart generates an enrolment and holds it in the session. Nothing is
// persisted yet: an enrolment that is never confirmed must not become a
// factor the next sign-in demands, or an abandoned setup locks the member
// out of their own account.
func (a *appUI) totpStart(w http.ResponseWriter, r *http.Request) {
	sess, m, ok := a.requireMember(w, r)
	if !ok {
		return
	}
	pending, err := totpkit.NewEnrolment(a.totp.codec, m.ID, a.totp.issuer, m.Email)
	if err != nil {
		a.logger.Error("totp enrolment", "err", err)
		a.render(w, http.StatusInternalServerError, "account", pageView{
			Title: "Account", Member: m, Error: "Could not start enrolment.",
		})
		return
	}
	sess.PendingTOTP = pending
	a.render(w, http.StatusOK, "enrol", pageView{
		Title:      "Set up two-factor",
		Member:     m,
		Secret:     pending.SecretBase32,
		OTPAuthURI: pending.OTPAuthURI,
	})
}

// totpConfirm verifies the first code and only then persists the factor.
func (a *appUI) totpConfirm(w http.ResponseWriter, r *http.Request) {
	sess, m, ok := a.requireMember(w, r)
	if !ok {
		return
	}
	if sess.PendingTOTP == nil {
		http.Redirect(w, r, "/account/totp", http.StatusSeeOther)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		a.render(w, http.StatusBadRequest, "account",
			pageView{Title: "Account", Member: m, Error: "That form could not be read."})
		return
	}
	record, err := totpkit.Confirm(a.totp.codec, sess.PendingTOTP, r.PostForm.Get("code"), a.now())
	if err != nil {
		a.render(w, http.StatusBadRequest, "enrol", pageView{
			Title:      "Set up two-factor",
			Member:     m,
			Secret:     sess.PendingTOTP.SecretBase32,
			OTPAuthURI: sess.PendingTOTP.OTPAuthURI,
			Error:      "That code was not accepted. Check your authenticator and try again.",
		})
		return
	}
	if err := a.totp.store.Put(r.Context(), record); err != nil {
		a.logger.Error("persist totp", "err", err)
		a.render(w, http.StatusInternalServerError, "account", pageView{
			Title: "Account", Member: m, Error: "Could not save that enrolment.",
		})
		return
	}
	sess.PendingTOTP = nil
	if err := a.members.setTOTPEnabled(r.Context(), m.ID, true, a.now()); err != nil {
		a.logger.Error("flag totp", "err", err)
	}
	m.TOTPEnabled = true
	a.render(w, http.StatusOK, "account", pageView{
		Title: "Account", Member: m,
		Notice: "Two-factor is on. Your next sign-in will ask for a code.",
	})
}
