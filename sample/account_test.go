//go:build example

package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/totpkit"
)

// testOrigin is the scheme://host the application under test is served
// from. Every state-changing POST has to name it.
const testOrigin = "https://sample.test"

// fakeMembers stands in for the application's account table. The table is
// MySQL-only, and what these tests drive is the pages rather than the SQL,
// so the pages run against the same narrow contract main.go wires the real
// store into.
//
// Passwords are held in plaintext here. The real store keeps the PHC
// encoding and compares through matchPasswordHash, which
// TestMatchPasswordHash covers against a hash op.HashPassword produced.
type fakeMembers struct {
	mu        sync.Mutex
	records   map[string]*member
	passwords map[string]string
}

func newFakeMembers() *fakeMembers {
	return &fakeMembers{records: map[string]*member{}, passwords: map[string]string{}}
}

// seed registers one account and returns its subject.
func (f *fakeMembers) seed(subject, email, password string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records[subject] = &member{ID: subject, Email: email, DisplayName: email}
	f.passwords[subject] = password
	return subject
}

func (f *fakeMembers) password(subject string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.passwords[subject]
}

func (f *fakeMembers) find(_ context.Context, subject string) (*member, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, ok := f.records[subject]
	if !ok {
		return nil, errors.New("no such member")
	}
	clone := *m
	return &clone, nil
}

func (f *fakeMembers) signUp(_ context.Context, email, displayName, password string, _ time.Time) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	subject := "sub-" + normaliseEmail(email)
	if _, taken := f.records[subject]; taken {
		return "", errEmailTaken
	}
	f.records[subject] = &member{ID: subject, Email: normaliseEmail(email), DisplayName: displayName}
	f.passwords[subject] = password
	return subject, nil
}

func (f *fakeMembers) verifyPassword(_ context.Context, subject, password string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	stored, ok := f.passwords[subject]
	if !ok || stored != password {
		return errPasswordMismatch
	}
	return nil
}

func (f *fakeMembers) changePassword(_ context.Context, subject, password string, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.passwords[subject] = password
	return nil
}

func (f *fakeMembers) setTOTPEnabled(_ context.Context, subject string, enabled bool, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if m, ok := f.records[subject]; ok {
		m.TOTPEnabled = enabled
	}
	return nil
}

// recordingTOTPs accepts confirmed enrolments and counts them.
type recordingTOTPs struct {
	mu    sync.Mutex
	count int
}

func (r *recordingTOTPs) Put(_ context.Context, _ *totpRecord) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.count++
	return nil
}

func newTestAppUI(t *testing.T, members memberDirectory, totps totpStore) *appUI {
	t.Helper()
	codec, err := totpkit.NewCodec(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatalf("totpkit.NewCodec: %v", err)
	}
	ui, err := newAppUI(members, newSessions(),
		totpEnrolment{codec: codec, store: totps, issuer: "sample"},
		time.Now, testOrigin, "https://rp.test", false,
		slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("newAppUI: %v", err)
	}
	return ui
}

// signedIn issues an application session and the CSRF token its forms
// carry, without going through signup.
func signedIn(t *testing.T, ui *appUI, subject string) (sessionID, csrfToken string) {
	t.Helper()
	sessionID, err := newOpaqueID()
	if err != nil {
		t.Fatalf("newOpaqueID: %v", err)
	}
	csrfToken, err = newOpaqueID()
	if err != nil {
		t.Fatalf("newOpaqueID: %v", err)
	}
	now := ui.now()
	ui.sessions.put(sessionID, &appSession{Subject: subject, Expires: now.Add(time.Hour)}, now)
	return sessionID, csrfToken
}

// appPost builds one authenticated POST carrying both halves of the
// double-submit pair. origin is passed explicitly so a test can send a
// request that names a different one.
func appPost(t *testing.T, path, origin, sessionID, csrfToken string, form url.Values) *http.Request {
	t.Helper()
	form.Set(csrfField, csrfToken)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, path,
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", origin)
	req.AddCookie(&http.Cookie{Name: appSessionCookie, Value: sessionID})
	req.AddCookie(&http.Cookie{Name: appCSRFCookie, Value: csrfToken})
	return req
}

// TestChangePasswordRequiresCurrentPassword pins the re-authentication.
// The session cookie says only that this browser signed in at some point
// in the last twelve hours; without a second check on the credential
// being replaced, whoever holds that cookie owns the account.
func TestChangePasswordRequiresCurrentPassword(t *testing.T) {
	t.Parallel()

	members := newFakeMembers()
	subject := members.seed("member-1", "member@example.com", "correct-horse")
	ui := newTestAppUI(t, members, &recordingTOTPs{})
	sessionID, token := signedIn(t, ui, subject)

	for _, tc := range []struct {
		name    string
		current string
	}{
		{"wrong password", "not-the-password"},
		{"no password at all", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rec := httptest.NewRecorder()
			ui.changePassword(rec, appPost(t, "/account/password", testOrigin, sessionID, token, url.Values{
				"current_password": {tc.current},
				"password":         {"a-brand-new-password"},
			}))

			if rec.Code != http.StatusForbidden {
				t.Errorf("status = %d, want 403; body = %q", rec.Code, rec.Body.String())
			}
			if got := members.password(subject); got != "correct-horse" {
				t.Errorf("password is now %q; the change went through without the current one", got)
			}
		})
	}
}

// TestChangePasswordAcceptsCurrentPassword is the control: the same
// request with the right current password does change it.
func TestChangePasswordAcceptsCurrentPassword(t *testing.T) {
	t.Parallel()

	members := newFakeMembers()
	subject := members.seed("member-1", "member@example.com", "correct-horse")
	ui := newTestAppUI(t, members, &recordingTOTPs{})
	sessionID, token := signedIn(t, ui, subject)

	rec := httptest.NewRecorder()
	ui.changePassword(rec, appPost(t, "/account/password", testOrigin, sessionID, token, url.Values{
		"current_password": {"correct-horse"},
		"password":         {"a-brand-new-password"},
	}))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %q", rec.Code, rec.Body.String())
	}
	if got := members.password(subject); got != "a-brand-new-password" {
		t.Errorf("password = %q, want the new one", got)
	}
}

// TestStateChangingPostsRejectForeignOrigin covers the CSRF gate on every
// POST the application serves. SameSite=Lax stops a cross-site POST in a
// current browser, but that is a property of whoever is browsing rather
// than one this application states, so each of these has to refuse on its
// own.
func TestStateChangingPostsRejectForeignOrigin(t *testing.T) {
	t.Parallel()

	members := newFakeMembers()
	subject := members.seed("member-1", "member@example.com", "correct-horse")

	for _, tc := range []struct {
		name    string
		path    string
		handler func(*appUI) http.HandlerFunc
		form    url.Values
	}{
		{
			name:    "change password",
			path:    "/account/password",
			handler: func(a *appUI) http.HandlerFunc { return a.changePassword },
			form:    url.Values{"current_password": {"correct-horse"}, "password": {"a-brand-new-password"}},
		},
		{
			name:    "confirm two-factor",
			path:    "/account/totp",
			handler: func(a *appUI) http.HandlerFunc { return a.totpConfirm },
			form:    url.Values{"current_password": {"correct-horse"}, "code": {"000000"}},
		},
		{
			name:    "sign up",
			path:    "/signup",
			handler: func(a *appUI) http.HandlerFunc { return a.signupSubmit },
			form: url.Values{
				"email": {"new@example.com"}, "display_name": {"New"}, "password": {"long-enough"},
			},
		},
		{
			name:    "sign out",
			path:    "/signout",
			handler: func(a *appUI) http.HandlerFunc { return a.signOut },
			form:    url.Values{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ui := newTestAppUI(t, members, &recordingTOTPs{})
			sessionID, token := signedIn(t, ui, subject)

			rec := httptest.NewRecorder()
			tc.handler(ui)(rec, appPost(t, tc.path, "https://attacker.example", sessionID, token, tc.form))
			if rec.Code != http.StatusForbidden {
				t.Errorf("cross-origin POST status = %d, want 403; body = %q", rec.Code, rec.Body.String())
			}

			rec = httptest.NewRecorder()
			req := appPost(t, tc.path, testOrigin, sessionID, token, tc.form)
			// A same-origin request whose form omits the token is the
			// other half of the pair, and must fail the same way.
			req.Body = http.NoBody
			req.ContentLength = 0
			tc.handler(ui)(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Errorf("tokenless POST status = %d, want 403; body = %q", rec.Code, rec.Body.String())
			}
		})
	}
}

// TestRenderedFormsCarryCSRFToken pins the other end of the gate: the
// pages have to hand the browser the token their own handlers demand.
func TestRenderedFormsCarryCSRFToken(t *testing.T) {
	t.Parallel()

	members := newFakeMembers()
	subject := members.seed("member-1", "member@example.com", "correct-horse")
	ui := newTestAppUI(t, members, &recordingTOTPs{})
	sessionID, _ := signedIn(t, ui, subject)

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/account", nil)
	req.AddCookie(&http.Cookie{Name: appSessionCookie, Value: sessionID})
	ui.account(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	token := ""
	for _, c := range rec.Result().Cookies() {
		if c.Name == appCSRFCookie {
			token = c.Value
		}
	}
	if token == "" {
		t.Fatal("the page set no CSRF cookie, so nothing it renders can be submitted")
	}
	if !strings.Contains(rec.Body.String(), `name="csrf_token" value="`+token+`"`) {
		t.Errorf("the change-password form does not echo the cookie's token:\n%s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `name="current_password"`) {
		t.Errorf("the change-password form does not ask for the current password:\n%s", rec.Body.String())
	}
}

// TestTOTPConfirmRequiresCurrentPassword covers the second credential the
// account page can replace. totpStore.Put overwrites, so confirming a
// fresh enrolment replaces whatever second factor was already there.
func TestTOTPConfirmRequiresCurrentPassword(t *testing.T) {
	t.Parallel()

	members := newFakeMembers()
	subject := members.seed("member-1", "member@example.com", "correct-horse")
	totps := &recordingTOTPs{}
	ui := newTestAppUI(t, members, totps)
	sessionID, token := signedIn(t, ui, subject)

	// Start an enrolment so the confirmation has something to consume.
	startRec := httptest.NewRecorder()
	startReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/account/totp", nil)
	startReq.AddCookie(&http.Cookie{Name: appSessionCookie, Value: sessionID})
	ui.totpStart(startRec, startReq)
	if startRec.Code != http.StatusOK {
		t.Fatalf("totpStart status = %d, want 200", startRec.Code)
	}

	rec := httptest.NewRecorder()
	ui.totpConfirm(rec, appPost(t, "/account/totp", testOrigin, sessionID, token, url.Values{
		"current_password": {"not-the-password"},
		"code":             {"000000"},
	}))

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403; body = %q", rec.Code, rec.Body.String())
	}
	totps.mu.Lock()
	defer totps.mu.Unlock()
	if totps.count != 0 {
		t.Errorf("%d enrolment(s) were persisted without the current password", totps.count)
	}
}

// TestMatchPasswordHash exercises the verifier against an encoding the
// library actually produced, which is the part the fake member store
// above stands in for.
func TestMatchPasswordHash(t *testing.T) {
	t.Parallel()

	hash, err := op.HashPassword("correct-horse")
	if err != nil {
		t.Fatalf("op.HashPassword: %v", err)
	}
	if err := matchPasswordHash("correct-horse", string(hash)); err != nil {
		t.Errorf("matchPasswordHash on the right password: %v", err)
	}
	for _, tc := range []struct {
		name     string
		password string
		encoded  string
	}{
		{"wrong password", "correct-hors", string(hash)},
		{"empty record", "correct-horse", ""},
		{"truncated record", "correct-horse", "$argon2id$v=19$m=65536,t=3,p=1$c2FsdA"},
		{"foreign scheme", "correct-horse", "$bcrypt$v=19$m=65536,t=3,p=1$c2FsdA$aGFzaA"},
	} {
		if err := matchPasswordHash(tc.password, tc.encoded); !errors.Is(err, errPasswordMismatch) {
			t.Errorf("%s: err = %v, want errPasswordMismatch", tc.name, err)
		}
	}
}

// TestSessionsPutReclaimsExpired pins that a session nobody comes back
// for is reclaimed. get drops the ones it is asked about, but an expired
// session is by definition one that is never looked up again, so without
// reclamation on insert the map only grows.
func TestSessionsPutReclaimsExpired(t *testing.T) {
	t.Parallel()

	s := newSessions()
	now := time.Now()
	expired := now.Add(-time.Hour)
	for i := range sessionSweepAt * 2 {
		s.put(string(rune(i))+"-abandoned", &appSession{Subject: "member", Expires: expired}, now)
	}

	s.mu.Lock()
	held := len(s.m)
	s.mu.Unlock()
	if held > sessionSweepAt {
		t.Errorf("the store holds %d expired sessions, want at most %d", held, sessionSweepAt)
	}
}

// TestPendingTOTPIsGuardedByTheStore drives an enrolment start and a
// confirmation at the same session concurrently, which is what two
// browser tabs on the enrolment page produce. Run under -race, it fails
// if the pending enrolment is reached through the pointer get returns
// rather than through the store's own methods.
func TestPendingTOTPIsGuardedByTheStore(t *testing.T) {
	t.Parallel()

	members := newFakeMembers()
	subject := members.seed("member-1", "member@example.com", "correct-horse")
	totps := &recordingTOTPs{}
	ui := newTestAppUI(t, members, totps)
	sessionID, token := signedIn(t, ui, subject)

	// The requests are built before anything starts, so the only
	// concurrency under test is the handlers'.
	const tabs = 8
	starts := make([]*http.Request, tabs)
	confirms := make([]*http.Request, tabs)
	for i := range tabs {
		starts[i] = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/account/totp", nil)
		starts[i].AddCookie(&http.Cookie{Name: appSessionCookie, Value: sessionID})
		confirms[i] = appPost(t, "/account/totp", testOrigin, sessionID, token, url.Values{
			"current_password": {"correct-horse"},
			"code":             {"000000"},
		})
	}

	var wg sync.WaitGroup
	for i := range tabs {
		wg.Add(2)
		go func() {
			defer wg.Done()
			ui.totpStart(httptest.NewRecorder(), starts[i])
		}()
		go func() {
			defer wg.Done()
			ui.totpConfirm(httptest.NewRecorder(), confirms[i])
		}()
	}
	wg.Wait()
}
