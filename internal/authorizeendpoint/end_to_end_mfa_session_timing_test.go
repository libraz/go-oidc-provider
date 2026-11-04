package authorizeendpoint_test

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"sync"
	"testing"
	"time"

	authntotp "github.com/libraz/go-oidc-provider/internal/authn/totp"
	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
	"github.com/libraz/go-oidc-provider/op/testkit"
	"github.com/libraz/go-oidc-provider/op/totpkit"
)

// sessionSaveRecorder is a store.Store whose session substore records
// the subject of every Save, so a test can tell "no session record was
// written" from "a record was written but its cookie was withheld".
type sessionSaveRecorder struct {
	*inmem.Store
	sessions *recordingSessionStore
}

func (s sessionSaveRecorder) Sessions() store.SessionStore { return s.sessions }

type recordingSessionStore struct {
	store.SessionStore
	mu    sync.Mutex
	saved []string
}

func (r *recordingSessionStore) Save(ctx context.Context, sess *store.Session) error {
	r.mu.Lock()
	r.saved = append(r.saved, sess.Subject)
	r.mu.Unlock()
	return r.SessionStore.Save(ctx, sess)
}

func (r *recordingSessionStore) savedFor(subject string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, s := range r.saved {
		if s == subject {
			n++
		}
	}
	return n
}

// TestEndToEnd_MFAWithholdsSessionUntilSecondFactorCompletes drives a
// password-then-TOTP LoginFlow and requires that the browser session
// (cookie and record) does not exist after the password step and appears
// only once the TOTP step has completed.
//
// Tracks: CVE-2026-92227 (Joomla — a remember-me cookie was issued before multi-factor authentication had completed)
func TestEndToEnd_MFAWithholdsSessionUntilSecondFactorCompletes(t *testing.T) {
	t.Parallel()

	const (
		subject  = "user-mfa-timing"
		username = "mfa-user"
		password = "correct horse battery staple"
	)
	clock := newMovableClock(time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	inner := inmem.New(inmem.WithClock(clock))
	rec := &recordingSessionStore{SessionStore: inner.Sessions()}
	st := sessionSaveRecorder{Store: inner, sessions: rec}

	hash, err := op.HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	inner.PutUserWithPassword(context.Background(), &store.User{Subject: subject}, username, hash)

	totpKey := make([]byte, 32)
	if _, err := rand.Read(totpKey); err != nil {
		t.Fatalf("totp key: %v", err)
	}
	codec, err := totpkit.NewCodec(totpKey)
	if err != nil {
		t.Fatalf("totpkit.NewCodec: %v", err)
	}
	pending, err := totpkit.NewEnrolment(codec, subject, "mfa-timing", "user@example.test")
	if err != nil {
		t.Fatalf("NewEnrolment: %v", err)
	}
	pending.Record.ConfirmedAt = clock.Now()
	if err := inner.TOTPs().Put(context.Background(), pending.Record); err != nil {
		t.Fatalf("TOTPs.Put: %v", err)
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(pending.SecretBase32)
	if err != nil {
		t.Fatalf("decode totp secret: %v", err)
	}

	const rpSecret = "rp-mfa-timing-secret" //nolint:gosec // test fixture, not a real credential.
	rpHash, err := op.HashClientSecret(rpSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	rp := &store.Client{
		ID:                      "rp-mfa-timing",
		RedirectURIs:            []string{"https://rp.testkit.invalid/callback"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
		SecretHash:              rpHash,
	}
	if err := inner.RegisterClient(context.Background(), rp); err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}

	provider, err := op.New(
		op.WithIssuer(testkit.DefaultIssuer),
		op.WithStore(st),
		op.WithUserStore(inner.Users()),
		op.WithKeyset(op.Keyset{newFlowSigningKey(t)}),
		op.WithCookieKeys(newFlowCookieKey(t)),
		op.WithUI(op.DriverUI{Driver: testkit.AutoConsentDriver{}}),
		op.WithClock(clock),
		op.WithLoginFlow(op.LoginFlow{
			Primary: op.PrimaryPassword{Store: inner.UserPasswords()},
			Rules:   []op.Rule{op.RuleAlways(op.StepTOTP{Store: inner.TOTPs(), EncryptionKey: totpKey})},
		}),
	)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	srv := httptest.NewTLSServer(provider)
	t.Cleanup(srv.Close)

	fix := &flowFixture{
		server: srv, store: inner, client: rp, clock: clock,
		issuer: testkit.DefaultIssuer, secret: rpSecret,
	}
	d := &reauthDriver{t: t, fix: fix, cl: fix.httpClient(t)}
	serverURL, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}
	hasSessionCookie := func(resp *http.Response) bool {
		if findCookie(resp.Cookies(), cookie.SessionProfile.Name) != nil {
			return true
		}
		return slices.ContainsFunc(d.cl.Jar.Cookies(serverURL), func(c *http.Cookie) bool {
			return c.Name == cookie.SessionProfile.Name
		})
	}

	loc := d.authorize(nil)
	env, csrf := d.firstPrompt(loc.Path)
	stateRef, _ := env["state_ref"].(string)

	// Password step: the next prompt is the TOTP challenge and nothing
	// durable exists yet.
	pwResp := d.submit(loc.Path, csrf, stateRef, map[string]string{"username": username, "password": password})
	defer pwResp.Body.Close()
	if pwResp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(pwResp.Body)
		t.Fatalf("password step status=%d body=%s", pwResp.StatusCode, dump)
	}
	hasCookieAfterPassword := hasSessionCookie(pwResp)
	next := decodeMap(t, pwResp)
	if got, _ := next["type"].(string); got != authntotp.PromptType {
		t.Fatalf("prompt after password = %q, want %q", got, authntotp.PromptType)
	}
	if hasCookieAfterPassword {
		t.Error("a session cookie was issued before the second factor completed")
	}
	if n := rec.savedFor(subject); n != 0 {
		t.Errorf("%d session record(s) written for %q before the second factor completed", n, subject)
	}

	// TOTP step: the chain completes and the session appears.
	if rotated := findCookie(pwResp.Cookies(), cookie.CSRFProfile.Name); rotated != nil {
		csrf = rotated.Value
	}
	nextRef, _ := next["state_ref"].(string)
	totpResp := d.submit(loc.Path, csrf, nextRef, map[string]string{
		authntotp.CodeFieldName: authntotp.Code(secret, clock.Now()),
	})
	defer totpResp.Body.Close()
	final := completeConsentIfPrompted(t, d.cl, srv.URL+loc.Path, fix.issuer, csrf, totpResp)
	defer final.Body.Close()
	if final.StatusCode != http.StatusFound {
		dump, _ := io.ReadAll(final.Body)
		t.Fatalf("final status=%d body=%s", final.StatusCode, dump)
	}
	if !hasSessionCookie(final) {
		t.Error("no session cookie after the second factor completed")
	}
	if n := rec.savedFor(subject); n == 0 {
		t.Error("no session record written after the second factor completed")
	}
}
