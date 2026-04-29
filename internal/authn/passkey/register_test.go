package passkey_test

// FinishRegistration is intentionally NOT exercised on its happy path
// in this package: a real round-trip requires a virtual authenticator
// (CTAP2 soft token, attestation object construction, COSE signing) the
// orchestrator-integration task will stand up. The tests below cover
// the deterministic surface — challenge / Session shape, error paths
// — so the orchestrator task can plug in the soft-token harness and
// exercise the happy path end-to-end without re-validating the inputs
// the package already checks.

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn/passkey"
	"github.com/libraz/go-oidc-provider/internal/timex"
)

func newTestVerifier(t *testing.T, now time.Time) *passkey.Verifier {
	t.Helper()
	v, err := passkey.New(passkey.Config{
		RPID:          "id.example.com",
		RPDisplayName: "Example Identity",
		RPOrigins:     []string{"https://id.example.com"},
		SessionTTL:    5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	v.Clock = timex.ClockFunc(func() time.Time { return now })
	return v
}

func TestBeginRegistration_ProducesChallengeAndSession(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	v := newTestVerifier(t, now)
	ch, sess, err := v.BeginRegistration(context.Background(), "user-alice", "alice@example.com", "Alice", nil)
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	if ch == nil || len(ch.PublicKey) == 0 {
		t.Fatalf("RegistrationChallenge.PublicKey empty: %+v", ch)
	}
	if sess == nil {
		t.Fatal("Session is nil")
	}
	if sess.Challenge == "" {
		t.Errorf("Challenge is empty")
	}
	if string(sess.UserID) != "user-alice" {
		t.Errorf("UserID=%q want user-alice", string(sess.UserID))
	}
	wantExpires := now.Add(5 * time.Minute)
	if !sess.Expires.Equal(wantExpires) {
		t.Errorf("Expires=%v want %v", sess.Expires, wantExpires)
	}
	if sess.Expires.Location() != time.UTC {
		t.Errorf("Expires.Location=%v want UTC", sess.Expires.Location())
	}
}

func TestBeginRegistration_RejectsEmptySubject(t *testing.T) {
	t.Parallel()

	v := newTestVerifier(t, time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC))
	_, _, err := v.BeginRegistration(context.Background(), "", "alice@example.com", "Alice", nil)
	if !errors.Is(err, passkey.ErrInvalidConfig) {
		t.Fatalf("err=%v want ErrInvalidConfig", err)
	}
}

func TestFinishRegistration_RejectsExpiredSession(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	v := newTestVerifier(t, now)
	stale := &passkey.Session{
		Challenge: "abc",
		UserID:    []byte("user-alice"),
		// Expired one second ago.
		Expires: now.Add(-1 * time.Second),
	}
	_, err := v.FinishRegistration(context.Background(), stale, "user-alice", "alice@example.com", "Alice", nil, []byte(`{"id":"x"}`))
	if !errors.Is(err, passkey.ErrChallengeExpired) {
		t.Fatalf("err=%v want ErrChallengeExpired", err)
	}
}

func TestFinishRegistration_RejectsZeroExpiresSession(t *testing.T) {
	t.Parallel()

	v := newTestVerifier(t, time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC))
	// Zero Expires is suspicious — a legitimate session always has
	// a non-zero stamp. The verifier rejects it as expired.
	zero := &passkey.Session{
		Challenge: "abc",
		UserID:    []byte("user-alice"),
	}
	_, err := v.FinishRegistration(context.Background(), zero, "user-alice", "alice@example.com", "Alice", nil, []byte(`{"id":"x"}`))
	if !errors.Is(err, passkey.ErrChallengeExpired) {
		t.Fatalf("err=%v want ErrChallengeExpired", err)
	}
}

func TestFinishRegistration_RejectsMalformedResponse(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	v := newTestVerifier(t, now)
	fresh := &passkey.Session{
		Challenge: "abc",
		UserID:    []byte("user-alice"),
		Expires:   now.Add(5 * time.Minute),
	}
	for _, tc := range []struct {
		name string
		body []byte
	}{
		{name: "empty", body: []byte("")},
		{name: "not-json", body: []byte("not-json")},
		{name: "missing-fields", body: []byte(`{}`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := v.FinishRegistration(context.Background(), fresh, "user-alice", "alice@example.com", "Alice", nil, tc.body)
			if !errors.Is(err, passkey.ErrInvalidResponse) {
				t.Fatalf("err=%v want ErrInvalidResponse", err)
			}
		})
	}
}

func TestFinishRegistration_RejectsNilSession(t *testing.T) {
	t.Parallel()

	v := newTestVerifier(t, time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC))
	_, err := v.FinishRegistration(context.Background(), nil, "user-alice", "alice@example.com", "Alice", nil, []byte(`{}`))
	if !errors.Is(err, passkey.ErrInvalidResponse) {
		t.Fatalf("err=%v want ErrInvalidResponse", err)
	}
}

// TestBeginRegistration_ExcludeCredentialsForwarded asserts the
// caller-supplied existing credentials reach the SPA as
// excludeCredentials so a CTAP2 authenticator already bound to the
// user refuses a duplicate registration at the device level
// (M-AUTHN-1).
func TestBeginRegistration_ExcludeCredentialsForwarded(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	v := newTestVerifier(t, now)
	existing := []passkey.Credential{{
		ID:         []byte("credential-one"),
		PublicKey:  []byte("pk-one"),
		Transports: []string{"usb"},
	}}
	ch, _, err := v.BeginRegistration(context.Background(), "user-alice", "alice@example.com", "Alice", existing)
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	// excludeCredentials is rendered as a JSON array under the
	// "excludeCredentials" key of the publicKey options. We test the
	// presence of the rendered key rather than the whole object shape
	// so the assertion survives upstream library cosmetic changes.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(ch.PublicKey, &raw); err != nil {
		t.Fatalf("Unmarshal PublicKey: %v", err)
	}
	excl, ok := raw["excludeCredentials"]
	if !ok {
		t.Fatalf("excludeCredentials key absent: %s", string(ch.PublicKey))
	}
	// The credential ID is base64url-encoded inside the descriptor; the
	// upstream library round-trips it via protocol.URLEncodedBase64.
	// Look for any non-empty array — the constant material would
	// already imply the option threaded through.
	if !strings.Contains(string(excl), "\"id\"") {
		t.Errorf("excludeCredentials missing id field: %s", string(excl))
	}
}
