package passkey_test

// FinishLogin is intentionally NOT exercised on its happy path in this
// package: a real round-trip requires a virtual authenticator that can
// mint a valid assertion signature, which the orchestrator-integration
// task will stand up. The tests below cover the deterministic surface
// — challenge / Session shape, error paths — so the integration task
// can plug in the soft-token harness and exercise the happy path
// end-to-end without re-validating the inputs the package already
// checks.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn/passkey"
)

func sampleCredential() passkey.Credential {
	return passkey.Credential{
		ID:              []byte{0x01, 0x02, 0x03},
		PublicKey:       []byte{0xaa, 0xbb, 0xcc},
		AttestationType: "none",
		Authenticator: passkey.AuthenticatorData{
			SignCount: 1,
		},
	}
}

func TestBeginLogin_ProducesAssertionAndSession(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	v := newTestVerifier(t, now)
	creds := []passkey.Credential{sampleCredential()}

	ch, sess, err := v.BeginLogin(context.Background(), "user-alice", "alice@example.com", creds)
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	if ch == nil || len(ch.PublicKey) == 0 {
		t.Fatalf("AssertionChallenge.PublicKey empty: %+v", ch)
	}
	if sess == nil {
		t.Fatal("Session is nil")
	}
	if sess.Challenge == "" {
		t.Errorf("Challenge is empty")
	}
	if len(sess.AllowedCredentialIDs) != 1 {
		t.Errorf("len(AllowedCredentialIDs)=%d want 1", len(sess.AllowedCredentialIDs))
	}
	wantExpires := now.Add(5 * time.Minute)
	if !sess.Expires.Equal(wantExpires) {
		t.Errorf("Expires=%v want %v", sess.Expires, wantExpires)
	}
}

func TestBeginLogin_RejectsEmptySubject(t *testing.T) {
	t.Parallel()

	v := newTestVerifier(t, time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC))
	creds := []passkey.Credential{sampleCredential()}

	_, _, err := v.BeginLogin(context.Background(), "", "alice@example.com", creds)
	if !errors.Is(err, passkey.ErrInvalidConfig) {
		t.Fatalf("err=%v want ErrInvalidConfig", err)
	}
}

func TestBeginLogin_RejectsEmptyCredentialList(t *testing.T) {
	t.Parallel()

	v := newTestVerifier(t, time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC))
	_, _, err := v.BeginLogin(context.Background(), "user-alice", "alice@example.com", nil)
	if !errors.Is(err, passkey.ErrCredentialNotRegistered) {
		t.Fatalf("err=%v want ErrCredentialNotRegistered", err)
	}
}

func TestFinishLogin_RejectsExpiredSession(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	v := newTestVerifier(t, now)
	stale := &passkey.Session{
		Challenge: "abc",
		UserID:    []byte("user-alice"),
		Expires:   now.Add(-1 * time.Second),
	}
	creds := []passkey.Credential{sampleCredential()}
	_, err := v.FinishLogin(context.Background(), stale, "user-alice", "alice@example.com", creds, []byte(`{}`))
	if !errors.Is(err, passkey.ErrChallengeExpired) {
		t.Fatalf("err=%v want ErrChallengeExpired", err)
	}
}

func TestFinishLogin_RejectsZeroExpiresSession(t *testing.T) {
	t.Parallel()

	v := newTestVerifier(t, time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC))
	zero := &passkey.Session{
		Challenge: "abc",
		UserID:    []byte("user-alice"),
	}
	creds := []passkey.Credential{sampleCredential()}
	_, err := v.FinishLogin(context.Background(), zero, "user-alice", "alice@example.com", creds, []byte(`{}`))
	if !errors.Is(err, passkey.ErrChallengeExpired) {
		t.Fatalf("err=%v want ErrChallengeExpired", err)
	}
}

func TestFinishLogin_RejectsEmptyCredentialList(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	v := newTestVerifier(t, now)
	fresh := &passkey.Session{
		Challenge: "abc",
		UserID:    []byte("user-alice"),
		Expires:   now.Add(5 * time.Minute),
	}
	_, err := v.FinishLogin(context.Background(), fresh, "user-alice", "alice@example.com", nil, []byte(`{}`))
	if !errors.Is(err, passkey.ErrCredentialNotRegistered) {
		t.Fatalf("err=%v want ErrCredentialNotRegistered", err)
	}
}

func TestFinishLogin_RejectsMalformedResponse(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	v := newTestVerifier(t, now)
	fresh := &passkey.Session{
		Challenge: "abc",
		UserID:    []byte("user-alice"),
		Expires:   now.Add(5 * time.Minute),
	}
	creds := []passkey.Credential{sampleCredential()}
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
			_, err := v.FinishLogin(context.Background(), fresh, "user-alice", "alice@example.com", creds, tc.body)
			if !errors.Is(err, passkey.ErrInvalidResponse) {
				t.Fatalf("err=%v want ErrInvalidResponse", err)
			}
		})
	}
}

func TestFinishLogin_RejectsNilSession(t *testing.T) {
	t.Parallel()

	v := newTestVerifier(t, time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC))
	creds := []passkey.Credential{sampleCredential()}
	_, err := v.FinishLogin(context.Background(), nil, "user-alice", "alice@example.com", creds, []byte(`{}`))
	if !errors.Is(err, passkey.ErrInvalidResponse) {
		t.Fatalf("err=%v want ErrInvalidResponse", err)
	}
}
