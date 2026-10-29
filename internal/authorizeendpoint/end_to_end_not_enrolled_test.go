package authorizeendpoint_test

import (
	"context"
	"crypto/rand"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// TestEndToEnd_NotEnrolledTOTPIsClientError drives a password-then-TOTP
// LoginFlow for a user with no TOTP enrolment. A rule that demands a second
// factor the user never enrolled is a user-side terminal failure, so the
// TOTP step must end with a 400 rather than a 500 or a silent skip.
func TestEndToEnd_NotEnrolledTOTPIsClientError(t *testing.T) {
	t.Parallel()

	const (
		username = "no-totp-user"
		password = "correct horse battery staple"
	)
	clock := newMovableClock(time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))

	hash, err := op.HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	creds := inmem.New(inmem.WithClock(clock))
	creds.PutUserWithPassword(context.Background(), &store.User{Subject: "user-no-totp"}, username, hash)

	totpKey := make([]byte, 32)
	if _, err := rand.Read(totpKey); err != nil {
		t.Fatalf("totp key: %v", err)
	}

	fix := buildFlowFixture(t, "not-enrolled-totp", clock, op.WithLoginFlow(op.LoginFlow{
		Primary: op.PrimaryPassword{Store: creds.UserPasswords()},
		Rules:   []op.Rule{op.RuleAlways(op.StepTOTP{Store: creds.TOTPs(), EncryptionKey: totpKey})},
	}))
	d := newReauthDriver(t, fix)

	loc := d.authorize(nil)
	env, csrf := d.firstPrompt(loc.Path)
	stateRef, _ := env["state_ref"].(string)

	resp := d.submit(loc.Path, csrf, stateRef, map[string]string{"username": username, "password": password})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		dump, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d, want 400 for an unenrolled second factor; body=%s", resp.StatusCode, dump)
	}
}
