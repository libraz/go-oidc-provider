package passkey_test

// The round trip both ceremonies exist for: register a credential, then
// authenticate with it. Every other test in this package drives one
// ceremony against inputs it constructs, which cannot catch the failure
// mode that matters most — a registration the login path will not
// accept. Here the same verifier that minted the credential is the one
// asked to believe it, against real ES256 signatures from
// internal/testutil/softkey.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn/passkey"
	"github.com/libraz/go-oidc-provider/internal/testutil/softkey"
)

const (
	roundTripRPID    = "id.example.com"
	roundTripOrigin  = "https://id.example.com"
	roundTripSubject = "user-alice"
	roundTripName    = "alice@example.com"
)

// registerRoundTrip runs the registration ceremony end to end and
// returns the credential the verifier accepted.
func registerRoundTrip(t *testing.T, v *passkey.Verifier, key *softkey.Key) *passkey.Credential {
	t.Helper()
	ctx := context.Background()

	challenge, session, err := v.BeginRegistration(ctx, roundTripSubject, roundTripName, "Alice", nil)
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	raw, err := softkey.ChallengeFromOptions(challenge.PublicKey)
	if err != nil {
		t.Fatalf("ChallengeFromOptions: %v", err)
	}
	response, err := key.Create(roundTripRPID, roundTripOrigin, raw)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	cred, err := v.FinishRegistration(ctx, session, roundTripSubject, roundTripName, "Alice", nil, response)
	if err != nil {
		t.Fatalf("FinishRegistration: %v", err)
	}
	return cred
}

// assertRoundTrip runs the assertion ceremony against the supplied
// credential list and returns the verifier's verdict unfiltered, so a
// caller can assert on the clone-detection error too.
func assertRoundTrip(t *testing.T, v *passkey.Verifier, key *softkey.Key, creds []passkey.Credential) (*passkey.Credential, error) {
	t.Helper()
	ctx := context.Background()

	challenge, session, err := v.BeginLogin(ctx, roundTripSubject, roundTripName, creds)
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	raw, err := softkey.ChallengeFromOptions(challenge.PublicKey)
	if err != nil {
		t.Fatalf("ChallengeFromOptions: %v", err)
	}
	response, err := key.Assert(roundTripRPID, roundTripOrigin, raw, []byte(roundTripSubject))
	if err != nil {
		t.Fatalf("Assert: %v", err)
	}
	return v.FinishLogin(ctx, session, roundTripSubject, roundTripName, creds, response)
}

func TestCeremony_RegisteredCredentialAuthenticates(t *testing.T) {
	t.Parallel()

	v := newTestVerifier(t, time.Now())
	key, err := softkey.New()
	if err != nil {
		t.Fatalf("softkey.New: %v", err)
	}

	registered := registerRoundTrip(t, v, key)
	if len(registered.PublicKey) == 0 {
		t.Fatal("registered credential carries no public key")
	}
	if registered.AttestationType != "none" {
		t.Errorf("AttestationType=%q want none", registered.AttestationType)
	}
	if !registered.Flags.UserPresent {
		t.Error("UserPresent flag not set on the registered credential")
	}

	asserted, err := assertRoundTrip(t, v, key, []passkey.Credential{*registered})
	if err != nil {
		t.Fatalf("FinishLogin: %v", err)
	}
	if string(asserted.ID) != string(registered.ID) {
		t.Errorf("asserted credential %x want %x", asserted.ID, registered.ID)
	}
	if asserted.Authenticator.SignCount <= registered.Authenticator.SignCount {
		t.Errorf("SignCount did not advance: %d then %d",
			registered.Authenticator.SignCount, asserted.Authenticator.SignCount)
	}
	if asserted.Authenticator.CloneWarning {
		t.Error("CloneWarning raised on a well-behaved authenticator")
	}
}

// TestCeremony_UnregisteredCredentialIsRefused asserts the assertion is
// checked against the caller's credential list, not merely against a
// well-formed signature: a second authenticator that never enrolled
// cannot sign its way in.
func TestCeremony_UnregisteredCredentialIsRefused(t *testing.T) {
	t.Parallel()

	v := newTestVerifier(t, time.Now())
	enrolled, err := softkey.New()
	if err != nil {
		t.Fatalf("softkey.New: %v", err)
	}
	stranger, err := softkey.New()
	if err != nil {
		t.Fatalf("softkey.New: %v", err)
	}

	registered := registerRoundTrip(t, v, enrolled)
	if _, err := assertRoundTrip(t, v, stranger, []passkey.Credential{*registered}); !errors.Is(err, passkey.ErrCredentialNotRegistered) {
		t.Fatalf("err=%v want ErrCredentialNotRegistered", err)
	}
}

// TestCeremony_StalledCounterRaisesCloneWarning drives the signal
// WebAuthn Level 3 §7.2 step 17 defines: a counter that fails to
// advance is how a duplicated authenticator gives itself away.
func TestCeremony_StalledCounterRaisesCloneWarning(t *testing.T) {
	t.Parallel()

	v := newTestVerifier(t, time.Now())
	key, err := softkey.New()
	if err != nil {
		t.Fatalf("softkey.New: %v", err)
	}

	registered := registerRoundTrip(t, v, key)
	asserted, err := assertRoundTrip(t, v, key, []passkey.Credential{*registered})
	if err != nil {
		t.Fatalf("FinishLogin: %v", err)
	}

	// Rewind the authenticator so its next assertion repeats a counter
	// the verifier has already seen — what a clone of the device would
	// produce.
	key.SetSignCount(asserted.Authenticator.SignCount - 1)

	replayed, err := assertRoundTrip(t, v, key, []passkey.Credential{*asserted})
	if !errors.Is(err, passkey.ErrCloneDetected) {
		t.Fatalf("err=%v want ErrCloneDetected", err)
	}
	if replayed == nil {
		t.Fatal("no credential returned; the caller cannot stamp the audit trail")
	}
	if !replayed.Authenticator.CloneWarning {
		t.Error("CloneWarning not set on the returned credential")
	}
	if replayed.Authenticator.SignCount != asserted.Authenticator.SignCount {
		t.Errorf("SignCount=%d want %d — a clone must not be able to move the stored counter",
			replayed.Authenticator.SignCount, asserted.Authenticator.SignCount)
	}
}
