package passkeykit_test

import (
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/passkeykit"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// TestNew_HonoursRequireUserVerification pins the enrolment half of the
// promise the package makes by taking the whole login step as its
// configuration: a policy field the login ceremony enforces has to reach
// the registration ceremony too. Under RequireUserVerification an
// authenticator with no PIN configured performs no gesture, so it must be
// refused here — otherwise the user walks away believing they enrolled a
// device, and every login with it is rejected for the missing UV flag
// they were never asked for.
func TestNew_HonoursRequireUserVerification(t *testing.T) {
	t.Parallel()

	st := inmem.New()
	reg, err := passkeykit.New(op.PrimaryPasskey{
		Store:                   st.Passkeys(),
		RPID:                    testRPID,
		RPDisplayName:           "Example Identity",
		RPOrigins:               []string{testOrigin},
		SessionTTL:              5 * time.Minute,
		RequireUserVerification: true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	key := newKey(t)
	key.UserVerified = false
	if _, err := enrolAs(t, reg, key, testUser()); !errors.Is(err, passkeykit.ErrAttestationInvalid) {
		t.Fatalf("presence-only enrolment err=%v, want ErrAttestationInvalid", err)
	}

	// The same policy accepts the authenticator that does verify the
	// user, so the refusal above is the gesture and not the ceremony.
	verifying := newKey(t)
	verifying.UserVerified = true
	rec, err := enrolAs(t, reg, verifying, testUser())
	if err != nil {
		t.Fatalf("verifying enrolment: %v", err)
	}
	if !rec.UserVerified {
		t.Error("persisted record does not carry the UV flag the policy demanded")
	}
}
