package passkey_test

import (
	"context"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/authn/passkey"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// newSeededPasskeyStore returns an inmem [store.PasskeyStore]
// pre-populated with a record matching subject and credentialID. The
// helper exists so the UV-propagation tests can drive
// continueResult's persistCredential without bringing up a full
// adapter fixture.
func newSeededPasskeyStore(t *testing.T, subject string, credentialID []byte) store.PasskeyStore {
	t.Helper()
	st := inmem.New().Passkeys()
	if err := st.Put(context.Background(), &store.PasskeyRecord{
		CredentialID: credentialID,
		Subject:      subject,
		PublicKey:    []byte{0xaa},
		AAGUID:       make([]byte, 16),
	}); err != nil {
		t.Fatalf("seed passkey store: %v", err)
	}
	return st
}

// TestAuthenticator_NoLongerImplementsUVReporter asserts that the
// process-local UV cache and its [authn.UserVerificationReporter]
// type-assertion target are gone. Multi-replica deployments without
// sticky sessions used to lose the UV bit when the appendFactor read
// landed on a replica that had not seen the assertion; the bit now
// rides [interaction.Result.UserVerified] back to the orchestrator,
// so the type assertion is no longer necessary.
//
// We assert the negative — the adapter MUST NOT satisfy the legacy
// interface — so a future refactor cannot silently re-introduce the
// process-local cache without flipping this test.
func TestAuthenticator_NoLongerImplementsUVReporter(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	v := newTestVerifier(t, now)
	a, err := passkey.NewAuthenticator(v, &fakePasskeyStore{})
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}

	// Probe the deprecated UserVerificationReporter on purpose: the
	// regression we pin asserts the built-in adapter dropped the
	// process-local cache and no longer satisfies the legacy
	// reporter.
	if _, ok := any(a).(authn.UserVerificationReporter); ok { //nolint:staticcheck // deprecated probe is the assertion shape.
		t.Errorf("Authenticator still satisfies UserVerificationReporter")
	}
}

// TestAuthenticator_UVBitTravelsOnResult asserts the UV bit set by
// the verifier reaches the orchestrator through
// [interaction.Result.UserVerified]. The test exercises the
// continueResult dispatcher directly through a test seam so we do
// not need a soft authenticator that mints a valid assertion.
func TestAuthenticator_UVBitTravelsOnResult(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	v := newTestVerifier(t, now)

	// The store must accept Put because continueResult persists the
	// rotated credential before stamping Result. We pre-seed the row
	// so the existing-record lookup inside persistCredential does not
	// surface ErrNotFound.
	st := newSeededPasskeyStore(t, "user-uv", []byte{0x01, 0x02})
	a, err := passkey.NewAuthenticator(v, st)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}

	cred := &passkey.Credential{
		ID:        []byte{0x01, 0x02},
		PublicKey: []byte{0xaa},
		Flags: passkey.CredentialFlags{
			UserVerified: true,
		},
		Authenticator: passkey.AuthenticatorData{
			SignCount: 7,
		},
	}
	step := a.ContinueResultForTest(context.Background(), "user-uv", now, cred)
	if step.Result == nil {
		t.Fatalf("Step.Result is nil: %+v", step)
	}
	if !step.Result.UserVerified {
		t.Errorf("Result.UserVerified = false, want true")
	}
}

// TestAuthenticator_UVBitFalseWhenAssertionUVOff asserts the inverse
// branch: an assertion without the UV bit produces a Result whose
// UserVerified field is false.
func TestAuthenticator_UVBitFalseWhenAssertionUVOff(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	v := newTestVerifier(t, now)
	st := newSeededPasskeyStore(t, "user-uv", []byte{0x01, 0x02})
	a, err := passkey.NewAuthenticator(v, st)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}

	cred := &passkey.Credential{
		ID:        []byte{0x01, 0x02},
		PublicKey: []byte{0xaa},
		Flags:     passkey.CredentialFlags{UserVerified: false},
		Authenticator: passkey.AuthenticatorData{
			SignCount: 7,
		},
	}
	step := a.ContinueResultForTest(context.Background(), "user-uv", now, cred)
	if step.Result == nil {
		t.Fatalf("Step.Result is nil: %+v", step)
	}
	if step.Result.UserVerified {
		t.Errorf("Result.UserVerified = true, want false")
	}
}
