package passkey_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/authn/passkey"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// allowedAAGUID is a canonical UUID the tests use to seed allowlists.
// The bytes are arbitrary; the test exercises the gate's allow / deny
// logic, not any particular vendor mapping.
var (
	allowedAAGUIDStr   = "fbfc3007-154e-4ecc-8c0b-6e020557d7bd"
	allowedAAGUIDBytes = []byte{
		0xfb, 0xfc, 0x30, 0x07, 0x15, 0x4e, 0x4e, 0xcc,
		0x8c, 0x0b, 0x6e, 0x02, 0x05, 0x57, 0xd7, 0xbd,
	}
	disallowedAAGUIDBytes = []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	}
)

func newVerifierWithRecheck(t *testing.T, allowlist []string, recheck bool) *passkey.Verifier {
	t.Helper()
	v, err := passkey.New(passkey.Config{
		RPID:                     "id.example.com",
		RPDisplayName:            "Example Identity",
		RPOrigins:                []string{"https://id.example.com"},
		AAGUIDAllowlist:          allowlist,
		AttestationRoots:         testAttestationRoots(t),
		AAGUIDReCheckOnAssertion: recheck,
		// An allowlist is only configurable alongside direct
		// attestation, since otherwise the AAGUID it compares is
		// self-asserted.
		AttestationPreference: protocol.PreferDirectAttestation,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return v
}

// TestAAGUIDRecheck_AllowedCredentialPassesThrough covers the happy
// path: a credential whose AAGUID remains in the allowlist passes the
// re-check gate (the helper returns nil so [Verifier.FinishLogin]
// continues to ValidateLogin).
func TestAAGUIDRecheck_AllowedCredentialPassesThrough(t *testing.T) {
	t.Parallel()
	v := newVerifierWithRecheck(t, []string{allowedAAGUIDStr}, true)
	creds := []passkey.Credential{{
		ID: []byte{0x01, 0x02, 0x03},
		Authenticator: passkey.AuthenticatorData{
			AAGUID: allowedAAGUIDBytes,
		},
	}}
	if err := v.CheckAAGUIDOnAssertionForTest(creds[0]); err != nil {
		t.Fatalf("CheckAAGUIDOnAssertion: %v", err)
	}
}

// TestAAGUIDRecheck_NarrowedAllowlistRejectsExistingCredential is the
// happy-path-of-defence: a credential that registered under a
// permissive allowlist is rejected at assertion time when the
// embedder narrows the allowlist below the credential's AAGUID.
func TestAAGUIDRecheck_NarrowedAllowlistRejectsExistingCredential(t *testing.T) {
	t.Parallel()
	// Allowlist no longer includes the credential's AAGUID — embedder
	// has narrowed the policy after the credential was registered.
	v := newVerifierWithRecheck(t, []string{allowedAAGUIDStr}, true)
	creds := []passkey.Credential{{
		ID: []byte{0x01, 0x02, 0x03},
		Authenticator: passkey.AuthenticatorData{
			AAGUID: disallowedAAGUIDBytes,
		},
	}}
	err := v.CheckAAGUIDOnAssertionForTest(creds[0])
	if !errors.Is(err, passkey.ErrAAGUIDDisallowed) {
		t.Fatalf("err=%v want ErrAAGUIDDisallowed", err)
	}
}

// TestAAGUIDRecheck_NoAllowlistShortCircuits asserts the helper
// short-circuits to nil when the verifier has no allowlist configured,
// regardless of the re-check toggle. An embedder that did not configure
// AAGUIDAllowlist sees no behaviour change from flipping the re-check
// toggle on.
func TestAAGUIDRecheck_NoAllowlistShortCircuits(t *testing.T) {
	t.Parallel()
	v := newVerifierWithRecheck(t, nil, true)
	creds := []passkey.Credential{{
		ID: []byte{0x01, 0x02, 0x03},
		Authenticator: passkey.AuthenticatorData{
			AAGUID: disallowedAAGUIDBytes,
		},
	}}
	if err := v.CheckAAGUIDOnAssertionForTest(creds[0]); err != nil {
		t.Fatalf("CheckAAGUIDOnAssertion: %v", err)
	}
}

// TestAAGUIDRecheck_DisabledToggleAllowsExistingCredential covers the
// backwards-compatible default: with the re-check toggle off, a
// credential whose AAGUID is no longer in the allowlist still passes
// the gate (the registration-time check is the only enforcement).
func TestAAGUIDRecheck_DisabledToggleAllowsExistingCredential(t *testing.T) {
	t.Parallel()
	v := newVerifierWithRecheck(t, []string{allowedAAGUIDStr}, false)
	creds := []passkey.Credential{{
		ID: []byte{0x01, 0x02, 0x03},
		Authenticator: passkey.AuthenticatorData{
			AAGUID: disallowedAAGUIDBytes,
		},
	}}
	if err := v.CheckAAGUIDOnAssertionForTest(creds[0]); err != nil {
		t.Fatalf("CheckAAGUIDOnAssertion: %v", err)
	}
}

// TestAAGUIDRecheck_ClockResolution exercises the helper across a
// timestamped credential to ensure the gate is purely AAGUID-driven —
// the credential's CreatedAt does NOT participate in the decision.
func TestAAGUIDRecheck_ClockResolution(t *testing.T) {
	t.Parallel()
	v := newVerifierWithRecheck(t, []string{allowedAAGUIDStr}, true)
	creds := []passkey.Credential{{
		ID:        []byte{0x01, 0x02, 0x03},
		CreatedAt: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		Authenticator: passkey.AuthenticatorData{
			AAGUID: allowedAAGUIDBytes,
		},
	}}
	if err := v.CheckAAGUIDOnAssertionForTest(creds[0]); err != nil {
		t.Fatalf("CheckAAGUIDOnAssertion: %v", err)
	}
}

// TestAAGUIDRecheck_AllCredentialsDisallowedIsNotEnrolled pins that a
// subject whose every passkey fails the re-check is not enrolled, so a
// one-of step falls back to another factor, and that Begin refuses it as
// a factor abort rather than a server fault. With the re-check off the
// same subject is enrolled.
func TestAAGUIDRecheck_AllCredentialsDisallowedIsNotEnrolled(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, recheck := range []bool{true, false} {
		pkstore := inmem.New().Passkeys()
		if err := pkstore.Put(ctx, &store.PasskeyRecord{
			CredentialID:    []byte{0x01, 0x02, 0x03},
			Subject:         "user-narrowed",
			PublicKey:       []byte{0xaa, 0xbb, 0xcc},
			AAGUID:          disallowedAAGUIDBytes,
			SignCount:       1,
			AttestationType: "none",
		}); err != nil {
			t.Fatalf("seed passkey: %v", err)
		}
		adapter, err := passkey.NewAuthenticator(newVerifierWithRecheck(t, []string{allowedAAGUIDStr}, recheck), pkstore)
		if err != nil {
			t.Fatalf("NewAuthenticator: %v", err)
		}
		enrolled, err := adapter.Enrolled(ctx, "user-narrowed")
		if err != nil {
			t.Fatalf("Enrolled: %v", err)
		}
		if enrolled == recheck {
			t.Errorf("recheck=%v: Enrolled=%v, want %v", recheck, enrolled, !recheck)
		}
		if !recheck {
			continue
		}
		_, err = adapter.Begin(ctx, op.BeginInput{Subject: "user-narrowed"})
		if !errors.Is(err, passkey.ErrAAGUIDDisallowed) || !errors.Is(err, authn.ErrFactorAbort) {
			t.Errorf("Begin err=%v, want ErrAAGUIDDisallowed wrapped in ErrFactorAbort", err)
		}
	}
}
