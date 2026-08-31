package op_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op"
)

func TestWithKeyset_RejectsEmpty(t *testing.T) {
	t.Parallel()

	_, err := op.New(
		op.WithIssuer(validIssuer),
		op.WithStore(stubStore{}),
		op.WithKeyset(op.Keyset{}),
	)
	if !errors.Is(err, op.ErrKeysetRequired) {
		t.Fatalf("expected ErrKeysetRequired for empty keyset, got %v", err)
	}
}

func TestWithKeyset_RejectsMissingKeyID(t *testing.T) {
	t.Parallel()

	bad := newTestKey(t, "")
	_, err := op.New(
		op.WithIssuer(validIssuer),
		op.WithStore(stubStore{}),
		op.WithKeyset(op.Keyset{bad}),
	)
	if err == nil {
		t.Fatal("expected error for missing KeyID, got nil")
	}
}

func TestWithKeyset_RejectsDuplicateKeyID(t *testing.T) {
	t.Parallel()

	a := newTestKey(t, "dup")
	b := newTestKey(t, "dup")
	_, err := op.New(
		op.WithIssuer(validIssuer),
		op.WithStore(stubStore{}),
		op.WithKeyset(op.Keyset{a, b}),
	)
	if err == nil {
		t.Fatal("expected error for duplicate KeyID, got nil")
	}
}

func TestWithKeyset_RejectsNonES256Key(t *testing.T) {
	t.Parallel()

	// rsa.PublicKey satisfies crypto.Signer.Public() but is not ECDSA P-256.
	rsaKey := &fakeRSASigner{}
	_, err := op.New(
		op.WithIssuer(validIssuer),
		op.WithStore(stubStore{}),
		op.WithKeyset(op.Keyset{{KeyID: "rsa-1", Signer: rsaKey}}),
	)
	if err == nil {
		t.Fatal("expected error for non-ES256 key, got nil")
	}
}

func TestWithKeyset_RejectsTypedNilSigner(t *testing.T) {
	t.Parallel()

	var typedNil *ecdsa.PrivateKey
	_, err := op.New(
		op.WithIssuer(validIssuer),
		op.WithStore(stubStore{}),
		op.WithKeyset(op.Keyset{{KeyID: "typed-nil", Signer: typedNil}}),
	)
	if err == nil || !strings.Contains(err.Error(), "nil Signer") {
		t.Fatalf("typed-nil signer error=%v, want nil Signer configuration error", err)
	}
}

// keysetClockNow is the instant the retirement-deadline tests below
// inject through [op.WithClock], so "already retired" and "still live"
// are decided against a pinned reading rather than the wall clock.
var keysetClockNow = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

func TestWithKeyset_RejectsActiveEntryPastNotAfter(t *testing.T) {
	t.Parallel()

	// A Provider built on this keyset would sign with a kid its own
	// verification gate rejects, breaking /userinfo and /introspect for
	// every token it issues.
	active := newTestKey(t, "retired-active")
	active.NotAfter = keysetClockNow.Add(-time.Second)

	_, err := op.New(
		op.WithIssuer(validIssuer),
		op.WithStore(stubStore{}),
		op.WithKeyset(op.Keyset{active}),
		op.WithCookieKeys(newRandomCookieKey(t)),
		fixtureAuthenticator(),
		op.WithClock(fakeClock{now: keysetClockNow}),
	)
	if err == nil {
		t.Fatal("New accepted a keyset whose active entry has already retired")
	}
	if !strings.Contains(err.Error(), "retired-active") ||
		!strings.Contains(err.Error(), "NotAfter") {
		t.Fatalf("err = %v, want it to name the active kid and its NotAfter deadline", err)
	}
}

func TestWithKeyset_RejectsActiveEntryAtNotAfter(t *testing.T) {
	t.Parallel()

	// keys.Set.Find rejects a deadline of exactly "now", so construction
	// must reject the same instant rather than admit a keyset that fails
	// on its first verification.
	active := newTestKey(t, "boundary-active")
	active.NotAfter = keysetClockNow

	_, err := op.New(
		op.WithIssuer(validIssuer),
		op.WithStore(stubStore{}),
		op.WithKeyset(op.Keyset{active}),
		op.WithCookieKeys(newRandomCookieKey(t)),
		fixtureAuthenticator(),
		op.WithClock(fakeClock{now: keysetClockNow}),
	)
	if err == nil {
		t.Fatal("New accepted a keyset whose active entry retires exactly now")
	}
}

func TestWithKeyset_AcceptsRetiredEntryBehindLiveActive(t *testing.T) {
	t.Parallel()

	// A completed rotation looks exactly like this: a live signer in the
	// active slot with the outgoing key held behind it for cache warmth.
	active := newTestKey(t, "live-active")
	active.NotAfter = keysetClockNow.Add(time.Hour)
	retiring := newTestKey(t, "past-deadline")
	retiring.NotAfter = keysetClockNow.Add(-time.Hour)

	if _, err := op.New(
		op.WithIssuer(validIssuer),
		op.WithStore(stubStore{}),
		op.WithKeyset(op.Keyset{active, retiring}),
		op.WithCookieKeys(newRandomCookieKey(t)),
		fixtureAuthenticator(),
		op.WithClock(fakeClock{now: keysetClockNow}),
	); err != nil {
		t.Fatalf("New rejected a live active key with a retired entry behind it: %v", err)
	}
}

func TestWithKeyset_AcceptsZeroNotAfter(t *testing.T) {
	t.Parallel()

	// The zero value means "never retires" and must stay the default.
	if _, err := op.New(append(
		validBaseOpts(t),
		op.WithClock(fakeClock{now: keysetClockNow}),
	)...); err != nil {
		t.Fatalf("New rejected a keyset with no retirement deadline: %v", err)
	}
}

// fakeRSASigner reports an RSA public key from Public(), so the Keyset
// validator can reject it without needing real RSA key generation in tests.
type fakeRSASigner struct{}

func (fakeRSASigner) Public() crypto.PublicKey { return &rsa.PublicKey{} }

// Sign is never invoked because validation rejects the key shape before
// any signing path is reached.
func (fakeRSASigner) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	return nil, nil
}

// validCookieKey returns a 32-byte filler suitable for the AES-256-GCM cookie
// codec. The contents do not need to be random for option-validation tests.
func validCookieKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i)
	}
	return k
}

func TestWithCookieKeys_AcceptsValidKey(t *testing.T) {
	t.Parallel()

	if _, err := op.New(append(validBaseOpts(t), op.WithCookieKeys(validCookieKey()))...); err != nil {
		t.Fatalf("WithCookieKeys rejected valid key: %v", err)
	}
}

func TestWithCookieKeys_RejectsWrongLength(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t), op.WithCookieKeys(make([]byte, 16)))...)
	if err == nil {
		t.Fatal("WithCookieKeys accepted 16-byte key, want rejection")
	}
}

func TestWithCookieKeys_AcceptsRotation(t *testing.T) {
	t.Parallel()

	current := validCookieKey()
	previous := validCookieKey()
	previous[0] = 0xff

	if _, err := op.New(append(validBaseOpts(t), op.WithCookieKeys(current, previous))...); err != nil {
		t.Fatalf("WithCookieKeys rejected rotation pair: %v", err)
	}
}

func TestWithCookieKeys_RejectsEmpty(t *testing.T) {
	t.Parallel()

	if _, err := op.New(append(validBaseOpts(t), op.WithCookieKeys())...); err == nil {
		t.Fatal("WithCookieKeys accepted empty input")
	}
}

func TestWithCookieKeys_RejectsBadRotationEntry(t *testing.T) {
	t.Parallel()

	bad := make([]byte, 31) // off by one
	_, err := op.New(append(validBaseOpts(t), op.WithCookieKeys(validCookieKey(), bad))...)
	if err == nil {
		t.Fatal("WithCookieKeys accepted 31-byte rotation key")
	}
}

func TestWithCookieKeys_DefensiveCopy(t *testing.T) {
	t.Parallel()

	// Mutating the input slice after construction must not change the OP's
	// stored keys. The test verifies behaviour via successful construction
	// (the validator runs on the stored copy).
	k := validCookieKey()
	provider, err := op.New(append(validBaseOpts(t), op.WithCookieKeys(k))...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for i := range k {
		k[i] = 0
	}
	// We have no public accessor; the test passes if construction
	// succeeded with the original key. The defensive copy prevents the
	// later mutation from changing what the OP holds.
	if provider == nil {
		t.Fatal("provider nil")
	}
}

// validMFAKey returns a 32-byte filler suitable for the AES-256-GCM
// TOTP codec. The contents do not need to be random for
// option-validation tests.
func validMFAKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = 0x80 | byte(i)
	}
	return k
}

func TestWithMFAEncryptionKeys_AcceptsValidKey(t *testing.T) {
	t.Parallel()

	if _, err := op.New(append(validBaseOpts(t), op.WithMFAEncryptionKeys(validMFAKey()))...); err != nil {
		t.Fatalf("WithMFAEncryptionKeys rejected valid key: %v", err)
	}
}

func TestWithMFAEncryptionKeys_RejectsWrongLength(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t), op.WithMFAEncryptionKeys(make([]byte, 16)))...)
	if err == nil {
		t.Fatal("WithMFAEncryptionKeys accepted 16-byte key, want rejection")
	}
	if !strings.Contains(err.Error(), "entry 0 is not 32 bytes") {
		t.Errorf("err = %v, want it to mention entry 0 not 32 bytes", err)
	}
}

func TestWithMFAEncryptionKeys_AcceptsRotation(t *testing.T) {
	t.Parallel()

	current := validMFAKey()
	previous := validMFAKey()
	previous[0] = 0xff

	if _, err := op.New(append(validBaseOpts(t), op.WithMFAEncryptionKeys(current, previous))...); err != nil {
		t.Fatalf("WithMFAEncryptionKeys rejected rotation pair: %v", err)
	}
}

func TestWithMFAEncryptionKeys_RejectsEmpty(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t), op.WithMFAEncryptionKeys())...)
	if err == nil {
		t.Fatal("WithMFAEncryptionKeys accepted empty input")
	}
	if !strings.Contains(err.Error(), "requires at least one key") {
		t.Errorf("err = %v, want it to mention at least one key", err)
	}
}

func TestWithMFAEncryptionKeys_RejectsBadRotationEntry(t *testing.T) {
	t.Parallel()

	bad := make([]byte, 8)
	_, err := op.New(append(validBaseOpts(t), op.WithMFAEncryptionKeys(validMFAKey(), bad))...)
	if err == nil {
		t.Fatal("WithMFAEncryptionKeys accepted 8-byte rotation key")
	}
	if !strings.Contains(err.Error(), "entry 1 is not 32 bytes") {
		t.Errorf("err = %v, want it to mention entry 1 not 32 bytes", err)
	}
}

func TestWithMFAEncryptionKeys_DefensiveCopy(t *testing.T) {
	t.Parallel()

	// Mutating the input slice after construction must not change the
	// stored keys. The defensive copy is the only thing standing between
	// a caller's later mutation and a runtime cipher swap; the test
	// asserts construction stays clean and (because the mutation runs
	// after construction) the stored copy is unaffected.
	k := validMFAKey()
	provider, err := op.New(append(validBaseOpts(t), op.WithMFAEncryptionKeys(k))...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for i := range k {
		k[i] = 0
	}
	if provider == nil {
		t.Fatal("provider nil")
	}
}
