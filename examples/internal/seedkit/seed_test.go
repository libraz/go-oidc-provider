//go:build example

package seedkit_test

import (
	"context"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/examples/internal/seedkit"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
	"github.com/libraz/go-oidc-provider/op/totpkit"
)

// newCodec constructs a fresh codec under a random key for tests.
// The helper centralises the rand.Read call so production seedkit
// code never reaches for crypto/rand on its own.
func newCodec(t *testing.T) *totpkit.Codec {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	c, err := totpkit.NewCodec(k)
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	return c
}

// TestSeed_PasswordOnly pins the no-TOTP path: a Seed call without
// SeedOptions.TOTP must materialise the user + password records and
// return (nil, nil). The user MUST be retrievable through both
// FindByUsername and ReadPasswordHash; the TOTP store MUST remain
// empty.
func TestSeed_PasswordOnly(t *testing.T) {
	t.Parallel()

	st := inmem.New()
	res, err := seedkit.Seed(context.Background(), st, seedkit.SeedOptions{
		Subject:  "user-alice",
		Username: "alice",
		Password: "correct-horse-battery-staple",
		Claims:   map[string]any{"name": "Alice"},
	})
	if err != nil {
		t.Fatalf("Seed: %v", err)
	}
	if res != nil {
		t.Errorf("Seed(no TOTP) result = %+v, want nil", res)
	}

	pw := st.UserPasswords()
	gotUser, err := pw.FindByUsername(context.Background(), "alice")
	if err != nil {
		t.Fatalf("FindByUsername: %v", err)
	}
	if gotUser.Subject != "user-alice" {
		t.Errorf("Subject = %q, want user-alice", gotUser.Subject)
	}
	if gotUser.Claims["name"] != "Alice" {
		t.Errorf("Claims[name] = %v, want Alice", gotUser.Claims["name"])
	}
	hash, err := pw.ReadPasswordHash(context.Background(), "user-alice")
	if err != nil {
		t.Fatalf("ReadPasswordHash: %v", err)
	}
	if len(hash) == 0 {
		t.Error("ReadPasswordHash returned empty slice")
	}

	// The TOTP store must be empty — no enrolment was requested.
	if _, err := st.TOTPs().Get(context.Background(), "user-alice"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("TOTPs().Get err = %v, want ErrNotFound", err)
	}
}

// TestSeed_WithTOTP pins the full path: SeedOptions.TOTP non-nil
// must materialise a confirmed [store.TOTPRecord]. The record MUST
// be retrievable via st.TOTPs().Get; ConfirmedAt MUST equal the
// supplied Now; the SecretCiphertext MUST decrypt under the codec
// with the subject as AAD; and the decrypted base32 representation
// MUST match SeedResult.SecretBase32.
func TestSeed_WithTOTP(t *testing.T) {
	t.Parallel()

	codec := newCodec(t)
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

	st := inmem.New()
	res, err := seedkit.Seed(context.Background(), st, seedkit.SeedOptions{
		Subject:  "user-alice",
		Username: "alice",
		Password: "hunter2",
		TOTP: &seedkit.SeedTOTP{
			Codec:   codec,
			Issuer:  "Example",
			Account: "alice@example.com",
			Now:     now,
		},
	})
	if err != nil {
		t.Fatalf("Seed: %v", err)
	}
	if res == nil {
		t.Fatal("SeedResult is nil for TOTP-enabled call")
	}
	if res.OTPAuthURI == "" {
		t.Error("SeedResult.OTPAuthURI is empty")
	}
	if res.SecretBase32 == "" {
		t.Error("SeedResult.SecretBase32 is empty")
	}
	if res.QRTerm == "" {
		t.Error("SeedResult.QRTerm is empty")
	}

	rec, err := st.TOTPs().Get(context.Background(), "user-alice")
	if err != nil {
		t.Fatalf("TOTPs().Get: %v", err)
	}
	if rec.ConfirmedAt.IsZero() {
		t.Error("ConfirmedAt is zero (record was not pre-confirmed)")
	}
	if !rec.ConfirmedAt.Equal(now) {
		t.Errorf("ConfirmedAt = %v, want %v", rec.ConfirmedAt, now)
	}
	wantStep := now.Unix() / 30
	if rec.LastAcceptedStep != wantStep {
		t.Errorf("LastAcceptedStep = %d, want %d", rec.LastAcceptedStep, wantStep)
	}

	// Decrypt the sealed secret under the same codec / AAD the
	// verify path uses and assert it round-trips through base32 to
	// match the operator-visible string.
	plain, err := codec.Open(rec.SecretCiphertext, []byte("user-alice"))
	if err != nil {
		t.Fatalf("codec.Open: %v", err)
	}
	if encoded := encodeBase32NoPad(plain); encoded != res.SecretBase32 {
		t.Errorf("base32(decrypted) = %q, want %q", encoded, res.SecretBase32)
	}
}

// TestSeed_RejectsBlankSubject pins the validation gate that the
// helper refuses a missing subject. Without it, the inmem userStore
// would happily index a user under the empty key and shadow every
// later lookup.
func TestSeed_RejectsBlankSubject(t *testing.T) {
	t.Parallel()

	st := inmem.New()
	_, err := seedkit.Seed(context.Background(), st, seedkit.SeedOptions{
		Subject:  "",
		Username: "alice",
		Password: "pw",
	})
	if !errors.Is(err, seedkit.ErrSeedSubjectRequired) {
		t.Errorf("err = %v, want ErrSeedSubjectRequired", err)
	}
}

// TestSeed_RejectsBlankUsername pins the validation gate against
// missing usernames; the PrimaryPassword Step looks the user up by
// username, so a blank one breaks login.
func TestSeed_RejectsBlankUsername(t *testing.T) {
	t.Parallel()

	st := inmem.New()
	_, err := seedkit.Seed(context.Background(), st, seedkit.SeedOptions{
		Subject:  "user-alice",
		Username: "",
		Password: "pw",
	})
	if !errors.Is(err, seedkit.ErrSeedUsernameRequired) {
		t.Errorf("err = %v, want ErrSeedUsernameRequired", err)
	}
}

// TestSeed_RejectsBlankPassword pins the validation gate against
// missing passwords; an empty hash would let anyone log in.
func TestSeed_RejectsBlankPassword(t *testing.T) {
	t.Parallel()

	st := inmem.New()
	_, err := seedkit.Seed(context.Background(), st, seedkit.SeedOptions{
		Subject:  "user-alice",
		Username: "alice",
		Password: "",
	})
	if !errors.Is(err, seedkit.ErrSeedPasswordRequired) {
		t.Errorf("err = %v, want ErrSeedPasswordRequired", err)
	}
}

// TestSeed_RejectsNilStore pins the validation gate against a nil
// store argument; without it, the helper would panic deep in the
// substore accessor.
func TestSeed_RejectsNilStore(t *testing.T) {
	t.Parallel()

	_, err := seedkit.Seed(context.Background(), nil, seedkit.SeedOptions{
		Subject:  "user-alice",
		Username: "alice",
		Password: "pw",
	})
	if !errors.Is(err, seedkit.ErrSeedStoreRequired) {
		t.Errorf("err = %v, want ErrSeedStoreRequired", err)
	}
}

// TestSeed_TOTPRequiresAllFields pins that an incomplete SeedTOTP
// (nil codec, blank issuer, blank account) is rejected before any
// substore mutation. The helper must surface a distinct sentinel
// for each missing field so an operator reading the error knows
// which input they need to supply.
func TestSeed_TOTPRequiresAllFields(t *testing.T) {
	t.Parallel()

	codec := newCodec(t)
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	base := seedkit.SeedOptions{
		Subject:  "user-alice",
		Username: "alice",
		Password: "pw",
	}

	cases := []struct {
		name string
		totp *seedkit.SeedTOTP
		want error
	}{
		{
			name: "nil codec",
			totp: &seedkit.SeedTOTP{Codec: nil, Issuer: "Example", Account: "alice@example.com", Now: now},
			want: seedkit.ErrSeedTOTPCodecRequired,
		},
		{
			name: "blank issuer",
			totp: &seedkit.SeedTOTP{Codec: codec, Issuer: "", Account: "alice@example.com", Now: now},
			want: seedkit.ErrSeedTOTPIssuerRequired,
		},
		{
			name: "blank account",
			totp: &seedkit.SeedTOTP{Codec: codec, Issuer: "Example", Account: "", Now: now},
			want: seedkit.ErrSeedTOTPAccountRequired,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			st := inmem.New()
			opts := base
			opts.TOTP = tc.totp
			if _, err := seedkit.Seed(context.Background(), st, opts); !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
			// And no substore mutation happened.
			if _, err := st.TOTPs().Get(context.Background(), "user-alice"); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("TOTP record exists after rejected Seed; err = %v, want ErrNotFound", err)
			}
		})
	}
}

// encodeBase32NoPad re-encodes raw using the same alphabet and
// padding policy [totpkit.NewEnrolment] uses (RFC 4648 base32 with
// padding stripped). The helper duplicates the encoding inline so
// the test does not depend on internal package state.
func encodeBase32NoPad(raw []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	if len(raw) == 0 {
		return ""
	}
	out := make([]byte, 0, ((len(raw)*8)+4)/5)
	var buf uint64
	bits := 0
	for _, b := range raw {
		buf = (buf << 8) | uint64(b)
		bits += 8
		for bits >= 5 {
			bits -= 5
			out = append(out, alphabet[(buf>>bits)&0x1f])
		}
	}
	if bits > 0 {
		out = append(out, alphabet[(buf<<(5-bits))&0x1f])
	}
	return string(out)
}
