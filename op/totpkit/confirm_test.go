package totpkit_test

import (
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn/totp"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/totpkit"
)

// confirmFixture wires a fresh codec, enrolment, and a deterministic
// instant the Confirm tests share. The instant lives well after the
// 1970 epoch so the step counter never hits the negative-Unix branch.
type confirmFixture struct {
	codec   *totpkit.Codec
	pending *totpkit.Pending
	now     time.Time
	secret  []byte
}

func newConfirmFixture(t *testing.T) *confirmFixture {
	t.Helper()
	codec := newCodec(t)
	pending, err := totpkit.NewEnrolment(codec, "user-alice", "Example", "alice@example.com")
	if err != nil {
		t.Fatalf("NewEnrolment: %v", err)
	}
	secret, err := codec.Open(pending.Record.SecretCiphertext, []byte("user-alice"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return &confirmFixture{
		codec:   codec,
		pending: pending,
		now:     time.Unix(1700000000, 0).UTC(),
		secret:  secret,
	}
}

// TestConfirm_AcceptsValidCode pins the happy-path contract: a code
// computed from the plaintext secret at the verifier's instant
// confirms the enrolment, stamps ConfirmedAt = now, and stamps a
// non-zero LastAcceptedStep that the verify path will use as the
// replay-defence anchor.
func TestConfirm_AcceptsValidCode(t *testing.T) {
	t.Parallel()

	f := newConfirmFixture(t)
	code := totp.Code(f.secret, f.now)
	rec, err := totpkit.Confirm(f.codec, f.pending, code, f.now)
	if err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	if !rec.ConfirmedAt.Equal(f.now) {
		t.Errorf("ConfirmedAt=%v want %v", rec.ConfirmedAt, f.now)
	}
	if rec.LastAcceptedStep == 0 {
		t.Error("LastAcceptedStep=0; replay defence anchor missing")
	}
	if rec.Subject != "user-alice" {
		t.Errorf("Subject=%q want user-alice", rec.Subject)
	}
}

// TestConfirm_RejectsWrongCode covers the simple miss path: a
// deterministic wrong code returns ErrCodeRejected and the input
// pending record is not mutated. The submitted value is
// non-numeric so a stray match against a random secret is
// impossible — [totp.Code] always returns six decimal digits.
func TestConfirm_RejectsWrongCode(t *testing.T) {
	t.Parallel()

	f := newConfirmFixture(t)
	rec, err := totpkit.Confirm(f.codec, f.pending, "abcdef", f.now)
	if !errors.Is(err, totpkit.ErrCodeRejected) {
		t.Errorf("err=%v want ErrCodeRejected", err)
	}
	if rec != nil {
		t.Errorf("rec=%v want nil on failure", rec)
	}
	if !f.pending.Record.ConfirmedAt.IsZero() {
		t.Error("ConfirmedAt mutated on failure")
	}
	if f.pending.Record.LastAcceptedStep != 0 {
		t.Errorf("LastAcceptedStep=%d mutated on failure", f.pending.Record.LastAcceptedStep)
	}
}

// TestConfirm_RejectsCodeOutsideSkew pins the ±1-step window: a
// code computed two steps away (outside the acceptance window) is
// rejected. Widening the window beyond ±1 would double the
// confirm-time brute-force surface.
func TestConfirm_RejectsCodeOutsideSkew(t *testing.T) {
	t.Parallel()

	for _, offset := range []time.Duration{-2 * 30 * time.Second, +2 * 30 * time.Second} {
		t.Run(offset.String(), func(t *testing.T) {
			t.Parallel()
			f := newConfirmFixture(t)
			code := totp.Code(f.secret, f.now.Add(offset))
			_, err := totpkit.Confirm(f.codec, f.pending, code, f.now)
			if !errors.Is(err, totpkit.ErrCodeRejected) {
				t.Errorf("offset=%v err=%v want ErrCodeRejected", offset, err)
			}
		})
	}
}

// TestConfirm_AcceptsCodeInsideSkew pins the inverse property: a
// code computed at the neighbouring step (T-1 or T+1) is accepted.
// Authenticator app clocks drift by a few seconds in practice and
// the verify path tolerates it; the enrolment path MUST match so a
// drifted-clock user can still confirm on the first attempt.
func TestConfirm_AcceptsCodeInsideSkew(t *testing.T) {
	t.Parallel()

	for _, offset := range []time.Duration{-30 * time.Second, +30 * time.Second} {
		t.Run(offset.String(), func(t *testing.T) {
			t.Parallel()
			f := newConfirmFixture(t)
			code := totp.Code(f.secret, f.now.Add(offset))
			rec, err := totpkit.Confirm(f.codec, f.pending, code, f.now)
			if err != nil {
				t.Fatalf("offset=%v err=%v", offset, err)
			}
			if !rec.ConfirmedAt.Equal(f.now) {
				t.Errorf("ConfirmedAt=%v want %v", rec.ConfirmedAt, f.now)
			}
		})
	}
}

// TestConfirm_RejectsReplayWithinSameStep verifies the single-use
// contract: once the first Confirm stamps LastAcceptedStep, a
// second Confirm against the same pending value with the same code
// at the same instant MUST be rejected with ErrCodeRejected. The
// guard mirrors the verify-path same-step rejection so an
// embedder who accidentally re-submits the same pending cannot
// smuggle a fresh ConfirmedAt past the verify-side single-use
// guard later.
func TestConfirm_RejectsReplayWithinSameStep(t *testing.T) {
	t.Parallel()

	f := newConfirmFixture(t)
	code := totp.Code(f.secret, f.now)

	rec1, err := totpkit.Confirm(f.codec, f.pending, code, f.now)
	if err != nil {
		t.Fatalf("first Confirm: %v", err)
	}
	firstStep := rec1.LastAcceptedStep
	firstConfirm := rec1.ConfirmedAt
	if firstStep == 0 {
		t.Fatal("first Confirm did not stamp LastAcceptedStep")
	}

	// Second call: same code, same instant. ErrCodeRejected MUST
	// surface and the recorded LastAcceptedStep / ConfirmedAt MUST
	// NOT drift.
	if _, err := totpkit.Confirm(f.codec, f.pending, code, f.now); !errors.Is(err, totpkit.ErrCodeRejected) {
		t.Fatalf("replay err=%v want ErrCodeRejected", err)
	}
	if f.pending.Record.LastAcceptedStep != firstStep {
		t.Errorf("LastAcceptedStep=%d want %d (replay drifted the step)", f.pending.Record.LastAcceptedStep, firstStep)
	}
	if !f.pending.Record.ConfirmedAt.Equal(firstConfirm) {
		t.Errorf("ConfirmedAt drifted across replay: %v vs %v", f.pending.Record.ConfirmedAt, firstConfirm)
	}
}

// TestConfirm_RejectsWrongCodec pins the AAD / key binding contract:
// a Pending sealed under one codec cannot be opened by another codec
// (different key, same key length). Confirm surfaces ErrDecrypt
// verbatim so the embedder can route the failure to a generic
// "configuration changed; please re-enrol" page.
func TestConfirm_RejectsWrongCodec(t *testing.T) {
	t.Parallel()

	f := newConfirmFixture(t)
	other, err := totpkit.NewCodec(newKey(t))
	if err != nil {
		t.Fatalf("NewCodec other: %v", err)
	}
	code := totp.Code(f.secret, f.now)
	_, err = totpkit.Confirm(other, f.pending, code, f.now)
	if !errors.Is(err, totpkit.ErrDecrypt) {
		t.Errorf("err=%v want ErrDecrypt", err)
	}
}

// TestConfirm_RejectsBlankCode covers the trivial input-validation
// contract. A blank submission MUST fail with ErrCodeRejected
// without touching the codec; otherwise an attacker who can replay
// an empty submission would learn timing information about the
// open path.
func TestConfirm_RejectsBlankCode(t *testing.T) {
	t.Parallel()

	f := newConfirmFixture(t)
	for _, code := range []string{"", "1", "12345", "1234567"} {
		_, err := totpkit.Confirm(f.codec, f.pending, code, f.now)
		if !errors.Is(err, totpkit.ErrCodeRejected) {
			t.Errorf("code=%q err=%v want ErrCodeRejected", code, err)
		}
	}
	if !f.pending.Record.ConfirmedAt.IsZero() {
		t.Error("ConfirmedAt mutated despite blank code")
	}
}

// TestConfirm_DoesNotMutateOnFailure pins the no-side-effect
// guarantee on every failure path: a wrong code, a wrong codec, or
// a malformed input MUST leave the pending record unchanged so the
// embedder can retry without re-issuing the enrolment.
func TestConfirm_DoesNotMutateOnFailure(t *testing.T) {
	t.Parallel()

	f := newConfirmFixture(t)
	originalConfirm := f.pending.Record.ConfirmedAt
	originalStep := f.pending.Record.LastAcceptedStep
	originalCipher := append([]byte(nil), f.pending.Record.SecretCiphertext...)

	// Wrong code path. Non-digit input cannot match any real TOTP
	// regardless of the secret, so this branch is deterministic.
	if _, err := totpkit.Confirm(f.codec, f.pending, "abcdef", f.now); !errors.Is(err, totpkit.ErrCodeRejected) {
		t.Fatalf("wrong code: err=%v want ErrCodeRejected", err)
	}
	assertPendingUnchanged(t, f.pending, originalConfirm, originalStep, originalCipher)

	// Wrong codec path.
	other, _ := totpkit.NewCodec(newKey(t))
	if _, err := totpkit.Confirm(other, f.pending, totp.Code(f.secret, f.now), f.now); !errors.Is(err, totpkit.ErrDecrypt) {
		t.Fatalf("wrong codec: err=%v want ErrDecrypt", err)
	}
	assertPendingUnchanged(t, f.pending, originalConfirm, originalStep, originalCipher)

	// Blank / malformed code path.
	if _, err := totpkit.Confirm(f.codec, f.pending, "abc", f.now); !errors.Is(err, totpkit.ErrCodeRejected) {
		t.Fatalf("malformed code: err=%v want ErrCodeRejected", err)
	}
	assertPendingUnchanged(t, f.pending, originalConfirm, originalStep, originalCipher)
}

func assertPendingUnchanged(t *testing.T, p *totpkit.Pending, confirmedAt time.Time, lastStep int64, cipher []byte) {
	t.Helper()
	if !p.Record.ConfirmedAt.Equal(confirmedAt) {
		t.Errorf("ConfirmedAt drifted: %v vs %v", p.Record.ConfirmedAt, confirmedAt)
	}
	if p.Record.LastAcceptedStep != lastStep {
		t.Errorf("LastAcceptedStep drifted: %d vs %d", p.Record.LastAcceptedStep, lastStep)
	}
	if string(p.Record.SecretCiphertext) != string(cipher) {
		t.Error("SecretCiphertext mutated")
	}
}

// TestConfirm_NilPending covers the explicit nil-guard so a
// programming mistake at the controller boundary surfaces as a
// configuration sentinel rather than a nil-pointer panic.
func TestConfirm_NilPending(t *testing.T) {
	t.Parallel()

	codec := newCodec(t)
	_, err := totpkit.Confirm(codec, nil, "123456", time.Unix(1700000000, 0).UTC())
	if !errors.Is(err, totpkit.ErrPendingNil) {
		t.Errorf("err=%v want ErrPendingNil", err)
	}
}

// TestConfirm_NilRecord covers the variant where the embedder
// somehow constructs a Pending with a nil Record (defensive — the
// helper itself never produces this).
func TestConfirm_NilRecord(t *testing.T) {
	t.Parallel()

	codec := newCodec(t)
	pending := &totpkit.Pending{}
	_, err := totpkit.Confirm(codec, pending, "123456", time.Unix(1700000000, 0).UTC())
	if !errors.Is(err, totpkit.ErrPendingMissingRecord) {
		t.Errorf("err=%v want ErrPendingMissingRecord", err)
	}
}

// TestConfirm_NilCodec mirrors NewEnrolment's nil-codec guard.
func TestConfirm_NilCodec(t *testing.T) {
	t.Parallel()

	pending := &totpkit.Pending{Record: &store.TOTPRecord{Subject: "user-alice"}}
	_, err := totpkit.Confirm(nil, pending, "123456", time.Unix(1700000000, 0).UTC())
	if !errors.Is(err, totpkit.ErrCodecRequired) {
		t.Errorf("err=%v want ErrCodecRequired", err)
	}
}
