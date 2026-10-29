package totpkit_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn/totp"
	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
	"github.com/libraz/go-oidc-provider/op/totpkit"
)

const verifySubject = "user-alice"

type verifyFixture struct {
	codec  *totpkit.Codec
	st     store.TOTPStore
	secret []byte
	// now is the instant Verify judges at, two steps past enrolment so the
	// confirm-time step is never the one under test.
	now time.Time
}

// newVerifyFixture enrols and confirms verifySubject in an in-memory store.
func newVerifyFixture(t *testing.T) *verifyFixture {
	t.Helper()
	codec := newCodec(t)
	st := inmem.New().TOTPs()
	confirmAt := time.Unix(1700000000, 0).UTC()

	pending, err := totpkit.NewEnrolment(codec, verifySubject, "Example", "alice@example.com")
	if err != nil {
		t.Fatalf("NewEnrolment: %v", err)
	}
	secret, err := codec.Open(pending.Record.SecretCiphertext, []byte(verifySubject))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	rec, err := totpkit.Confirm(codec, pending, totp.Code(secret, confirmAt), confirmAt)
	if err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	if err := st.Put(context.Background(), rec); err != nil {
		t.Fatalf("Put: %v", err)
	}
	return &verifyFixture{codec: codec, st: st, secret: secret, now: confirmAt.Add(90 * time.Second)}
}

func (f *verifyFixture) record(t *testing.T) *store.TOTPRecord {
	t.Helper()
	rec, err := f.st.Get(context.Background(), verifySubject)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	return rec
}

// wrongCode is not numeric, so it can never match a generated code.
const wrongCode = "abcdef"

func TestVerify(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("correct", func(t *testing.T) {
		t.Parallel()
		f := newVerifyFixture(t)
		if err := totpkit.Verify(ctx, f.codec, f.st, verifySubject, totp.Code(f.secret, f.now), f.now); err != nil {
			t.Fatalf("Verify: %v", err)
		}
	})

	t.Run("replay", func(t *testing.T) {
		t.Parallel()
		f := newVerifyFixture(t)
		code := totp.Code(f.secret, f.now)
		if err := totpkit.Verify(ctx, f.codec, f.st, verifySubject, code, f.now); err != nil {
			t.Fatalf("first Verify: %v", err)
		}
		err := totpkit.Verify(ctx, f.codec, f.st, verifySubject, code, f.now)
		if !errors.Is(err, totpkit.ErrCodeRejected) {
			t.Fatalf("replay err=%v want ErrCodeRejected", err)
		}
		if got := f.record(t).FailedCount; got != 0 {
			t.Errorf("FailedCount=%d after replay; want 0", got)
		}
	})

	t.Run("locked", func(t *testing.T) {
		t.Parallel()
		f := newVerifyFixture(t)
		for i := 0; i < 30; i++ {
			err := totpkit.Verify(ctx, f.codec, f.st, verifySubject, wrongCode, f.now)
			if !errors.Is(err, totpkit.ErrCodeRejected) {
				t.Fatalf("wrong attempt %d err=%v want ErrCodeRejected", i+1, err)
			}
		}
		err := totpkit.Verify(ctx, f.codec, f.st, verifySubject, totp.Code(f.secret, f.now), f.now)
		if !errors.Is(err, totpkit.ErrLocked) {
			t.Fatalf("err=%v want ErrLocked", err)
		}
	})

	t.Run("not enrolled", func(t *testing.T) {
		t.Parallel()
		f := newVerifyFixture(t)
		err := totpkit.Verify(ctx, f.codec, f.st, "user-bob", "123456", f.now)
		if !errors.Is(err, totpkit.ErrNotEnrolled) {
			t.Fatalf("err=%v want ErrNotEnrolled", err)
		}
	})

	t.Run("unconfirmed", func(t *testing.T) {
		t.Parallel()
		f := newVerifyFixture(t)
		pending, err := totpkit.NewEnrolment(f.codec, "user-carol", "Example", "carol@example.com")
		if err != nil {
			t.Fatalf("NewEnrolment: %v", err)
		}
		if err := f.st.Put(ctx, pending.Record); err != nil {
			t.Fatalf("Put: %v", err)
		}
		err = totpkit.Verify(ctx, f.codec, f.st, "user-carol", "123456", f.now)
		if !errors.Is(err, totpkit.ErrNotEnrolled) {
			t.Fatalf("err=%v want ErrNotEnrolled", err)
		}
	})

	t.Run("nil codec", func(t *testing.T) {
		t.Parallel()
		f := newVerifyFixture(t)
		err := totpkit.Verify(ctx, nil, f.st, verifySubject, "123456", f.now)
		if !errors.Is(err, totpkit.ErrCodecRequired) {
			t.Fatalf("err=%v want ErrCodecRequired", err)
		}
	})

	t.Run("nil store", func(t *testing.T) {
		t.Parallel()
		f := newVerifyFixture(t)
		err := totpkit.Verify(ctx, f.codec, nil, verifySubject, "123456", f.now)
		if !errors.Is(err, totpkit.ErrStoreRequired) {
			t.Fatalf("err=%v want ErrStoreRequired", err)
		}
	})

	t.Run("step already accepted at login is refused", func(t *testing.T) {
		t.Parallel()
		f := newVerifyFixture(t)
		code := totp.Code(f.secret, f.now)
		login := &totp.Verifier{Codec: f.codec, Clock: timex.ClockFunc(func() time.Time { return f.now })}
		if _, err := totp.VerifyAndRecord(ctx, f.st, login, verifySubject, code); err != nil {
			t.Fatalf("login-path verify: %v", err)
		}
		err := totpkit.Verify(ctx, f.codec, f.st, verifySubject, code, f.now)
		if !errors.Is(err, totpkit.ErrCodeRejected) {
			t.Fatalf("err=%v want ErrCodeRejected", err)
		}
	})

	t.Run("failure increments FailedCount", func(t *testing.T) {
		t.Parallel()
		f := newVerifyFixture(t)
		err := totpkit.Verify(ctx, f.codec, f.st, verifySubject, wrongCode, f.now)
		if !errors.Is(err, totpkit.ErrCodeRejected) {
			t.Fatalf("err=%v want ErrCodeRejected", err)
		}
		if got := f.record(t).FailedCount; got != 1 {
			t.Fatalf("FailedCount=%d want 1", got)
		}
	})
}
