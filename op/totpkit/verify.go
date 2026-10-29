package totpkit

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/authn/totp"
	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/op/store"
)

// Verify checks code against subject's confirmed TOTP record in st and
// persists the outcome through the same path the login step uses: a wrong
// code advances the record's failure counter, an accepted code advances
// LastAcceptedStep, so a code redeemed at login cannot be redeemed again
// here, nor the other way round. now is the instant the code is judged at,
// normally the current wall-clock time.
//
// Use it to re-prove possession of the factor before replacing or removing
// it. It returns nil only for a correct, unused code.
//
// Verify is bounded only by the TOTP record's own counters (30 failures in
// 24 hours lock the record for 1 hour, 90 lock it for 24 hours). It does not
// take part in the login cross-factor lockout. Put the calling page behind a
// recent auth_time and its own rate limit.
//
// Errors:
//   - [ErrCodecRequired] / [ErrStoreRequired] when codec / st is nil.
//   - [ErrNotEnrolled] when there is no record or it is unconfirmed.
//   - [ErrLocked] while the record is locked.
//   - [ErrCodeRejected] for a wrong code or one already accepted.
//   - Any store or decryption fault, wrapped.
//
// Stable since v1.5.
func Verify(ctx context.Context, codec *Codec, st store.TOTPStore, subject, code string, now time.Time) error {
	if codec == nil {
		return ErrCodecRequired
	}
	if st == nil {
		return ErrStoreRequired
	}
	v := &totp.Verifier{Codec: codec, Clock: timex.ClockFunc(func() time.Time { return now })}
	_, err := totp.VerifyAndRecord(ctx, st, v, subject, code)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, authn.ErrFactorNotEnrolled), errors.Is(err, totp.ErrNotConfirmed):
		return ErrNotEnrolled
	case errors.Is(err, totp.ErrLocked), errors.Is(err, totp.ErrResetRequired):
		return ErrLocked
	case errors.Is(err, totp.ErrWrongCode):
		return ErrCodeRejected
	default:
		return fmt.Errorf("totpkit: verify: %w", err)
	}
}
