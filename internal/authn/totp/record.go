package totp

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/op/store"
)

// maxPersistRetries bounds the re-read / re-verify loop that follows a lost
// conditional write.
const maxPersistRetries = 16

// VerifyAndRecord loads subject's record from st, checks code through v and
// persists the outcome: a compare-and-swap for a wrong code or a reset, an
// atomic Accept for a success. A lost write re-reads and re-verifies, so a
// finite set of concurrent guesses increments the counter once per request
// and a concurrent acceptance of the same code surfaces as a replay.
//
// The verifier's sentinel ([ErrWrongCode], [ErrReplayed], [ErrLocked],
// [ErrResetRequired], [ErrNotConfirmed]) is returned unwrapped with the
// [Result] it came with. A missing record is [authn.ErrFactorNotEnrolled]
// and an exhausted retry budget is [ErrRetry]. Store faults are wrapped. The
// cross-factor lockout is the caller's concern.
func VerifyAndRecord(ctx context.Context, st store.TOTPStore, v *Verifier, subject, code string) (*Result, error) {
	for retries := 0; retries < maxPersistRetries; retries++ {
		rec, err := st.Get(ctx, subject)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return nil, fmt.Errorf("totp: load record: %w", err)
		}
		if err != nil || rec == nil {
			return nil, authn.ErrFactorNotEnrolled
		}

		previous := cloneRecord(rec)
		res, verr := v.Verify(ctx, rec, code)
		// Locked and replayed leave the record unchanged and success goes
		// through Accept below; the remaining outcomes use CAS to keep
		// every counter update.
		if res != nil && res.Record != nil && res.Outcome != OutcomeLocked &&
			res.Outcome != OutcomeSuccess && res.Outcome != OutcomeReplayed {
			if perr := st.CompareAndSwap(ctx, previous, res.Record); perr != nil {
				if errors.Is(perr, store.ErrAlreadyConsumed) {
					continue
				}
				return nil, fmt.Errorf("totp: persist record: %w", perr)
			}
		}
		if verr == nil {
			if perr := st.Accept(ctx, res.Record); perr != nil {
				if errors.Is(perr, store.ErrAlreadyConsumed) {
					continue
				}
				return nil, fmt.Errorf("totp: accept record: %w", perr)
			}
		}
		return res, verr
	}
	return nil, ErrRetry
}

func cloneRecord(r *store.TOTPRecord) *store.TOTPRecord {
	if r == nil {
		return nil
	}
	out := *r
	out.SecretCiphertext = slices.Clone(r.SecretCiphertext)
	return &out
}
