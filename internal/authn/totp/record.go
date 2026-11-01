package totp

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/op/store"
)

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
	for range authn.MaxPersistRetries {
		rec, err := st.Get(ctx, subject)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return nil, fmt.Errorf("totp: load record: %w", err)
		}
		if err != nil || rec == nil {
			return nil, authn.ErrFactorNotEnrolled
		}

		previous := cloneRecord(rec)
		res, verr := v.Verify(ctx, rec, code)
		retry, perr := persistOutcome(ctx, st, previous, res, verr)
		if perr != nil {
			return nil, perr
		}
		if retry {
			continue
		}
		return res, verr
	}
	return nil, ErrRetry
}

// persistOutcome writes the verifier's verdict back. Locked and replayed
// leave the record unchanged and success goes through Accept; the remaining
// outcomes use CAS to keep every counter update. retry reports a lost race
// that the caller resolves by re-reading the record.
func persistOutcome(ctx context.Context, st store.TOTPStore, previous *store.TOTPRecord, res *Result, verr error) (retry bool, err error) {
	if res != nil && res.Record != nil && res.Outcome != OutcomeLocked &&
		res.Outcome != OutcomeSuccess && res.Outcome != OutcomeReplayed {
		if perr := st.CompareAndSwap(ctx, previous, res.Record); perr != nil {
			if errors.Is(perr, store.ErrAlreadyConsumed) {
				return true, nil
			}
			return false, fmt.Errorf("totp: persist record: %w", perr)
		}
	}
	if verr == nil {
		if perr := st.Accept(ctx, res.Record); perr != nil {
			if errors.Is(perr, store.ErrAlreadyConsumed) {
				return true, nil
			}
			return false, fmt.Errorf("totp: accept record: %w", perr)
		}
	}
	return false, nil
}

func cloneRecord(r *store.TOTPRecord) *store.TOTPRecord {
	if r == nil {
		return nil
	}
	out := *r
	out.SecretCiphertext = slices.Clone(r.SecretCiphertext)
	return &out
}
