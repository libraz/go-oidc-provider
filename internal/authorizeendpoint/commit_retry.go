package authorizeendpoint

import (
	"context"
	"errors"

	"github.com/libraz/go-oidc-provider/op/store"
)

// maxCommitAttempts bounds the retries [retryOnGrantConflict] makes
// against an optimistic-lock conflict. A conflict there means a second
// authorization for the same (subject, client) amended the grant between
// this transaction's read and its commit, so the losing side only has to
// re-read and re-apply. Three attempts covers the ordinary two-tab case
// and the occasional three-way pile-up; a subject whose grant is
// contended past that is not a user racing themselves, and spinning would
// turn the endpoint into a load amplifier.
const maxCommitAttempts = 3

// retryOnGrantConflict runs commit until it succeeds, fails with
// something other than [store.ErrConflict], or exhausts
// [maxCommitAttempts]. It is the single retry every /authorize path that
// mints an authorization code goes through, whether the code comes out of
// an answered interaction or out of a silent mint, so a backend that
// versions the grant record cannot fail one of those and not the other.
//
// A lost optimistic-lock race is retried rather than surfaced. Grants are
// amended, not replaced — a second authorization adds to what the grant
// already held — so a backend that versions the record makes the loser
// fail instead of silently dropping the winner's additions. That is the
// correct store-level answer and the wrong answer for the user in front
// of it: nothing about their request was invalid, and the amendment they
// lost is one a re-read reproduces exactly.
//
// A caller may only be wrapped in this if re-running its body is
// indistinguishable from running it once. Two properties buy that, and
// both callers hold them: the identifier of everything the body persists
// is fixed before the first attempt rather than drawn per attempt, so a
// retry rewrites the same authorization code instead of minting a second
// one; and every write the body makes is staged inside a transaction it
// owns, so an attempt that lost wrote nothing — no code, and no consumed
// request_uri — while an attempt whose commit did land is recognised on
// re-entry rather than repeated.
//
// commit's second result is the caller's own flag (whether a code was
// freshly minted, whether the failure came from the PAR consumption) and
// passes through untouched.
func retryOnGrantConflict[T any](ctx context.Context, commit func() (T, bool, error)) (T, bool, error) {
	for attempt := 1; ; attempt++ {
		value, flag, err := commit()
		// The bound is compared with >= rather than ==: an equality test
		// would never hold if the constant were ever edited to zero, and
		// the loop would spin forever on exactly the contention it exists
		// to bound.
		if err == nil || !errors.Is(err, store.ErrConflict) || attempt >= maxCommitAttempts {
			return value, flag, err
		}
		if ctx.Err() != nil {
			// The caller went away mid-retry. Report the conflict that
			// caused the retry rather than the cancellation, so the reason
			// the attempt was in flight is not lost.
			return value, flag, err
		}
	}
}
