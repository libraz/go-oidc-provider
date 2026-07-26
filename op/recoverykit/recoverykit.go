// Package recoverykit issues the recovery-code batches that
// [op.StepRecoveryCode] consumes.
//
// The login flow can spend a recovery code but has no way to create
// one: enrolment happens on the embedder's account-management page,
// which the library does not own. Without this package that leaves
// [op.StepRecoveryCode] configurable and unusable — the code format,
// the argon2id parameters, and the batch size are fixed by the
// verifier and deliberately not configurable, so an embedder cannot
// hand-build a [store.RecoveryBatch] the verifier will accept.
//
// The split between the two fields of [Result] is the whole safety
// story. Batch carries hashes only and is what goes to storage; Codes
// carries the plaintext and has exactly one sanctioned destination,
// the user's screen or printer, exactly once. Nothing here logs,
// audits, or persists the plaintext, and callers MUST NOT either — a
// recovery code in a log is a standing credential with no expiry and
// no second factor in front of it.
//
// Typical use, from an account page after the user has
// re-authenticated:
//
//	res, err := recoverykit.Replace(ctx, st.RecoveryCodes(), subject)
//	if err != nil {
//	    return err
//	}
//	renderOnce(res.Codes) // and never again
//
// Replacement is wholesale: a new batch invalidates every code from
// the previous one. That is the intended semantics — "I lost my
// printout" and "I think someone saw my printout" are the same
// request.
//
// Stable since v1.0.
package recoverykit

import (
	"context"
	"errors"

	"github.com/libraz/go-oidc-provider/internal/authn/recovery"
	"github.com/libraz/go-oidc-provider/op/store"
)

// Result is one freshly minted batch, split into the half that is
// persisted and the half that is shown.
type Result struct {
	// Batch is the persistent representation: hashes only, every slot
	// unconsumed. Safe to hand to [store.RecoveryStore.Put].
	Batch *store.RecoveryBatch

	// Codes are the human-readable codes, in the same order as
	// Batch.Codes. Display them once and drop them. The order carries
	// no security meaning.
	Codes []string
}

// Generate mints a batch for subject without persisting it. Use it
// when the batch has to be written inside a transaction the caller
// owns, or shown for confirmation before it takes effect; otherwise
// prefer [Replace], which cannot leave the user holding codes the
// store never accepted.
//
// The call reads from crypto/rand and spends CPU on argon2id hashing.
// On a typical server the batch completes in well under a second, so
// calling it inline from a handler is fine; embedders chasing
// sub-100ms responses generate asynchronously and stream the plaintext
// to a follow-up GET.
func Generate(ctx context.Context, subject string) (*Result, error) {
	if subject == "" {
		return nil, errors.New("recoverykit: subject is required")
	}
	res, err := (&recovery.Verifier{}).Generate(ctx, subject)
	if err != nil {
		return nil, err
	}
	return &Result{Batch: res.Batch, Codes: res.PlaintextCodes}, nil
}

// Replace mints a batch and persists it in one call, overwriting any
// prior batch for subject. The plaintext is returned only after the
// store has accepted the batch, so a storage failure cannot leave the
// user holding codes that will never verify.
func Replace(ctx context.Context, recoveryStore store.RecoveryStore, subject string) (*Result, error) {
	if recoveryStore == nil {
		return nil, errors.New("recoverykit: store is required")
	}
	res, err := (&recovery.Verifier{}).Replace(ctx, recoveryStore, subject)
	if err != nil {
		return nil, err
	}
	return &Result{Batch: res.Batch, Codes: res.PlaintextCodes}, nil
}
