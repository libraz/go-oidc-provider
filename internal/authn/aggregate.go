package authn

import (
	"sort"

	"github.com/libraz/go-oidc-provider/op"
)

// amrMFA is the RFC 8176 §2 token that signals the user authenticated
// with multiple distinct factors during this login. The library appends
// it to the aggregated amr slice when the chain saw two or more
// **different** RFC 8176 tokens and the resulting assurance level is
// at least [op.AAL2]; see [Aggregate] for the precise rule.
const amrMFA = "mfa"

// Aggregate folds a per-step factor slice into the (acr, amr, level)
// triple the session record stores. The function is total: every input,
// including a nil or empty slice, produces a defined output.
//
// Semantics:
//
//   - level is the maximum [Factor.AssuranceLevel] across factors. An
//     empty slice yields [op.AAL0].
//   - amr is the sorted, de-duplicated set of non-empty
//     [Factor.AMRValue] results. Foreign factor types contribute the
//     empty string and are filtered out, so they cannot dilute the
//     claim.
//   - acr is level.ACRURI(); empty when level is [op.AAL0] or out of
//     range.
//
// Multi-factor signalling: if the aggregated amr set contains at least
// two distinct RFC 8176 tokens AND the resulting level is [op.AAL2] or
// higher, Aggregate appends "mfa" to amr (RFC 8176 §2). The "distinct"
// rule matters: two TOTP verifications during a step-up flow both emit
// "otp", so the slice carries one entry, no "mfa" appears, and the user
// is correctly classified as single-factor. A password-then-TOTP login
// emits {"pwd", "otp"}, which earns the "mfa" tag.
//
// Aggregate does not mutate factors. Callers MAY pass a slice they
// continue to read after the call.
func Aggregate(factors []Factor) (acr string, amr []string, level op.AAL) {
	if len(factors) == 0 {
		return "", nil, op.AAL0
	}

	// Collect distinct, non-empty AMR values. A small map suffices;
	// the per-login factor count is bounded by the chain length
	// (typically 1-3), so allocation overhead is negligible.
	seen := make(map[string]struct{}, len(factors))
	for _, f := range factors {
		if f.AssuranceLevel > level {
			level = f.AssuranceLevel
		}
		v := f.AMRValue()
		if v == "" {
			continue
		}
		seen[v] = struct{}{}
	}

	if len(seen) == 0 {
		// Every factor was foreign or contributed no amr value; we
		// still report the level so a custom authenticator can lift
		// the session, but amr stays nil so the id_token encoder
		// drops the claim.
		return level.ACRURI(), nil, level
	}

	amr = make([]string, 0, len(seen)+1)
	for v := range seen {
		amr = append(amr, v)
	}
	if len(seen) >= 2 && level >= op.AAL2 {
		amr = append(amr, amrMFA)
	}
	sort.Strings(amr)

	return level.ACRURI(), amr, level
}
