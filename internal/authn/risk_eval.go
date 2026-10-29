package authn

import (
	"context"

	"github.com/libraz/go-oidc-provider/internal/authn/risk"
)

// This file is the orchestrator's "risk" responsibility seam: the
// once-per-chain consult that adapts the orchestrator's State into the
// risk sub-package's Input shape and translates the returned outcome
// back into the orchestrator's authn-package types. The decision wiring
// itself lives in internal/authn/risk.

// runRiskOnceForLoginFlow consults Risk at chain start when no step has
// completed yet, caches the score on st.RiskScoreCached and the
// required-factor set on st.RiskRequiredFactors, and returns whether the
// chain is denied. Subsequent calls during the same chain are no-ops;
// this is the §3.1 budget invariant ("Risk.Assess at most once per
// chain").
//
// A [RiskRequire] outcome that names factors is recorded rather than
// acted on here: the consult happens before Primary has even run, so the
// obligation has to survive until the chain would otherwise grant. See
// [Orchestrator.transitionToAfterAuthn] for where it is discharged.
//
// The mapping from [RiskOutcome] onto [State.RiskScoreCached]:
//
//   - [RiskOutcome.Score] non-zero — used verbatim. This is the path
//     an assessor takes to surface [RiskScoreMedium], which the
//     Decision-only fallback cannot reach.
//   - Score zero, Decision = [RiskAllow] — cached as [RiskScoreLow]
//     (a signal was observed but nothing actionable).
//   - Score zero, Decision = [RiskRequire] — cached as
//     [RiskScoreHigh] (the assessor recommends a stronger factor).
//   - Decision = [RiskDeny] — handled separately; the orchestrator
//     returns [ErrRiskDenied] without caching.
//
// Rule predicates `score >= threshold` see the cached value
// uniformly regardless of which path produced it.
func (o *Orchestrator) runRiskOnceForLoginFlow(ctx context.Context, st State, flow *CompiledLoginFlow) (State, bool, error) {
	if flow.risk == nil {
		return st, false, nil
	}
	if st.RiskScoreCached != RiskScoreNone {
		return st, false, nil
	}
	in := o.buildRiskInput(st, "")
	in.AuthTime = st.AuthTime
	res, err := risk.RunOnceForLoginFlow(ctx, wrapRiskAssessor(flow.risk), in)
	if err != nil {
		return st, false, err
	}
	if res.Denied {
		return st, true, nil
	}
	if res.Score != risk.ScoreNone {
		st.RiskScoreCached = riskScoreFromPkg(res.Score)
	}
	st.RiskRequiredFactors = factorTypesFromStrings(res.Required)
	st.NewDeviceCached = res.NewDevice
	return st, false, nil
}
