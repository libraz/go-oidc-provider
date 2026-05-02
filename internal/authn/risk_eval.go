package authn

import (
	"context"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn/risk"
)

// This file is the orchestrator's "risk" responsibility seam: the
// PreFactor / PostFactor consult helpers that adapt the orchestrator's
// State into the risk sub-package's Input shape and translate the
// returned risk.Outcome back into the orchestrator's authn-package
// types (FactorType, denied flag).
//
// The actual decision wiring lives in internal/authn/risk; this file
// is a thin per-stage adapter that keeps orchestrator.go free of the
// per-call boilerplate. The pre-split call sites had identical bodies
// inlined three times (PreFactor, PostFactor, LoginFlow once-per-chain);
// consolidating them here makes a future fourth stage (e.g.
// TokenExchange) a one-line addition rather than a copy-paste.

// runRiskPreFactor consults the assessor at PreFactor and returns the
// factor-type filter the orchestrator should apply (empty = no
// filter), plus a denied flag.
func (o *Orchestrator) runRiskPreFactor(ctx context.Context, st State, now time.Time) ([]FactorType, bool, error) {
	in := buildRiskInput(st, "")
	in.AuthTime = now
	res, err := risk.RunPreFactor(ctx, o.riskAssessor, in)
	if err != nil {
		return nil, false, err
	}
	if res.Denied {
		return nil, true, nil
	}
	return factorTypesFromStrings(res.Required), false, nil
}

// runRiskPostFactor consults the assessor after a successful factor
// completion. The current implementation honours [RiskDeny] only;
// [RiskRequire] at PostFactor is queued by the next PreFactor pass
// (the orchestrator does not preempt the current factor).
func (o *Orchestrator) runRiskPostFactor(ctx context.Context, st State, now time.Time, last FactorType) (bool, error) {
	in := buildRiskInput(st, last)
	in.AuthTime = now
	return risk.RunPostFactor(ctx, o.riskAssessor, in)
}
