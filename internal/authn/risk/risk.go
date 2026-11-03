// Package risk wraps the orchestrator's [Assessor] consult sites so the
// state machine in internal/authn/orchestrator.go does not have to
// inline the input-build / decision-dispatch wiring at every call.
//
// The package defines its own [Input] / [Outcome] / [Decision] /
// [Score] / [Stage] surface so it can stand alone without importing
// internal/authn (which would form a cycle: the parent imports this
// package). The parent package adapts authn.RiskInput / RiskOutcome at
// the call site; the shapes are intentionally identical.
package risk

import (
	"context"
	"net/netip"
	"time"
)

// Stage identifies the orchestrator stage at which an [Assessor.Assess]
// call is being made. Mirrors authn.RiskStage.
type Stage int

// Stage values mirror authn.RiskStage.
const (
	AuthorizeEntry Stage = iota
	PreFactor
	PostFactor
	TokenExchange
)

// Decision mirrors authn.RiskDecision.
type Decision int

// Decision values.
const (
	Allow Decision = iota
	Require
	Deny
)

// Score mirrors authn.RiskScore.
type Score int

// Score values.
const (
	ScoreNone Score = iota
	ScoreLow
	ScoreMedium
	ScoreHigh
)

// Input mirrors authn.RiskInput. The parent fills it from State.
type Input struct {
	Stage      Stage
	Subject    string
	ClientID   string
	RemoteIP   netip.Addr
	UserAgent  string
	AMRSoFar   []string
	ACRValues  []string
	LastFactor string
	AuthTime   time.Time
}

// Outcome mirrors authn.RiskOutcome. The helpers in this package
// interpret Decision, RequiredFactors, Score and NewDevice;
// Reason is omitted because it is an audit-only field the parent reads
// directly off authn.RiskOutcome and never routes through this seam.
type Outcome struct {
	Decision        Decision
	RequiredFactors []string
	Score           Score
	NewDevice       bool
}

// Assessor is the duck-typed authn.RiskAssessor. The parent passes its
// own assessor wrapped in a thin adapter when it crosses the package
// boundary.
type Assessor interface {
	Assess(ctx context.Context, in Input) (Outcome, error)
}

// LoginFlowResult is the output of the once-per-chain LoginFlow
// consult.
type LoginFlowResult struct {
	// Score is the cached value the orchestrator stamps onto
	// State.RiskScoreCached. ScoreNone means "do not update".
	Score Score
	// Required is the OR-set of factor types a [Require] outcome
	// demands. Empty on every other decision, and empty on Require
	// when the assessor named no candidate — the directive then
	// carries no step-up, only the elevated Score.
	Required []string
	// NewDevice is the device-familiarity signal, carried through on
	// every decision. It is orthogonal to Decision: an assessor may
	// report an unfamiliar device and still Allow, leaving the flow's
	// rules to decide what that warrants.
	NewDevice bool
	// Denied reports whether the chain is denied.
	Denied bool
}

// RunOnceForLoginFlow consults assessor at AuthorizeEntry. The
// LoginFlow path caches the resulting Score on State.RiskScoreCached
// and the required-factor set on State.RiskRequiredFactors; this helper
// computes both from the [Outcome] so the budget invariant
// ("Risk.Assess at most once per chain") stays in one place.
//
// Mapping:
//   - Outcome.Score non-zero — used verbatim.
//   - Score zero, Decision = Allow — ScoreLow.
//   - Score zero, Decision = Require — ScoreHigh.
//   - Decision = Require — RequiredFactors carried through verbatim,
//     independently of which branch produced the Score.
//   - Decision = Deny — Denied flag set, score unchanged.
//   - NewDevice — carried through on every decision, Deny included, so
//     the signal does not depend on which verdict accompanied it.
func RunOnceForLoginFlow(ctx context.Context, assessor Assessor, in Input) (LoginFlowResult, error) {
	if assessor == nil {
		return LoginFlowResult{}, nil
	}
	in.Stage = AuthorizeEntry
	out, err := assessor.Assess(ctx, in)
	if err != nil {
		return LoginFlowResult{}, err
	}
	res := LoginFlowResult{NewDevice: out.NewDevice}
	switch out.Decision {
	case Deny:
		res.Denied = true
	case Require:
		res.Required = out.RequiredFactors
		res.Score = out.Score
		if res.Score == ScoreNone {
			res.Score = ScoreHigh
		}
	case Allow:
		res.Score = out.Score
		if res.Score == ScoreNone {
			res.Score = ScoreLow
		}
	}
	return res, nil
}
