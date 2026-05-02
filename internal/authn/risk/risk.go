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

// Outcome mirrors authn.RiskOutcome. The orchestrator reads only
// Decision, RequiredFactors, and Score — MinAAL / Reason are carried
// through for parity but not interpreted by the helpers in this pkg.
type Outcome struct {
	Decision        Decision
	RequiredFactors []string
	Score           Score
}

// Assessor is the duck-typed authn.RiskAssessor. The parent passes its
// own assessor wrapped in a thin adapter when it crosses the package
// boundary.
type Assessor interface {
	Assess(ctx context.Context, in Input) (Outcome, error)
}

// PreFactorResult is the output of the PreFactor consult helper.
type PreFactorResult struct {
	Required []string
	Denied   bool
}

// RunPreFactor consults assessor at PreFactor and returns the
// required-factor filter and denied flag. assessor may be nil — the
// helper returns the zero-result in that case so the parent does not
// need a nil guard.
func RunPreFactor(ctx context.Context, assessor Assessor, in Input) (PreFactorResult, error) {
	if assessor == nil {
		return PreFactorResult{}, nil
	}
	in.Stage = PreFactor
	out, err := assessor.Assess(ctx, in)
	if err != nil {
		return PreFactorResult{}, err
	}
	switch out.Decision {
	case Deny:
		return PreFactorResult{Denied: true}, nil
	case Require:
		return PreFactorResult{Required: out.RequiredFactors}, nil
	default:
		return PreFactorResult{}, nil
	}
}

// RunPostFactor consults assessor at PostFactor. The current contract
// honours [Deny] only; [Require] at PostFactor is queued by the next
// PreFactor pass (the orchestrator does not preempt the current
// factor). Returns whether the chain is denied.
func RunPostFactor(ctx context.Context, assessor Assessor, in Input) (bool, error) {
	if assessor == nil {
		return false, nil
	}
	in.Stage = PostFactor
	out, err := assessor.Assess(ctx, in)
	if err != nil {
		return false, err
	}
	return out.Decision == Deny, nil
}

// LoginFlowResult is the output of the once-per-chain LoginFlow
// consult.
type LoginFlowResult struct {
	// Score is the cached value the orchestrator stamps onto
	// State.RiskScoreCached. ScoreNone means "do not update".
	Score Score
	// Denied reports whether the chain is denied.
	Denied bool
}

// RunOnceForLoginFlow consults assessor at AuthorizeEntry. The
// LoginFlow path caches the resulting Score on State.RiskScoreCached;
// this helper computes the value from the [Outcome.Decision] /
// [Outcome.Score] pair so the budget invariant ("Risk.Assess at most
// once per chain") stays in one place.
//
// Mapping:
//   - Outcome.Score non-zero — used verbatim.
//   - Score zero, Decision = Allow — ScoreLow.
//   - Score zero, Decision = Require — ScoreHigh.
//   - Decision = Deny — Denied flag set, score unchanged.
func RunOnceForLoginFlow(ctx context.Context, assessor Assessor, in Input) (LoginFlowResult, error) {
	if assessor == nil {
		return LoginFlowResult{}, nil
	}
	in.Stage = AuthorizeEntry
	out, err := assessor.Assess(ctx, in)
	if err != nil {
		return LoginFlowResult{}, err
	}
	switch out.Decision {
	case Deny:
		return LoginFlowResult{Denied: true}, nil
	case Require:
		if out.Score != ScoreNone {
			return LoginFlowResult{Score: out.Score}, nil
		}
		return LoginFlowResult{Score: ScoreHigh}, nil
	case Allow:
		if out.Score != ScoreNone {
			return LoginFlowResult{Score: out.Score}, nil
		}
		return LoginFlowResult{Score: ScoreLow}, nil
	}
	return LoginFlowResult{}, nil
}
