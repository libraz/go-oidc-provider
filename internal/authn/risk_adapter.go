package authn

import (
	"context"

	"github.com/libraz/go-oidc-provider/internal/authn/risk"
)

// riskAssessorAdapter wraps a public-API [RiskAssessor] so it can be
// driven by the risk sub-package. The adapter translates between the
// authn-package RiskInput / RiskOutcome and the risk sub-package's
// Input / Outcome shapes; the two are intentionally identical so the
// translation is a pure rename.
type riskAssessorAdapter struct {
	wrapped RiskAssessor
}

// Assess implements risk.Assessor by routing to the wrapped
// authn.RiskAssessor.
func (a riskAssessorAdapter) Assess(ctx context.Context, in risk.Input) (risk.Outcome, error) {
	out, err := a.wrapped.Assess(ctx, RiskInput{
		Stage:      riskStageFromPkg(in.Stage),
		Subject:    in.Subject,
		ClientID:   in.ClientID,
		RemoteIP:   in.RemoteIP,
		UserAgent:  in.UserAgent,
		AMRSoFar:   in.AMRSoFar,
		ACRValues:  in.ACRValues,
		LastFactor: FactorType(in.LastFactor),
		AuthTime:   in.AuthTime,
	})
	if err != nil {
		return risk.Outcome{}, err
	}
	return risk.Outcome{
		Decision:        riskDecisionToPkg(out.Decision),
		RequiredFactors: factorTypesToStrings(out.RequiredFactors),
		Score:           riskScoreToPkg(out.Score),
		MinAAL:          aalToPkg(out.MinAAL),
		NewDevice:       out.NewDevice,
	}, nil
}

// wrapRiskAssessor returns a risk.Assessor that delegates to a, or nil
// if a is nil. Storing the wrapper once on the orchestrator avoids
// rebuilding it on every Tick.
//
//nolint:ireturn,nolintlint // adapter intentionally returns the package-internal interface.
func wrapRiskAssessor(a RiskAssessor) risk.Assessor {
	if a == nil {
		return nil
	}
	return riskAssessorAdapter{wrapped: a}
}

// riskStageFromPkg maps the risk sub-package's Stage onto the
// authn-package RiskStage enum.
func riskStageFromPkg(s risk.Stage) RiskStage {
	switch s {
	case risk.AuthorizeEntry:
		return RiskAuthorizeEntry
	case risk.PreFactor:
		return RiskPreFactor
	case risk.PostFactor:
		return RiskPostFactor
	case risk.TokenExchange:
		return RiskTokenExchange
	}
	return RiskAuthorizeEntry
}

// riskDecisionToPkg maps the authn-package RiskDecision onto the risk
// sub-package's Decision.
func riskDecisionToPkg(d RiskDecision) risk.Decision {
	switch d {
	case RiskAllow:
		return risk.Allow
	case RiskRequire:
		return risk.Require
	case RiskDeny:
		return risk.Deny
	}
	return risk.Allow
}

// riskScoreToPkg maps RiskScore (authn) onto risk.Score.
func riskScoreToPkg(s RiskScore) risk.Score {
	switch s {
	case RiskScoreNone:
		return risk.ScoreNone
	case RiskScoreLow:
		return risk.ScoreLow
	case RiskScoreMedium:
		return risk.ScoreMedium
	case RiskScoreHigh:
		return risk.ScoreHigh
	}
	return risk.ScoreNone
}

// riskScoreFromPkg maps risk.Score onto authn.RiskScore.
func riskScoreFromPkg(s risk.Score) RiskScore {
	switch s {
	case risk.ScoreNone:
		return RiskScoreNone
	case risk.ScoreLow:
		return RiskScoreLow
	case risk.ScoreMedium:
		return RiskScoreMedium
	case risk.ScoreHigh:
		return RiskScoreHigh
	}
	return RiskScoreNone
}

// aalToPkg maps authn.AAL onto the risk sub-package's AAL. The ladders
// are identical so the mapping is a pure rename per level.
func aalToPkg(l AAL) risk.AAL {
	switch l {
	case AAL1:
		return risk.AAL1
	case AAL2:
		return risk.AAL2
	case AAL3:
		return risk.AAL3
	default:
		return risk.AAL0
	}
}

// aalFromPkg is the inverse of aalToPkg.
func aalFromPkg(l risk.AAL) AAL {
	switch l {
	case risk.AAL1:
		return AAL1
	case risk.AAL2:
		return AAL2
	case risk.AAL3:
		return AAL3
	default:
		return AAL0
	}
}

// factorTypesToStrings copies a FactorType slice into a string slice
// for the risk sub-package.
func factorTypesToStrings(in []FactorType) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = string(v)
	}
	return out
}

// factorTypesFromStrings is the inverse of factorTypesToStrings.
func factorTypesFromStrings(in []string) []FactorType {
	if len(in) == 0 {
		return nil
	}
	out := make([]FactorType, len(in))
	for i, v := range in {
		out[i] = FactorType(v)
	}
	return out
}

// buildRiskInput composes the risk.Input for a per-tick consult. The
// orchestrator hands st + the per-call fields through; this helper
// keeps the snapshot/copy semantics centralised so a future change
// to the input shape lands in one place.
func buildRiskInput(st State, lastFactor FactorType) risk.Input {
	return risk.Input{
		Subject:    st.Subject,
		ClientID:   st.ClientID,
		RemoteIP:   st.RemoteIP,
		UserAgent:  st.UserAgent,
		AMRSoFar:   collectAMR(st.Factors),
		ACRValues:  append([]string(nil), st.ACRValues...),
		LastFactor: string(lastFactor),
	}
}
