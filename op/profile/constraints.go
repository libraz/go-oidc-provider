package profile

import (
	"time"

	"github.com/libraz/go-oidc-provider/op/feature"
)

// RequiredFeatures returns the conjunctive set of [feature.Flag]
// values an [op.Provider] MUST have enabled for p to be a valid
// configuration. The slice is freshly allocated on each call; callers
// may mutate it freely.
//
// The mapping mirrors the MUST clauses from each profile spec:
//
//   - [FAPI2Baseline]: PAR (FAPI 2.0 §3.1.1) and JAR (§3.1.11). The
//     sender-constrained-token requirement (§3.1.4) is conjunctive
//     across the profile but disjunctive across DPoP / mTLS, so it
//     lives on [RequiredAnyOf] rather than here.
//   - [FAPI2MessageSigning]: every [FAPI2Baseline] requirement plus
//     JARM (Message Signing §5).
//
// [FAPICIBA] and [IGovHigh] return nil because their option surfaces
// are scheduled for v1.x / v2+; returning nil keeps the switch
// exhaustive without the library claiming requirements it cannot yet
// enforce.
func RequiredFeatures(p Profile) []feature.Flag {
	switch p {
	case FAPI2Baseline:
		return []feature.Flag{feature.PAR, feature.JAR}
	case FAPI2MessageSigning:
		return []feature.Flag{feature.PAR, feature.JAR, feature.JARM}
	case FAPICIBA, IGovHigh, profileUnspecified:
		return nil
	default:
		return nil
	}
}

// RequiredAnyOf returns the disjunctive constraint sets layered on
// top of [RequiredFeatures]. The outer slice is conjunctive: every
// set MUST be satisfied. The inner slice is disjunctive: at least one
// listed [feature.Flag] satisfies the set.
//
// FAPI 2.0 §3.1.4 mandates a sender-constrained access token but
// lets the deployment choose between DPoP (RFC 9449) and mTLS
// (RFC 8705), so the constraint is "DPoP OR MTLS" rather than the
// stronger "DPoP AND MTLS" — pinning a single binding mechanism would
// reject conformant deployments that picked the other.
func RequiredAnyOf(p Profile) [][]feature.Flag {
	switch p {
	case FAPI2Baseline, FAPI2MessageSigning:
		return [][]feature.Flag{{feature.DPoP, feature.MTLS}}
	case FAPICIBA, IGovHigh, profileUnspecified:
		return nil
	default:
		return nil
	}
}

// MaxAccessTokenTTL returns the upper bound the profile imposes on
// access token lifetime, or 0 when p does not constrain it. The
// rule is one-directional: an embedder MAY configure a stricter
// (smaller) TTL but MUST NOT configure a value above this bound.
//
// Both FAPI 2.0 Baseline and Message Signing cap access tokens at
// 10 minutes (FAPI 2.0 §3.1.9). [FAPICIBA] and [IGovHigh] return 0
// because their option surfaces are scheduled for v1.x / v2+.
func MaxAccessTokenTTL(p Profile) time.Duration {
	switch p {
	case FAPI2Baseline, FAPI2MessageSigning:
		return 10 * time.Minute
	case FAPICIBA, IGovHigh, profileUnspecified:
		return 0
	default:
		return 0
	}
}
