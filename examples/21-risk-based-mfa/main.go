//go:build example

// Example 21 demonstrates risk-driven step-up. A [op.RiskAssessor]
// scores each /authorize request; [op.RuleRisk] schedules a follow-on
// factor when the score crosses the threshold the rule names. Lower
// scores fall through to the password-only happy path.
//
// Run with the example build tag:
//
//	go run -tags example ./examples/21-risk-based-mfa
//
// The example wires a deliberately silly assessor that returns
// [op.RiskScoreHigh] when the request's UserAgent looks scripted
// (curl / Go / Python) and [op.RiskScoreLow] otherwise. RuleRisk
// fires StepTOTP when the score is High, so a human in a browser
// signs in with password alone but a curl invocation is asked for
// TOTP. Real assessors look at IP geolocation, device fingerprint,
// velocity counters, and similar signals.
//
// PRODUCTION CAVEATS:
//   - Keys: ephemeral; load from a vault / KMS in production.
//   - Store: in-memory; use op/storeadapter/sql or composite.
//   - Listener: plain HTTP; front behind TLS-terminating ingress.
//   - Risk assessor: User-Agent heuristic is illustrative — never gate authentication on a single header. Real assessors call fraud-detection services (Cloudflare Bot Management, Castle, Sift, Stripe Radar) and aggregate multiple signals.
package main

import (
	"context"
	"log"
	"net/http"
	"strings"

	"github.com/libraz/go-oidc-provider/examples/internal/devkeys"
	"github.com/libraz/go-oidc-provider/examples/internal/serve"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// uaRiskAssessor flags scripted user-agents as high risk. The
// orchestrator maps RiskRequire → RiskScoreHigh internally so
// [op.RuleRisk(op.RiskScoreHigh, ...)] fires; benign requests
// return RiskAllow which maps to RiskScoreLow.
type uaRiskAssessor struct{}

func (uaRiskAssessor) Assess(_ context.Context, in op.RiskInput) (op.RiskOutcome, error) {
	ua := strings.ToLower(in.UserAgent)
	suspicious := strings.Contains(ua, "curl") ||
		strings.Contains(ua, "python") ||
		strings.Contains(ua, "go-http-client")
	if suspicious {
		return op.RiskOutcome{
			Decision: op.RiskRequire,
			Reason:   "anomaly.scripted-user-agent",
		}, nil
	}
	return op.RiskOutcome{Decision: op.RiskAllow}, nil
}

func main() {
	keys := devkeys.MustEphemeral("risk-1")

	st := inmem.New()
	flow := op.LoginFlow{
		Primary: op.PrimaryPassword{Store: st.UserPasswords()},
		Risk:    uaRiskAssessor{},
		Rules: []op.Rule{
			// TOTP fires only when the assessor scores the
			// request RiskScoreHigh or above.
			op.RuleRisk(op.RiskScoreHigh, op.StepTOTP{
				Store:         st.TOTPs(),
				EncryptionKey: keys.TOTPKey,
			}),
		},
	}

	provider, err := op.New(
		op.WithIssuer("https://op.example.com"),
		op.WithStore(st),
		op.WithKeyset(keys.Keyset()),
		op.WithCookieKey(keys.CookieKey),
		op.WithLoginFlow(flow),
	)
	if err != nil {
		log.Fatalf("op.New: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", provider)

	log.Println("risk-based example listening on :8080 (TOTP fires on UserAgent containing curl/python/go-http-client)")
	if err := serve.Listen(":8080", mux); err != nil {
		log.Fatalf("listen: %v", err)
	}
}
