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
// The example wires a deliberately silly assessor that grades on the
// User-Agent header:
//
//   - "curl" / "python" / "go-http-client" → [op.RiskScoreHigh]
//     (TOTP fires)
//   - "headless" (anomalous browser) → [op.RiskScoreMedium]
//     (captcha fires; not a hard block)
//   - everything else → [op.RiskScoreLow] (password-only happy path)
//
// The Medium path is the case [op.RiskOutcome.Score] exists for: the
// Decision-only fallback can only reach Low or High. Returning
// `Decision: RiskRequire, Score: RiskScoreMedium` lets a captcha
// rule fire while a TOTP rule gated on High stays silent.
// Real assessors look at IP geolocation, device fingerprint,
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
	"errors"
	"log"
	"net/http"
	"strings"

	"github.com/libraz/go-oidc-provider/examples/internal/devkeys"
	"github.com/libraz/go-oidc-provider/examples/internal/serve"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// uaRiskAssessor grades on the User-Agent header. Scripted UAs are
// surfaced as RiskScoreHigh through the Decision-only fallback;
// "headless" UAs are surfaced as RiskScoreMedium through the
// explicit Score field. Benign UAs return RiskAllow → RiskScoreLow.
type uaRiskAssessor struct{}

func (uaRiskAssessor) Assess(_ context.Context, in op.RiskInput) (op.RiskOutcome, error) {
	ua := strings.ToLower(in.UserAgent)
	switch {
	case strings.Contains(ua, "curl"),
		strings.Contains(ua, "python"),
		strings.Contains(ua, "go-http-client"):
		// Scripted user-agents: hard step-up. The Decision-only path
		// is enough — the orchestrator caches RiskScoreHigh.
		return op.RiskOutcome{
			Decision: op.RiskRequire,
			Reason:   "anomaly.scripted-user-agent",
		}, nil
	case strings.Contains(ua, "headless"):
		// Anomalous-but-not-blocking signal: ask for a captcha but
		// not a strong factor. Score is the seam that makes Medium
		// reachable; without it, RiskRequire would be cached as
		// RiskScoreHigh and the captcha rule below would never fire
		// in isolation from the TOTP rule.
		return op.RiskOutcome{
			Decision: op.RiskRequire,
			Score:    op.RiskScoreMedium,
			Reason:   "anomaly.headless-browser",
		}, nil
	default:
		return op.RiskOutcome{Decision: op.RiskAllow}, nil
	}
}

// stubCaptchaVerifier accepts any non-empty token. A real deployment
// wires Cloudflare Turnstile / hCaptcha / reCAPTCHA here.
type stubCaptchaVerifier struct{}

func (stubCaptchaVerifier) Verify(_ context.Context, in op.CaptchaInput) error {
	if in.Token == "" {
		return errors.New("captcha token missing")
	}
	return nil
}

func main() {
	keys := devkeys.MustEphemeral("risk-1")

	st := inmem.New()
	flow := op.LoginFlow{
		Primary: op.PrimaryPassword{Store: st.UserPasswords()},
		Risk:    uaRiskAssessor{},
		Rules: []op.Rule{
			// TOTP fires only when the assessor scores the
			// request RiskScoreHigh or above (scripted UAs).
			op.RuleRisk(op.RiskScoreHigh, op.StepTOTP{
				Store:         st.TOTPs(),
				EncryptionKey: keys.TOTPKey,
			}),
			// Captcha fires from RiskScoreMedium upward, so
			// "headless" requests are challenged but not
			// hard-blocked. Rule order matters: TOTP wins on High
			// because it appears first.
			op.RuleRisk(op.RiskScoreMedium, op.StepCaptcha{
				Verifier: stubCaptchaVerifier{},
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

	log.Println("risk-based example listening on :8080")
	log.Println("  UA contains curl/python/go-http-client → RiskScoreHigh → TOTP")
	log.Println("  UA contains 'headless'                 → RiskScoreMedium → captcha")
	log.Println("  otherwise                              → RiskScoreLow → password only")
	if err := serve.Listen(":8080", mux); err != nil {
		log.Fatalf("listen: %v", err)
	}
}
