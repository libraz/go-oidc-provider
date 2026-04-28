//go:build example

// Example 22 demonstrates [op.RuleAfterFailedAttempts]: a captcha
// challenge that gates the login chain only after the user has
// fumbled the password N times in a row. This is the canonical
// shape for "make brute-force expensive without inconveniencing
// honest users".
//
// Run with the example build tag:
//
//	go run -tags example ./examples/22-login-captcha
//
// Three failed password attempts trigger the captcha prompt; a
// successful attempt resets the counter. The library invokes the
// supplied [op.CaptchaVerifier] to validate the SPA's submitted
// token. The example wires a no-op verifier that always succeeds
// because the example is about the orchestrator shape, not the
// upstream captcha provider integration. A production embedder
// implements [op.CaptchaVerifier] against Cloudflare Turnstile,
// Google reCAPTCHA, hCaptcha, or whatever provider their security
// posture requires.
//
// PRODUCTION CAVEATS: this example uses ephemeral keys and an
// in-memory store. The "always succeed" CaptchaVerifier is
// deliberately vacuous — never ship that. The real verifier MUST
// (a) call the upstream provider with the embedder's secret and
// (b) collapse all upstream rejection codes onto one generic error
// so the SPA cannot enumerate provider-side rejection reasons.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"log"
	"net/http"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// noopCaptcha is the test-only [op.CaptchaVerifier] this example
// wires. Verify always succeeds; the example's value is the
// orchestrator wiring, not the captcha verification.
type noopCaptcha struct{}

func (noopCaptcha) Verify(_ context.Context, _ op.CaptchaInput) error { return nil }

func main() {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("generate signing key: %v", err)
	}
	cookieKey := make([]byte, 32)
	if _, err := rand.Read(cookieKey); err != nil {
		log.Fatalf("generate cookie key: %v", err)
	}

	st := inmem.New()
	flow := op.LoginFlow{
		Primary: op.PrimaryPassword{Store: st.UserPasswords()},
		Rules: []op.Rule{
			// Inject a captcha after 3 consecutive password
			// failures. The orchestrator clears the counter on
			// the next successful attempt.
			op.RuleAfterFailedAttempts(3, op.StepCaptcha{
				Verifier: noopCaptcha{},
			}),
		},
	}

	provider, err := op.New(
		op.WithIssuer("https://op.example.com"),
		op.WithStore(st),
		op.WithKeyset(op.Keyset{{KeyID: "captcha-1", Signer: priv}}),
		op.WithCookieKey(cookieKey),
		op.WithLoginFlow(flow),
	)
	if err != nil {
		log.Fatalf("op.New: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", provider)

	log.Println("login-captcha example listening on :8080 (captcha after 3 failed attempts)")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatalf("listen: %v", err)
	}
}
