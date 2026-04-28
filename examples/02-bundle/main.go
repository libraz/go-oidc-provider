//go:build example

// Example 02 is the comprehensive "this is what a real OP wiring
// looks like" example. It composes every option a typical embedder
// reaches for: a [op.LoginFlow] with password + MFA + captcha + risk
// gating, typed client seeds, scope catalogue, profile auto-enable,
// trusted-proxy normalisation, and the recommended logger.
//
// Run with the example build tag:
//
//	go run -tags example ./examples/02-bundle
//
// The example does NOT enable a security profile by default; flip
// the FAPI knob in the source if you want to see WithProfile +
// auto-enable. The default shape matches a typical "OIDC Core OP
// for the embedder's own apps" deployment.
//
// PRODUCTION CAVEATS: this example uses ephemeral keys and an
// in-memory store. Production embedders read keys from a vault /
// KMS, persist records in a real backend, and configure the
// trusted-proxy list against their actual edge.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"log"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

type alwaysOKCaptcha struct{}

func (alwaysOKCaptcha) Verify(_ context.Context, _ op.CaptchaInput) error { return nil }

func main() {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("generate signing key: %v", err)
	}
	cookieKey := make([]byte, 32)
	if _, err := rand.Read(cookieKey); err != nil {
		log.Fatalf("generate cookie key: %v", err)
	}
	totpKey := make([]byte, 32)
	if _, err := rand.Read(totpKey); err != nil {
		log.Fatalf("generate TOTP key: %v", err)
	}

	st := inmem.New()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	flow := op.LoginFlow{
		Primary: op.PrimaryPassword{Store: st.UserPasswords()},
		Rules: []op.Rule{
			// Always require TOTP. Production deployments often
			// gate this on RuleACR or RuleRisk instead so users
			// without a TOTP enrolment can still sign in.
			op.RuleAlways(op.StepTOTP{
				Store:         st.TOTPs(),
				EncryptionKey: totpKey,
			}),
			// Captcha after 5 failed attempts in this session.
			op.RuleAfterFailedAttempts(5, op.StepCaptcha{
				Verifier: alwaysOKCaptcha{},
			}),
		},
	}

	provider, err := op.New(
		op.WithIssuer("https://op.example.com"),
		op.WithStore(st),
		op.WithKeyset(op.Keyset{{KeyID: "bundle-1", Signer: priv}}),
		op.WithCookieKey(cookieKey),
		op.WithLogger(logger),
		op.WithLoginFlow(flow),
		op.WithStaticClients(
			op.PublicClient{
				ID:           "first-party-spa",
				RedirectURIs: []string{"https://app.example.com/callback"},
				Scopes:       []string{"openid", "profile", "email"},
			},
			op.ConfidentialClient{
				ID:           "backend-service",
				Secret:       "rotate-me-via-secret-manager",
				AuthMethod:   op.AuthClientSecretBasic,
				RedirectURIs: []string{"https://backend.example.com/callback"},
				Scopes:       []string{"openid", "profile"},
			},
		),
		op.WithFirstPartyClients("first-party-spa"),
		// Token lifetimes. Defaults are 5m (access) / 30d (refresh);
		// the values below tighten access tokens and shorten refresh
		// tokens for a higher-touch session. WithProfile(FAPI2*) caps
		// access at 10m (FAPI 2.0 §3.1.9); refresh has no profile cap.
		// Refresh tokens are issued only when the granted scope
		// includes "openid" AND the client GrantTypes contains
		// "refresh_token" — see [op.ScopeNameOfflineAccess] godoc for
		// the rationale.
		op.WithAccessTokenTTL(2*time.Minute),
		op.WithRefreshTokenTTL(7*24*time.Hour),
		// OIDC standard scopes (openid, profile, email, address, phone,
		// offline_access) are auto-registered with library defaults; the
		// calls below override the built-in entries only to attach
		// custom titles for the consent prompt.
		op.WithScope(op.PublicScope("profile", "Access your profile")),
		op.WithScope(op.PublicScope("email", "Read your email address")),
	)
	if err != nil {
		log.Fatalf("op.New: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", provider)

	log.Println("bundle example listening on :8080 (LoginFlow + clients + scopes + first-party)")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatalf("listen: %v", err)
	}
}
