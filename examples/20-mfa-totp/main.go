//go:build example

// Example 20 demonstrates a [op.LoginFlow] that always requires
// password + RFC 6238 TOTP. The Primary step is
// [op.PrimaryPassword]; a single rule with [op.RuleAlways] schedules
// [op.StepTOTP] as the second factor. The orchestrator drives both
// prompts in sequence; a successful TOTP submission emits the
// authorization code with amr=["pwd","otp"] and AAL2.
//
// Run with the example build tag:
//
//	go run -tags example ./examples/20-mfa-totp
//
// To exercise the flow you would also seed a TOTPRecord for the
// demo user; the example focuses on the orchestrator wiring shape
// and treats enrolment as out-of-band.
//
// PRODUCTION CAVEATS: this example uses ephemeral keys and an
// in-memory store. The 32-byte TOTP encryption key (AES-256-GCM
// at rest for stored secrets) is generated at startup; production
// embedders supply it from a vault / KMS so secrets survive
// process restart.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"log"
	"net/http"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

func main() {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("generate signing key: %v", err)
	}
	cookieKey := make([]byte, 32)
	if _, err := rand.Read(cookieKey); err != nil {
		log.Fatalf("generate cookie key: %v", err)
	}

	// 32-byte AES-256-GCM key for TOTP secret storage at rest.
	totpKey := make([]byte, 32)
	if _, err := rand.Read(totpKey); err != nil {
		log.Fatalf("generate TOTP key: %v", err)
	}

	st := inmem.New()

	flow := op.LoginFlow{
		Primary: op.PrimaryPassword{Store: st.UserPasswords()},
		Rules: []op.Rule{
			op.RuleAlways(op.StepTOTP{
				Store:         st.TOTPs(),
				EncryptionKey: totpKey,
			}),
		},
	}

	provider, err := op.New(
		op.WithIssuer("https://op.example.com"),
		op.WithStore(st),
		op.WithKeyset(op.Keyset{{KeyID: "mfa-1", Signer: priv}}),
		op.WithCookieKey(cookieKey),
		op.WithLoginFlow(flow),
	)
	if err != nil {
		log.Fatalf("op.New: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", provider)

	log.Println("mfa-totp example listening on :8080 (password + TOTP)")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatalf("listen: %v", err)
	}
}
