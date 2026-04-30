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
// PRODUCTION CAVEATS:
//   - Keys: ephemeral; load from a vault / KMS in production.
//   - Store: in-memory; use op/storeadapter/sql or composite.
//   - Listener: plain HTTP; front behind TLS-terminating ingress.
//   - TOTP encryption key: 32 bytes (AES-256-GCM at rest for stored secrets) generated at startup; supply it from a vault / KMS so secrets survive process restart.
package main

import (
	"log"
	"net/http"

	"github.com/libraz/go-oidc-provider/examples/internal/devkeys"
	"github.com/libraz/go-oidc-provider/examples/internal/serve"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

func main() {
	keys := devkeys.MustEphemeral("mfa-1")

	st := inmem.New()

	flow := op.LoginFlow{
		Primary: op.PrimaryPassword{Store: st.UserPasswords()},
		Rules: []op.Rule{
			op.RuleAlways(op.StepTOTP{
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

	log.Println("mfa-totp example listening on :8080 (password + TOTP)")
	if err := serve.Listen(":8080", mux); err != nil {
		log.Fatalf("listen: %v", err)
	}
}
