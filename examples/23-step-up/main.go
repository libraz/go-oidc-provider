//go:build example

// Example 23 demonstrates RFC 9470 Authentication Context Class
// step-up. The RP requests a stronger authentication posture by
// passing acr_values in the /authorize call (or claims.id_token.acr
// for OIDC Core); the orchestrator schedules a follow-on factor when
// the active session does not already meet the requested ACR.
//
// Run with the example build tag:
//
//	go run -tags example ./examples/23-step-up
//
// The example registers [op.RuleACR("urn:mace:incommon:iap:silver",
// op.StepTOTP{...})] so an RP that asks for that ACR triggers a
// TOTP challenge on top of the password chain. RPs that do not
// request the ACR receive the password-only flow.
//
// PRODUCTION CAVEATS:
//   - Keys: ephemeral; load from a vault / KMS in production.
//   - Store: in-memory; use op/storeadapter/sql or composite.
//   - Listener: plain HTTP; front behind TLS-terminating ingress.
//   - ACR string: opaque to the library — the embedder picks the value and is responsible for the meaning. Common conventions are urn:mace:incommon:iap:silver / iap:bronze (InCommon Federation) or AAL1 / AAL2 / AAL3 (NIST SP 800-63B).
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
	keys := devkeys.MustEphemeral("step-up-1")

	st := inmem.New()
	flow := op.LoginFlow{
		Primary: op.PrimaryPassword{Store: st.UserPasswords()},
		Rules: []op.Rule{
			// RPs that ask for this ACR pull a TOTP step on top
			// of the password chain; ones that do not stay on
			// the password-only path.
			op.RuleACR("urn:mace:incommon:iap:silver", op.StepTOTP{
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

	log.Println("step-up example listening on :8080 (TOTP gated on acr_values=urn:mace:incommon:iap:silver)")
	if err := serve.Listen(":8080", mux); err != nil {
		log.Fatalf("listen: %v", err)
	}
}
