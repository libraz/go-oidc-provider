//go:build example

// Example 30-custom-grant demonstrates [op.WithCustomGrant]: an
// embedder-defined grant_type that lets a backend service exchange a
// self-issued service token (a JWT signed by the embedder's own KMS)
// for an OP-minted, cnf-bindable JWT access token bearing the
// embedder's service identity.
//
// Run with the example build tag:
//
//	go run -tags example ./examples/30-custom-grant
//
// The example is self-contained: a single binary stands up the OP on
// :8088, runs an in-process self-verify probe before the public listener
// starts, and then keeps serving so an operator can reproduce the
// round-trip with curl. The probe is the contract: it fails the process
// with exit code 1 if any step of the exchange regresses.
//
// The codebase is split by role across this directory:
//
//   - main.go   — entrypoint, public listener, package godoc.
//   - op.go     — OP-side wiring: buildProvider, the
//     [op.CustomGrantHandler] implementation, and the handler's
//     service-token verifier.
//   - client.go — embedder-side service that mints the inbound
//     service_token (rolesplit: this is the JWS the backend service
//     would sign through its KMS).
//   - probe.go  — self-verify probe: drives the wire round-trip
//     against an httptest OP and asserts the issued access-token
//     shape.
//
// What the run prints, in order:
//
//  1. "[probe] starting in-process round-trip" — the self-verify gate
//     boots an httptest OP, mints a service_token, POSTs to /oidc/token
//     and asserts HTTP 200 + access_token + token_type=Bearer + a
//     decodable JWT carrying the expected aud/iss/sub claims.
//  2. "[OK] self-verify: custom-grant round-trip OK" — the gate
//     succeeded; the probe OP is torn down.
//  3. "[op] listening on :8088 (issuer http://127.0.0.1:8088)" — the
//     public listener is now serving the same wiring.
//  4. Probe FAIL prints "[FAIL] self-verify: <reason>" and exits 1
//     before the listener starts.
//
// The custom grant in this example:
//
//   - Name: "urn:example:libraz:service-token-exchange". A backend
//     service POSTs to /oidc/token with grant_type set to this URN,
//     authenticates with client_secret_post, and supplies a
//     service_token form parameter. The handler verifies the token's
//     ES256 signature against a hard-coded service key, extracts the
//     "sub" claim as the service identity, and returns a
//     [op.BoundAccessToken] so the OP mints the access token under
//     its own keyset (with cnf binding stamped automatically when the
//     request carried a verified DPoP / mTLS credential — none in this
//     plain demo).
//   - Wire form parameters: ParamPolicy.Allowed = ["service_token",
//     "scope"]. RFC 6749 §3.2 shared parameters (grant_type, client_id,
//     client_secret, scope) are implicit; only handler-specific extras
//     are listed.
//   - Issued claims: aud=["internal-api"], iss=issuer, sub=<service
//     identity from the service_token's "sub" claim>, ttl=5m. The
//     handler returns no AccessToken string (mutually exclusive with
//     BoundAccessToken); the OP fills iss/exp/iat/jti/scope/client_id.
//
// PRODUCTION CAVEATS:
//   - Keys: ephemeral; load from a vault / KMS in production. Both the
//     OP signing key AND the service-token verification key are rotated
//     at every boot so an operator running the example twice in
//     succession sees two unrelated keysets.
//   - Service-token verification: the demo trusts a single hard-coded
//     ES256 public key. Production handlers fetch the embedder's
//     service-key JWKS over a mutually authenticated channel, pin the
//     issuer, validate exp / nbf / aud, and revoke compromised kids
//     out-of-band. The demo only checks the signature and "sub" so the
//     example stays focused on the op.WithCustomGrant surface.
//   - Store: in-memory; use op/storeadapter/sql or composite.
//   - Listener: plain HTTP; front behind TLS-terminating ingress.
//   - Client secret: the demo seeds a fixed value; production embedders
//     issue high-entropy random secrets and rotate through their secret
//     manager.
//   - cnf binding: this demo does not present DPoP or mTLS. A real
//     deployment that wants per-request sender constraint sends a DPoP
//     proof with the /token POST; the OP stamps cnf.jkt on the issued
//     access token without any handler change.
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/libraz/go-oidc-provider/examples/internal/devkeys"
	"github.com/libraz/go-oidc-provider/examples/internal/serve"
)

const (
	opAddr   = ":8088"
	issuer   = "http://127.0.0.1" + opAddr
	clientID = "service-a"
	// clientSecret is the demo confidential-client secret. Production
	// embedders generate this through their secret manager and rotate
	// out-of-band. The demo value is fixed so the operator-facing curl
	// snippets in the README reproduce.
	clientSecret = "service-secret"

	// grantURN is the embedder-defined grant_type the custom handler
	// answers to. RFC 6749 §4.5 strongly recommends URN form for
	// extension grants; the OP rejects collisions with the built-in
	// grant_type wires at registration time.
	grantURN = "urn:example:libraz:service-token-exchange"

	// serviceTokenAudience is the "aud" claim the demo backend service
	// stamps on its self-issued service tokens. The handler MUST
	// verify it equals the OP's trust anchor for the service-token
	// channel; production handlers usually pin it to the OP's issuer.
	serviceTokenAudience = "op://service-token-exchange"

	// serviceSubject is the "sub" claim the demo backend service
	// stamps on its self-issued service tokens. The handler reflects
	// this onto the OP-minted access token's "sub" claim.
	serviceSubject = "service-a-instance-1"

	// resourceAudience is the resource the OP-minted access token
	// addresses. The confidential client below registers it under
	// Resources so the dispatcher's audience subset gate accepts the
	// handler's response shape.
	resourceAudience = "internal-api"

	tokenPath = "/oidc/token"

	// accessTokenTTL is the access-token lifetime the handler asks for.
	// The OP truncates to its global cap (default 1 hour); 5 minutes is
	// well inside that.
	accessTokenTTL = 5 * time.Minute

	// serviceTokenTTL bounds the lifetime of the demo service token.
	// The handler's verifier only checks the signature in this demo,
	// but production verifiers MUST enforce exp / nbf.
	serviceTokenTTL = 1 * time.Minute
)

func main() {
	if err := selfVerify(); err != nil {
		fmt.Fprintf(os.Stderr, "✗ self-verify: %v\n", err)
		os.Exit(1)
	}
	// The literal "✓ self-verify: ..." prefix is the contract a
	// release-prep harness greps for. Keep it byte-stable.
	log.Print("✓ self-verify: custom-grant round-trip OK")
	if err := runListener(); err != nil {
		log.Fatalf("custom-grant example: listener: %v", err)
	}
}

// runListener stands up the public OP listener with the same wiring
// the self-verify probe used. The listener is not driven by the demo
// itself — operators reproduce the round-trip with curl using the
// snippets in the package godoc.
func runListener() error {
	keys := devkeys.MustEphemeral("custom-grant-1")
	servicePriv, servicePub, err := newServiceKey()
	if err != nil {
		return err
	}
	provider, err := buildProvider(keys, servicePub)
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.Handle("/", provider)

	// Print a one-shot operator snippet so the running listener is
	// useful without consulting the README. We exercise the same
	// service token construction the probe uses, so the snippet always
	// works against the live binary.
	demoToken, err := signServiceToken(servicePriv, time.Now()) //nolint:forbidigo // demo only: see signServiceToken godoc.
	if err != nil {
		return err
	}
	serve.Demo("op", opAddr, issuer,
		fmt.Sprintf(`curl -s -d 'grant_type=%s&client_id=%s&client_secret=%s&service_token=%s' %s%s`,
			grantURN, clientID, clientSecret, demoToken, issuer, tokenPath),
	)
	return serve.Listen(opAddr, mux)
}
