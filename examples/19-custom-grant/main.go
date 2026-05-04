//go:build example

// Example 19-custom-grant demonstrates [op.WithCustomGrant]: an
// embedder-defined grant_type that lets a backend service exchange a
// self-issued service token (a JWT signed by the embedder's own KMS)
// for an OP-minted, cnf-bindable JWT access token bearing the
// embedder's service identity.
//
// Run with the example build tag:
//
//	go run -tags example ./examples/19-custom-grant
//
// The example is self-contained: a single binary stands up the OP on
// :8088, runs an in-process self-verify probe before the public listener
// starts, and then keeps serving so an operator can reproduce the
// round-trip with curl. The probe is the contract: it fails the process
// with exit code 1 if any step of the exchange regresses.
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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/libraz/go-oidc-provider/examples/internal/devkeys"
	"github.com/libraz/go-oidc-provider/examples/internal/serve"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
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

// selfVerify runs an in-process round-trip of the custom-grant exchange
// against an httptest.NewServer-hosted OP. It is the example's
// regression contract: any change that breaks the exchange shape (the
// op.WithCustomGrant wiring, the BoundAccessToken contract, the
// dispatcher's audience / scope gates, the access-token verifier)
// fails the probe before the public listener starts.
func selfVerify() error {
	log.Print("[probe] starting in-process round-trip")

	keys := devkeys.MustEphemeral("custom-grant-probe")
	servicePriv, servicePub, err := newServiceKey()
	if err != nil {
		return fmt.Errorf("generate service key: %w", err)
	}

	provider, err := buildProvider(keys, servicePub)
	if err != nil {
		return fmt.Errorf("build provider: %w", err)
	}

	srv := httptest.NewServer(provider)
	defer srv.Close()

	serviceToken, err := signServiceToken(servicePriv, time.Now()) //nolint:forbidigo // demo only: production embedders sign service tokens through their own KMS / clock seam, the OP itself never reaches for time.Now()
	if err != nil {
		return fmt.Errorf("sign service token: %w", err)
	}

	at, err := exchangeServiceToken(srv.URL+tokenPath, serviceToken)
	if err != nil {
		return fmt.Errorf("exchange: %w", err)
	}
	// The OP-minted access token's "iss" claim is the configured
	// issuer (the const above), not the httptest server's ephemeral
	// URL — RFC 8414 §2 / OIDC Discovery 1.0 §3 require the discovery
	// document's issuer to be stable across host bindings.
	if err := assertAccessTokenShape(at, issuer); err != nil {
		return fmt.Errorf("verify access token: %w", err)
	}
	return nil
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
	demoToken, err := signServiceToken(servicePriv, time.Now()) //nolint:forbidigo // demo only: see runProbe godoc.
	if err != nil {
		return err
	}
	serve.Demo("op", opAddr, issuer,
		fmt.Sprintf(`curl -s -d 'grant_type=%s&client_id=%s&client_secret=%s&service_token=%s' %s%s`,
			grantURN, clientID, clientSecret, demoToken, issuer, tokenPath),
	)
	return serve.Listen(opAddr, mux)
}

// buildProvider wires the OP with op.WithCustomGrant pointing at a
// serviceTokenExchange handler. The wiring is shared between the
// self-verify probe and the public listener so a regression in one
// surface always fails the other.
func buildProvider(keys *devkeys.Material, servicePub *ecdsa.PublicKey) (*op.Provider, error) {
	st := inmem.New()

	handler := &serviceTokenExchange{verifier: servicePub}

	provider, err := op.New(
		op.WithIssuer(issuer),
		op.WithStore(st),
		op.WithKeyset(keys.Keyset()),
		op.WithCookieKeys(keys.CookieKey),
		op.WithCustomGrant(handler),
		op.WithStaticClients(op.ConfidentialClient{
			ID:         clientID,
			Secret:     clientSecret,
			AuthMethod: op.AuthClientSecretPost,
			// Custom-grant clients never visit /authorize; the
			// GrantTypes set is overridden so the registration
			// only carries the custom URN. The dispatcher rejects
			// any client that asks for a grant_type not listed
			// here with unauthorized_client.
			GrantTypes: []string{grantURN},
			Scopes:     []string{"api:read"},
			// Resources gate the BoundAccessToken.Audience subset
			// check the dispatcher applies before issuance.
			Resources: []string{resourceAudience},
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("op.New: %w", err)
	}
	return provider, nil
}

// serviceTokenExchange implements op.CustomGrantHandler for the
// demo's "exchange a service-issued JWT for an OP-minted access
// token" flow. The verifier is the public half of an out-of-band
// ES256 key the embedder's KMS would normally hold; the demo
// generates it ephemerally at boot and trusts it directly.
type serviceTokenExchange struct {
	verifier *ecdsa.PublicKey
}

// Name implements op.CustomGrantHandler.
func (h *serviceTokenExchange) Name() string { return grantURN }

// ParamPolicy implements op.CustomGrantHandler. Only the handler-
// specific extras are listed; the shared RFC 6749 §3.2 parameters
// (grant_type, client_id, client_secret, scope) are implicit.
func (h *serviceTokenExchange) ParamPolicy() op.ParamPolicy {
	return op.ParamPolicy{Allowed: []string{"service_token", "scope"}}
}

// Handle implements op.CustomGrantHandler. The OP has already
// authenticated the client and parsed the form per ParamPolicy by the
// time this runs; the handler verifies the supplied service_token,
// extracts the service identity, and asks the OP to mint a JWT access
// token bound to the request's DPoP / mTLS credential when present.
func (h *serviceTokenExchange) Handle(_ context.Context, req op.CustomGrantRequest) (op.CustomGrantResponse, error) {
	form := url.Values(req.Form)
	rawToken := form.Get("service_token")
	if rawToken == "" {
		// Generic Go errors are mapped to invalid_grant by the
		// dispatcher with the message redacted from the response body
		// (so internal diagnostics never leak). Embedders that want to
		// surface a specific RFC 6749 §5.2 wire code construct an
		// [*op.Error] directly.
		return op.CustomGrantResponse{}, errors.New("service_token form parameter is required")
	}
	subject, err := verifyServiceToken(h.verifier, rawToken)
	if err != nil {
		return op.CustomGrantResponse{}, fmt.Errorf("service_token verification failed: %w", err)
	}
	return op.CustomGrantResponse{
		BoundAccessToken: &op.BoundAccessToken{
			Subject:  op.Subject(subject),
			Audience: []string{resourceAudience},
			TTL:      accessTokenTTL,
			ExtraClaims: map[string]any{
				"svc_id": subject,
			},
		},
		Scope: []string{"api:read"},
	}, nil
}

// newServiceKey generates the ephemeral ES256 keypair the demo uses to
// sign and verify service tokens. The pair is unrelated to the OP's
// own signing keyset — the whole point of the example is that the
// embedder's trust anchor is independent of the OP's.
func newServiceKey() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return priv, &priv.PublicKey, nil
}

// signServiceToken builds and signs a compact-serialised JWS with
// alg=ES256 over a minimal claim set (iss/sub/aud/iat/exp/nbf/jti).
// The demo backend service would normally sign through its KMS; here
// the keypair is held in-process so the example stays single-binary.
func signServiceToken(priv *ecdsa.PrivateKey, now time.Time) (string, error) {
	header := map[string]string{"alg": "ES256", "typ": "JWT"}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", err
	}
	claims := map[string]any{
		"iss": "service-issuer",
		"sub": serviceSubject,
		"aud": serviceTokenAudience,
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"exp": now.Add(serviceTokenTTL).Unix(),
		"jti": base64.RawURLEncoding.EncodeToString(jti),
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		return "", err
	}
	// RFC 7518 §3.4: ES256 signatures are the fixed-width
	// concatenation of R and S, each padded to 32 bytes.
	const coordLen = 32
	sig := make([]byte, 2*coordLen)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sig[coordLen-len(rBytes):coordLen], rBytes)
	copy(sig[2*coordLen-len(sBytes):], sBytes)
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// verifyServiceToken parses the supplied compact JWS, checks the
// alg=ES256 header, verifies the signature against pub, and returns
// the "sub" claim. The demo intentionally skips exp / nbf / aud
// enforcement to keep the verifier surface small; a production handler
// MUST validate every standard claim.
func verifyServiceToken(pub *ecdsa.PublicKey, raw string) (string, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("expected 3 segments, got %d", len(parts))
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", fmt.Errorf("decode header: %w", err)
	}
	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return "", fmt.Errorf("decode header json: %w", err)
	}
	if header.Alg != "ES256" {
		return "", fmt.Errorf("unsupported alg %q, want ES256", header.Alg)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", fmt.Errorf("decode signature: %w", err)
	}
	if len(sig) != 64 {
		return "", fmt.Errorf("ES256 signature length=%d want 64", len(sig))
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return "", errors.New("ecdsa verify failed")
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("decode payload: %w", err)
	}
	var claims struct {
		Sub string `json:"sub"`
	}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return "", fmt.Errorf("decode claims: %w", err)
	}
	if claims.Sub == "" {
		return "", errors.New("sub claim missing")
	}
	return claims.Sub, nil
}

// exchangeServiceToken POSTs the custom-grant exchange and returns the
// access_token from the success response. Authentication is
// client_secret_post per the seeded ConfidentialClient.AuthMethod.
func exchangeServiceToken(endpoint, serviceToken string) (string, error) {
	form := url.Values{
		"grant_type":    []string{grantURN},
		"client_id":     []string{clientID},
		"client_secret": []string{clientSecret},
		"service_token": []string{serviceToken},
		"scope":         []string{"api:read"},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("do: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status=%d body=%s", resp.StatusCode, string(body))
	}
	var decoded struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
		Scope       string `json:"scope"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		return "", fmt.Errorf("decode body: %w", err)
	}
	if decoded.AccessToken == "" {
		return "", fmt.Errorf("access_token missing: %s", string(body))
	}
	if decoded.TokenType != "Bearer" {
		return "", fmt.Errorf("token_type=%q want Bearer", decoded.TokenType)
	}
	return decoded.AccessToken, nil
}

// assertAccessTokenShape decodes the OP-minted access token's payload
// and confirms the iss / aud / sub claims look right. The probe does
// not verify the signature against the OP's JWKS — the same process
// just signed it — but it does inspect the cnf claim (expected absent
// since the demo presents no DPoP / mTLS credential) and the svc_id
// extra claim the handler stamped.
func assertAccessTokenShape(jwt, expectedIssuer string) error {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return fmt.Errorf("access_token is not a 3-segment JWS: got %d segments", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("base64 decode payload: %w", err)
	}
	var claims struct {
		Iss    string `json:"iss"`
		Sub    string `json:"sub"`
		Aud    any    `json:"aud"`
		SvcID  string `json:"svc_id"`
		Cnf    any    `json:"cnf"`
		Scope  string `json:"scope"`
		Client string `json:"client_id"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return fmt.Errorf("decode claims: %w", err)
	}
	if claims.Iss != expectedIssuer {
		return fmt.Errorf("iss=%q want %q", claims.Iss, expectedIssuer)
	}
	if claims.Sub != serviceSubject {
		return fmt.Errorf("sub=%q want %q", claims.Sub, serviceSubject)
	}
	if claims.SvcID != serviceSubject {
		return fmt.Errorf("svc_id=%q want %q", claims.SvcID, serviceSubject)
	}
	if claims.Client != clientID {
		return fmt.Errorf("client_id=%q want %q", claims.Client, clientID)
	}
	if !audienceMatches(claims.Aud, resourceAudience) {
		return fmt.Errorf("aud=%v want contains %q", claims.Aud, resourceAudience)
	}
	if claims.Cnf != nil {
		return fmt.Errorf("cnf=%v want nil (plain bearer request, no DPoP / mTLS)", claims.Cnf)
	}
	log.Printf("[probe] access_token sub=%q aud=%v iss=%q svc_id=%q",
		claims.Sub, claims.Aud, claims.Iss, claims.SvcID)
	return nil
}

// audienceMatches accepts either a single-string aud claim or a JSON
// array (RFC 7519 §4.1.3) and reports whether want appears in the set.
func audienceMatches(aud any, want string) bool {
	switch v := aud.(type) {
	case string:
		return v == want
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}
