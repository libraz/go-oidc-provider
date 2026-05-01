package scenarios_test

// Catalog: test/scenarios/catalog/signatures.yaml (SIG-NNN)
// Spec:
//   - RFC 7515 — JSON Web Signature
//   - RFC 7518 §3 — JSON Web Algorithms
//   - OIDC Core 1.0 §3.1.3.6 (`at_hash`, `c_hash`), §3.1.3.7 (id_token signing)
//   - RFC 9700 §2 / FAPI 1.0 / FAPI 2.0 (alg policy)

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/testkit"
	"github.com/libraz/go-oidc-provider/test/scenarios/internal/scenariokit"
)

// TestScenario_SIG_022_NoneAlgNotAdvertised verifies that the
// well-known discovery document never advertises `alg=none` for ID
// tokens. RFC 9700 §2 + FAPI 1/2 mandate at least RS256 baseline; none
// is forbidden. Also asserts at least one secure alg is advertised.
//
// Spec: OIDC Core §3.1.3.7, RFC 9700 §2.
func TestScenario_SIG_022_NoneAlgNotAdvertised(t *testing.T) {
	t.Parallel()

	p := testkit.NewProvider(t)

	_, _, doc := fetchDiscovery(t, p.Server.URL)

	algs, _ := doc["id_token_signing_alg_values_supported"].([]any)
	if len(algs) == 0 {
		t.Fatalf("id_token_signing_alg_values_supported is empty; OIDC Core §3.1.3.7 requires advertising at least one alg")
	}
	for _, raw := range algs {
		alg, _ := raw.(string)
		if alg == "none" {
			t.Errorf("id_token_signing_alg_values_supported contains %q; RFC 9700 §2 forbids none for ID tokens", alg)
		}
	}
}

// --- Pending bindings --------------------------------------------------

func TestScenario_SIG_001_HS256IDTokenIssuance(t *testing.T) {
	t.Parallel()
	t.Skip("pending: SIG-001 — needs RP simulator + per-client alg pinning")
}

func TestScenario_SIG_002_HS256IDTokenAcceptedAsHint(t *testing.T) {
	t.Parallel()
	t.Skip("pending: SIG-002")
}

func TestScenario_SIG_010_AtHashLengthSHA256(t *testing.T) {
	t.Parallel()
	t.Skip("pending: SIG-010 — needs hybrid response_type wiring")
}

func TestScenario_SIG_011_AtHashLengthSHA384(t *testing.T) {
	t.Parallel()
	t.Skip("pending: SIG-011")
}

func TestScenario_SIG_012_AtHashLengthSHA512(t *testing.T) {
	t.Parallel()
	t.Skip("pending: SIG-012")
}

func TestScenario_SIG_013_EdDSAAtHashLength(t *testing.T) {
	t.Parallel()
	t.Skip("pending: SIG-013")
}

func TestScenario_SIG_014_Ed25519AtHashLength(t *testing.T) {
	t.Parallel()
	t.Skip("pending: SIG-014")
}

// TestScenario_SIG_020_AlgFromClientMetadataAndKidInHeader confirms
// the OIDC Core §3.1.3.7 contract: the id_token returned from /token
// is a compact JWS whose header's alg matches the client's
// id_token_signed_response_alg and whose kid identifies which key in
// the OP keystore signed it. v1.0 issues ES256 only, so we register a
// client without a custom alg (taking the default) and assert the
// header carries alg=ES256 and a non-empty kid that matches one of
// the kids advertised at /jwks.
//
// Spec: OIDC Core §3.1.3.7 / RFC 7515.
func TestScenario_SIG_020_AlgFromClientMetadataAndKidInHeader(t *testing.T) {
	t.Parallel()

	const (
		clientID = "rp-sig-020"
		callback = "https://rp.testkit.invalid/callback"
	)
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-sig-020-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}

	tk := testkit.NewProvider(t)
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		RedirectURIs:            []string{callback},
		Scopes:                  []string{"openid"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})

	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    rp.ID,
		RedirectURI: callback,
		Scope:       "openid",
		PKCE:        pkce,
	})
	if flow.Code == "" {
		t.Fatalf("authorize callback missing code: %+v", flow)
	}

	tok := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code:         flow.Code,
		RedirectURI:  callback,
		Verifier:     pkce.Verifier,
		ClientID:     rp.ID,
		ClientSecret: clientSecret,
	})
	if tok.StatusCode != http.StatusOK {
		t.Fatalf("/token status=%d body=%v", tok.StatusCode, tok.Raw)
	}
	if tok.IDToken == "" {
		t.Fatalf("id_token missing from /token response: %v", tok.Raw)
	}

	dot := strings.IndexByte(tok.IDToken, '.')
	if dot <= 0 {
		t.Fatalf("id_token is not a compact JWS: %q", tok.IDToken)
	}
	hdrBytes, err := base64.RawURLEncoding.DecodeString(tok.IDToken[:dot])
	if err != nil {
		t.Fatalf("decode JWS header: %v", err)
	}
	var hdr map[string]any
	if err := json.Unmarshal(hdrBytes, &hdr); err != nil {
		t.Fatalf("unmarshal JWS header: %v (raw=%q)", err, hdrBytes)
	}

	alg, _ := hdr["alg"].(string)
	if alg != "ES256" {
		t.Errorf("id_token JWS header alg=%q, want ES256 (v1.0 issues ES256 only)", alg)
	}
	kid, _ := hdr["kid"].(string)
	if kid == "" {
		t.Fatalf("id_token JWS header is missing kid; OIDC Core §3.1.3.7 requires the OP to identify the signing key")
	}

	_, _, jwksDoc := fetchJWKS(t, tk.Server.URL)
	keys, _ := jwksDoc["keys"].([]any)
	if len(keys) == 0 {
		t.Fatalf("/jwks returned no keys: %v", jwksDoc)
	}
	matched := false
	for _, raw := range keys {
		entry, _ := raw.(map[string]any)
		if entry == nil {
			continue
		}
		if id, _ := entry["kid"].(string); id == kid {
			matched = true
			break
		}
	}
	if !matched {
		t.Errorf("id_token JWS kid=%q not found in /jwks key set %v", kid, keys)
	}
}

// TestScenario_SIG_021_AlgValuesAdvertisedInDiscovery verifies that
// id_token_signing_alg_values_supported is non-empty, contains only
// registered JWA signing algorithms, and includes at least one of the
// concrete public-key algorithms the testkit's default key set
// signs with (ES256). The discovery contract is "advertise what you
// can do" — RPs that pin a per-client alg need this list to be
// authoritative.
//
// Spec: OIDC Discovery 1.0 §3.
func TestScenario_SIG_021_AlgValuesAdvertisedInDiscovery(t *testing.T) {
	t.Parallel()

	p := testkit.NewProvider(t)

	_, _, doc := fetchDiscovery(t, p.Server.URL)
	algsRaw, _ := doc["id_token_signing_alg_values_supported"].([]any)
	if len(algsRaw) == 0 {
		t.Fatal("id_token_signing_alg_values_supported is empty")
	}
	registered := map[string]struct{}{
		"RS256": {}, "RS384": {}, "RS512": {},
		"ES256": {}, "ES384": {}, "ES512": {}, "ES256K": {},
		"PS256": {}, "PS384": {}, "PS512": {},
		"HS256": {}, "HS384": {}, "HS512": {},
		"EdDSA": {},
	}
	algs := make([]string, 0, len(algsRaw))
	for _, raw := range algsRaw {
		alg, _ := raw.(string)
		algs = append(algs, alg)
		if _, ok := registered[alg]; !ok {
			t.Errorf("id_token_signing_alg_values_supported entry %q is not a registered JWA signing alg", alg)
		}
	}
	// The testkit signs ID tokens with ES256 by default; if the OP
	// stops advertising it here, the discovery contract is broken.
	found := false
	for _, alg := range algs {
		if alg == "ES256" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("id_token_signing_alg_values_supported=%v must include ES256 (testkit default)", algs)
	}
}
