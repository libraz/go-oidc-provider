package scenarios_test

// Catalog: test/scenarios/catalog/jwks.yaml (JWKS-NNN)
// Spec:
//   - RFC 7517 — JSON Web Key
//   - RFC 7518 — JSON Web Algorithms
//   - OIDC Core 1.0 §10, §10.1, §10.1.1, §10.2
//   - OIDC Discovery 1.0 §3 (`jwks_uri`)

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op/testkit"
)

// fetchJWKS issues a GET against the OP's `jwks_uri` (resolved through
// the discovery document so the test does not hard-code the path).
// Returns status code, response headers, and decoded body. The HTTP
// body is closed before returning.
func fetchJWKS(tb testing.TB, base string) (int, http.Header, map[string]any) {
	tb.Helper()

	_, _, doc := fetchDiscovery(tb, base)
	jwksURI, _ := doc["jwks_uri"].(string)
	if jwksURI == "" {
		tb.Fatalf("discovery document missing jwks_uri")
	}

	if idx := strings.Index(jwksURI, "/.well-known"); idx >= 0 {
		jwksURI = base + jwksURI[idx:]
	} else if !strings.HasPrefix(jwksURI, base) {
		if slash := strings.Index(jwksURI[len("https://"):], "/"); slash >= 0 {
			jwksURI = base + jwksURI[len("https://")+slash:]
		}
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, jwksURI, http.NoBody)
	if err != nil {
		tb.Fatalf("NewRequest: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		tb.Fatalf("GET %s: %v", req.URL, err)
	}
	defer resp.Body.Close()

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		tb.Fatalf("decode jwks body: %v", err)
	}
	return resp.StatusCode, resp.Header.Clone(), body
}

// TestScenario_JWKS_001_JWKSServedAsJWKSetJSON verifies the endpoint
// returns 200 with `application/jwk-set+json`.
//
// Spec: RFC 7517 §5 + IANA media-type registration.
func TestScenario_JWKS_001_JWKSServedAsJWKSetJSON(t *testing.T) {
	t.Parallel()

	p := testkit.NewProvider(t)

	status, headers, _ := fetchJWKS(t, p.Server.URL)
	if status != http.StatusOK {
		t.Fatalf("status=%d want 200", status)
	}
	got := headers.Get("Content-Type")
	// RFC 7517 §5 mandates `application/jwk-set+json`. The charset
	// suffix is permitted; assert prefix-match.
	if !strings.HasPrefix(got, "application/jwk-set+json") {
		t.Errorf("Content-Type=%q want application/jwk-set+json prefix", got)
	}
}

// TestScenario_JWKS_002_BodyIsKeysObject checks the top-level shape is
// `{"keys":[...]}`.
//
// Spec: RFC 7517 §5.
func TestScenario_JWKS_002_BodyIsKeysObject(t *testing.T) {
	t.Parallel()

	p := testkit.NewProvider(t)

	_, _, body := fetchJWKS(t, p.Server.URL)
	keys, ok := body["keys"].([]any)
	if !ok {
		t.Fatalf("body[keys]=%T want []any", body["keys"])
	}
	if len(keys) == 0 {
		t.Fatal("body[keys] is empty; testkit always wires one signing key")
	}
}

// TestScenario_JWKS_010_KeyHasKid asserts every published JWK carries a
// `kid`.
//
// Spec: RFC 7517 §4.5 / OIDC Core §10.1.1.
func TestScenario_JWKS_010_KeyHasKid(t *testing.T) {
	t.Parallel()

	p := testkit.NewProvider(t)

	_, _, body := fetchJWKS(t, p.Server.URL)
	keys, _ := body["keys"].([]any)
	for i, raw := range keys {
		k, _ := raw.(map[string]any)
		if kid, _ := k["kid"].(string); kid == "" {
			t.Errorf("keys[%d] missing kid: %+v", i, k)
		}
	}
}

// TestScenario_JWKS_011_KeyHasKty asserts every published JWK carries a
// `kty`.
//
// Spec: RFC 7517 §4.1.
func TestScenario_JWKS_011_KeyHasKty(t *testing.T) {
	t.Parallel()

	p := testkit.NewProvider(t)

	_, _, body := fetchJWKS(t, p.Server.URL)
	keys, _ := body["keys"].([]any)
	for i, raw := range keys {
		k, _ := raw.(map[string]any)
		kty, _ := k["kty"].(string)
		switch kty {
		case "EC", "RSA", "OKP", "oct":
			// recognised
		default:
			t.Errorf("keys[%d] has kty=%q, expected EC|RSA|OKP|oct", i, kty)
		}
	}
}

// TestScenario_JWKS_013_ECKeyPublishesPublicCoordinatesOnly asserts EC
// keys publish `crv`, `x`, `y` and never `d`.
//
// Spec: RFC 7518 §6.2.1 (public params); RFC 7517 §4.7 (private fields
// MUST NOT leak).
func TestScenario_JWKS_013_ECKeyPublishesPublicCoordinatesOnly(t *testing.T) {
	t.Parallel()

	p := testkit.NewProvider(t)

	_, _, body := fetchJWKS(t, p.Server.URL)
	keys, _ := body["keys"].([]any)
	for i, raw := range keys {
		k, _ := raw.(map[string]any)
		if k["kty"] != "EC" {
			continue
		}
		for _, field := range []string{"crv", "x", "y"} {
			if v, _ := k[field].(string); v == "" {
				t.Errorf("keys[%d] EC key missing %q", i, field)
			}
		}
		if _, present := k["d"]; present {
			t.Errorf("keys[%d] EC key must not publish private scalar 'd'", i)
		}
	}
}

// TestScenario_JWKS_017_NoPrivateMaterialEverPublished is a structural
// guard: scan every JWK for any of the private-key fields RFC 7517 §4.7
// forbids in a public set. This is the most important regression
// surface the JWKS catalog protects.
//
// Spec: RFC 7517 §4.7.
func TestScenario_JWKS_017_NoPrivateMaterialEverPublished(t *testing.T) {
	t.Parallel()

	p := testkit.NewProvider(t)

	_, _, body := fetchJWKS(t, p.Server.URL)
	keys, _ := body["keys"].([]any)

	private := []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"}
	for i, raw := range keys {
		k, _ := raw.(map[string]any)
		for _, field := range private {
			if _, present := k[field]; present {
				t.Errorf("keys[%d] leaks private field %q: %+v", i, field, k)
			}
		}
	}
}

// --- Pending bindings --------------------------------------------------

func TestScenario_JWKS_003_HandlerDoesNotBindEntities(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JWKS-003")
}

func TestScenario_JWKS_012_RSAKeyPublishesNAndE(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JWKS-012 — testkit wires EC only; revisit after RSA fixture lands")
}

func TestScenario_JWKS_014_OKPKeyPublishesCrvAndX(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JWKS-014 — testkit wires EC only; revisit after OKP fixture lands")
}

func TestScenario_JWKS_015_UseFieldIsSigOrEnc(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JWKS-015")
}

func TestScenario_JWKS_016_AlgFieldIsRegisteredJWA(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JWKS-016")
}

func TestScenario_JWKS_020_EncryptionKeysPublishedWhenFeatureOn(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JWKS-020 — encryption feature not implemented")
}

func TestScenario_JWKS_021_SigningKeyMayOmitUseAndAlg(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JWKS-021")
}

func TestScenario_JWKS_030_AllKeysAreSigWhenEncryptionOff(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JWKS-030")
}

func TestScenario_JWKS_040_NewKeyPublishedBeforeUse(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JWKS-040")
}

func TestScenario_JWKS_041_RotatedOutKeysRetainedUntilExpiry(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JWKS-041")
}

func TestScenario_JWKS_042_RotationIssuesNewKid(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JWKS-042")
}

func TestScenario_JWKS_050_CacheControlAdvisedShortTTL(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JWKS-050")
}

func TestScenario_JWKS_051_JWKSEndpointIsCORSOpen(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JWKS-051")
}
