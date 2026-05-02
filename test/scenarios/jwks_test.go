package scenarios_test

// Catalog: test/scenarios/catalog/jwks.yaml (JWKS-NNN)
// Spec:
//   - RFC 7517 — JSON Web Key
//   - RFC 7518 — JSON Web Algorithms
//   - OIDC Core 1.0 §10, §10.1, §10.1.1, §10.2
//   - OIDC Discovery 1.0 §3 (`jwks_uri`)

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// newScenarioSigningKey returns a fresh ECDSA P-256 signer wrapped in
// op.SigningKey. The helper is local to the scenarios suite so JWKS
// rotation rows can build a multi-entry Keyset without depending on
// op-internal test fixtures (which are not exported).
func newScenarioSigningKey(tb testing.TB, kid string) op.SigningKey {
	tb.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("generate signing key %q: %v", kid, err)
	}
	return op.SigningKey{KeyID: kid, Signer: priv}
}

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

// TestScenario_JWKS_003_HandlerDoesNotBindEntities verifies that
// /jwks is unauthenticated and stateless: it MUST NOT bind any
// client/session/token entity, MUST NOT require Authorization, and
// MUST NOT mint a Set-Cookie. The wire-level signal is that an
// arbitrary bogus Authorization header has no effect on status or
// body shape, and no Set-Cookie appears on either response.
//
// Spec: implementation contract — /jwks is the public key set, not a
// per-caller resource.
func TestScenario_JWKS_003_HandlerDoesNotBindEntities(t *testing.T) {
	t.Parallel()

	p := testkit.NewProvider(t)

	_, _, doc := fetchDiscovery(t, p.Server.URL)
	jwksURI, _ := doc["jwks_uri"].(string)
	if jwksURI == "" {
		t.Fatalf("discovery missing jwks_uri")
	}
	if strings.HasPrefix(jwksURI, "https://") {
		if slash := strings.Index(jwksURI[len("https://"):], "/"); slash >= 0 {
			jwksURI = p.Server.URL + jwksURI[len("https://")+slash:]
		}
	}

	get := func(authz string) (int, http.Header, map[string]any) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, jwksURI, http.NoBody)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		if authz != "" {
			req.Header.Set("Authorization", authz)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET %s authz=%q: %v", jwksURI, authz, err)
		}
		defer resp.Body.Close()
		var body map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("decode jwks body: %v", err)
		}
		return resp.StatusCode, resp.Header.Clone(), body
	}

	statusAnon, headersAnon, bodyAnon := get("")
	if statusAnon != http.StatusOK {
		t.Fatalf("anonymous /jwks status=%d want 200", statusAnon)
	}
	if cookies := headersAnon.Values("Set-Cookie"); len(cookies) > 0 {
		t.Errorf("anonymous /jwks emitted Set-Cookie=%v; handler must be stateless", cookies)
	}

	statusBogus, headersBogus, bodyBogus := get("Bearer not.a.real.token.value")
	if statusBogus != http.StatusOK {
		t.Errorf("bogus-Authorization /jwks status=%d want 200; bearer MUST be ignored", statusBogus)
	}
	if cookies := headersBogus.Values("Set-Cookie"); len(cookies) > 0 {
		t.Errorf("bogus-Authorization /jwks emitted Set-Cookie=%v; handler must be stateless", cookies)
	}

	keysAnon, _ := bodyAnon["keys"].([]any)
	keysBogus, _ := bodyBogus["keys"].([]any)
	if len(keysAnon) != len(keysBogus) {
		t.Errorf("body shape diverged when Authorization was supplied: anon=%d keys, bogus=%d keys",
			len(keysAnon), len(keysBogus))
	}
}

// TestScenario_JWKS_012_RSAKeyPublishesNAndE is OOS — see catalog out_of_scope_reason.
func TestScenario_JWKS_012_RSAKeyPublishesNAndE(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: JWKS-012 (see catalog out_of_scope_reason)")
}

// TestScenario_JWKS_014_OKPKeyPublishesCrvAndX is OOS — see catalog out_of_scope_reason.
func TestScenario_JWKS_014_OKPKeyPublishesCrvAndX(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: JWKS-014 (see catalog out_of_scope_reason)")
}

// TestScenario_JWKS_015_UseFieldIsSigOrEnc verifies that every JWK
// the OP publishes either omits the `use` field (RFC 7517 §4.2 makes
// it OPTIONAL — clients infer from `alg`) or sets it to one of the
// two values the spec defines (`sig` or `enc`). Any other value is a
// regression that breaks RP key-selection logic.
//
// Spec: RFC 7517 §4.2.
func TestScenario_JWKS_015_UseFieldIsSigOrEnc(t *testing.T) {
	t.Parallel()

	p := testkit.NewProvider(t)

	_, _, body := fetchJWKS(t, p.Server.URL)
	keys, _ := body["keys"].([]any)
	if len(keys) == 0 {
		t.Fatal("body[keys] is empty; testkit always wires one signing key")
	}
	for i, raw := range keys {
		k, _ := raw.(map[string]any)
		v, present := k["use"]
		if !present {
			continue
		}
		use, _ := v.(string)
		if use != "sig" && use != "enc" {
			t.Errorf("keys[%d] use=%q want sig or enc (RFC 7517 §4.2)", i, use)
		}
	}
}

// TestScenario_JWKS_016_AlgFieldIsRegisteredJWA verifies that every
// JWK that publishes an `alg` declares a registered JWA value. The
// allowlist intentionally covers the project's signing & encryption
// algorithm sets (RFC 7518 + RFC 8037 + RFC 8812) without trying to
// be a complete IANA mirror — the goal is to catch typos and hostile
// values like "none" or unregistered legacy strings.
//
// Spec: RFC 7517 §4.4 + RFC 7518 §3 (IANA "JSON Web Signature and
// Encryption Algorithms" registry).
func TestScenario_JWKS_016_AlgFieldIsRegisteredJWA(t *testing.T) {
	t.Parallel()

	p := testkit.NewProvider(t)

	_, _, body := fetchJWKS(t, p.Server.URL)
	keys, _ := body["keys"].([]any)
	if len(keys) == 0 {
		t.Fatal("body[keys] is empty; testkit always wires one signing key")
	}
	registered := map[string]struct{}{
		// Signing.
		"HS256": {}, "HS384": {}, "HS512": {},
		"RS256": {}, "RS384": {}, "RS512": {},
		"ES256": {}, "ES384": {}, "ES512": {}, "ES256K": {},
		"PS256": {}, "PS384": {}, "PS512": {},
		"EdDSA": {},
		// Key management / content encryption.
		"RSA-OAEP": {}, "RSA-OAEP-256": {}, "RSA-OAEP-384": {}, "RSA-OAEP-512": {},
		"ECDH-ES": {}, "ECDH-ES+A128KW": {}, "ECDH-ES+A192KW": {}, "ECDH-ES+A256KW": {},
		"A128KW": {}, "A192KW": {}, "A256KW": {},
		"A128GCMKW": {}, "A192GCMKW": {}, "A256GCMKW": {},
		"PBES2-HS256+A128KW": {}, "PBES2-HS384+A192KW": {}, "PBES2-HS512+A256KW": {},
		"dir": {},
	}
	for i, raw := range keys {
		k, _ := raw.(map[string]any)
		v, present := k["alg"]
		if !present {
			continue
		}
		alg, _ := v.(string)
		if alg == "" {
			t.Errorf("keys[%d] has empty alg field", i)
			continue
		}
		if alg == "none" {
			t.Errorf("keys[%d] alg=%q is not a JWS/JWE algorithm and MUST NOT appear in JWKS", i, alg)
			continue
		}
		if _, ok := registered[alg]; !ok {
			t.Errorf("keys[%d] alg=%q is not a registered JWA value", i, alg)
		}
	}
}

// TestScenario_JWKS_020_EncryptionKeysPublishedWhenFeatureOn is OOS — see catalog out_of_scope_reason.
func TestScenario_JWKS_020_EncryptionKeysPublishedWhenFeatureOn(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: JWKS-020 (see catalog out_of_scope_reason)")
}

// TestScenario_JWKS_021_SigningKeyMayOmitUseAndAlg pins the OP's
// per-purpose signing-key wire shape. RFC 7517 §4.2 / §4.4 make `use`
// and `alg` OPTIONAL — a key MAY be published without either — but
// the spec also notes embedders SHOULD prefer pinning for clarity.
// The OP follows the SHOULD: every published signing key carries
// both use=sig and alg=ES256 so RP verifiers can route the key
// without parsing kty / crv. The test asserts this default policy.
//
// Spec: OIDC Discovery §3 / RFC 7517 §4.2 / §4.4.
func TestScenario_JWKS_021_SigningKeyMayOmitUseAndAlg(t *testing.T) {
	t.Parallel()

	p := testkit.NewProvider(t)

	_, _, body := fetchJWKS(t, p.Server.URL)
	keys, _ := body["keys"].([]any)
	if len(keys) == 0 {
		t.Fatal("body[keys] is empty; testkit always wires one signing key")
	}
	for i, raw := range keys {
		k, _ := raw.(map[string]any)
		if got, _ := k["use"].(string); got != "sig" {
			t.Errorf("keys[%d] use=%q want \"sig\" (OP pins use per the SHOULD in RFC 7517 §4.2)", i, got)
		}
		if got, _ := k["alg"].(string); got != "ES256" {
			t.Errorf("keys[%d] alg=%q want \"ES256\" (OP pins alg per the SHOULD in RFC 7517 §4.4)", i, got)
		}
	}
}

// TestScenario_JWKS_030_AllKeysAreSigWhenEncryptionOff verifies that,
// with the encryption feature disabled (the project default), every
// key the OP publishes either omits `use` or sets it to `sig`. A
// `use=enc` key under a non-encryption-enabled OP would be a
// configuration leak: the OP would advertise material it has no
// crypto path to use, and RPs that key-pin on `use` would route
// traffic into a dead end.
//
// Spec: OIDC Core §10.1.
func TestScenario_JWKS_030_AllKeysAreSigWhenEncryptionOff(t *testing.T) {
	t.Parallel()

	p := testkit.NewProvider(t)

	_, _, body := fetchJWKS(t, p.Server.URL)
	keys, _ := body["keys"].([]any)
	if len(keys) == 0 {
		t.Fatal("body[keys] is empty; testkit always wires one signing key")
	}
	for i, raw := range keys {
		k, _ := raw.(map[string]any)
		v, present := k["use"]
		if !present {
			continue
		}
		if got, _ := v.(string); got != "sig" {
			t.Errorf("keys[%d] use=%q want sig (encryption feature is off)", i, got)
		}
	}
}

// TestScenario_JWKS_040_NewKeyPublishedBeforeUse verifies that every
// kid the embedder placed in [op.Keyset] is published in /jwks
// immediately. RFC 7517 §4.5 / OIDC Core §10.1.1 require lazy verifiers
// to be able to fetch a freshly added key before the OP signs anything
// with it; the wire-level evidence is that the kid is reachable in the
// public set as soon as op.New returns.
//
// The test wires a two-entry Keyset {active, retired} (the OP signs
// with index 0; later entries are retired) and asserts both kids are
// observable in /jwks. JWKS-041 leans on the same setup but reads it
// from the retired-key angle.
//
// Spec: RFC 7517 §4.5 / OIDC Core §10.1.1.
func TestScenario_JWKS_040_NewKeyPublishedBeforeUse(t *testing.T) {
	t.Parallel()

	active := newScenarioSigningKey(t, "scenario-jwks-040-active")
	retired := newScenarioSigningKey(t, "scenario-jwks-040-retired")
	p := testkit.NewProvider(t, testkit.WithOptions(
		op.WithKeyset(op.Keyset{active, retired}),
	))

	_, _, body := fetchJWKS(t, p.Server.URL)
	keys, _ := body["keys"].([]any)
	got := publishedKIDs(keys)
	for _, want := range []string{active.KeyID, retired.KeyID} {
		if _, ok := got[want]; !ok {
			t.Errorf("kid %q missing from /jwks (got %v)", want, got)
		}
	}
}

// TestScenario_JWKS_041_RotatedOutKeysRetainedUntilExpiry asserts that
// a key occupying a non-zero Keyset index — i.e. one the embedder
// rotated out of the active signing slot — continues to be published
// in /jwks until the embedder explicitly drops it. OIDC Core §10.1.1
// requires retired keys to remain reachable so RPs can verify
// in-flight tokens that were signed by them.
//
// Spec: OIDC Core §10.1.1.
func TestScenario_JWKS_041_RotatedOutKeysRetainedUntilExpiry(t *testing.T) {
	t.Parallel()

	active := newScenarioSigningKey(t, "scenario-jwks-041-active")
	retired := newScenarioSigningKey(t, "scenario-jwks-041-retired")
	p := testkit.NewProvider(t, testkit.WithOptions(
		op.WithKeyset(op.Keyset{active, retired}),
	))

	_, _, body := fetchJWKS(t, p.Server.URL)
	keys, _ := body["keys"].([]any)
	got := publishedKIDs(keys)
	if _, ok := got[retired.KeyID]; !ok {
		t.Errorf("retired kid %q missing from /jwks (got %v); rotated-out keys MUST stay published", retired.KeyID, got)
	}
}

// publishedKIDs collects the "kid" string of every JWK in the slice so
// rotation rows can assert membership without nested loops.
func publishedKIDs(keys []any) map[string]struct{} {
	out := make(map[string]struct{}, len(keys))
	for _, raw := range keys {
		k, _ := raw.(map[string]any)
		if kid, _ := k["kid"].(string); kid != "" {
			out[kid] = struct{}{}
		}
	}
	return out
}

// TestScenario_JWKS_042_RotationIssuesNewKid asserts that the OP
// refuses to construct a Keyset whose entries reuse a kid. RFC 7517
// §4.5 makes kid an identifier — a rotation that re-publishes the
// same kid for a different key would silently invalidate every
// in-flight token that pinned the old material to that name.
//
// The wire-level evidence here is structural: op.New rejects a
// duplicate-kid Keyset at construction time, so by the time /jwks is
// reachable every published kid is necessarily unique. The test
// constructs the OP through op.New directly because testkit.NewProvider
// surfaces construction errors via tb.Fatalf.
//
// Spec: RFC 7517 §4.5.
func TestScenario_JWKS_042_RotationIssuesNewKid(t *testing.T) {
	t.Parallel()

	dupA := newScenarioSigningKey(t, "scenario-jwks-042-dup")
	dupB := newScenarioSigningKey(t, "scenario-jwks-042-dup")

	_, err := op.New(
		op.WithIssuer("https://op.testkit.invalid"),
		op.WithStore(inmem.New()),
		op.WithKeyset(op.Keyset{dupA, dupB}),
		op.WithCookieKeys(newJWKSCookieKey(t)),
	)
	if err == nil {
		t.Fatal("op.New accepted a duplicate-kid Keyset; rotation MUST mint a fresh kid")
	}
}

// newJWKSCookieKey returns a fresh 32-byte cookie key for op.WithCookieKey.
// The helper is local to the JWKS file because JWKS-042 is the only row
// in the suite that constructs op.New without going through testkit,
// and the BUS file already owns its own cookie-key helper.
func newJWKSCookieKey(tb testing.TB) []byte {
	tb.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		tb.Fatalf("generate cookie key: %v", err)
	}
	return key
}

// TestScenario_JWKS_050_CacheControlAdvisedShortTTL verifies that the
// /jwks response carries a Cache-Control header advertising a max-age
// so browsers and intermediaries can cache the public key set. The
// implementation publishes "public, max-age=86400, stale-while-
// revalidate=3600" by default (a shorter window applies during a
// rotation window). This row pins the wire-level cacheability
// contract; the exact TTL is implementation policy.
//
// Spec: OIDC Discovery §3 (jwks_uri caching guidance).
func TestScenario_JWKS_050_CacheControlAdvisedShortTTL(t *testing.T) {
	t.Parallel()

	p := testkit.NewProvider(t)

	_, headers, _ := fetchJWKS(t, p.Server.URL)
	cc := headers.Get("Cache-Control")
	if cc == "" {
		t.Fatalf("Cache-Control missing on /jwks; embedders need a cacheability hint")
	}
	if !strings.Contains(cc, "max-age=") {
		t.Errorf("Cache-Control=%q must advertise max-age=...", cc)
	}
	if !strings.Contains(cc, "public") {
		t.Errorf("Cache-Control=%q must include \"public\" — JWKS is not user-specific", cc)
	}
}

// TestScenario_JWKS_051_JWKSEndpointIsCORSOpen verifies that /jwks is
// reachable from any browser origin: both the actual GET and the
// OPTIONS preflight emit Access-Control-Allow-Origin echoing the
// caller's Origin or "*". Browsers MUST be able to cache the public
// key set without a per-RP allowlist.
//
// Spec: Fetch CORS / OIDC Core §10. Cross-ref: cors#COR-003.
func TestScenario_JWKS_051_JWKSEndpointIsCORSOpen(t *testing.T) {
	t.Parallel()

	p := testkit.NewProvider(t)

	_, _, doc := fetchDiscovery(t, p.Server.URL)
	jwksURI, _ := doc["jwks_uri"].(string)
	if jwksURI == "" {
		t.Fatalf("discovery missing jwks_uri")
	}
	if strings.HasPrefix(jwksURI, "https://") {
		if slash := strings.Index(jwksURI[len("https://"):], "/"); slash >= 0 {
			jwksURI = p.Server.URL + jwksURI[len("https://")+slash:]
		}
	}

	for _, method := range []string{http.MethodGet, http.MethodOptions} {
		_, headers := corsRequest(t, method, jwksURI)
		allow := headers.Get("Access-Control-Allow-Origin")
		if allow != corsOrigin && allow != "*" {
			t.Errorf("[%s] Access-Control-Allow-Origin=%q want %q or *", method, allow, corsOrigin)
		}
	}
}
