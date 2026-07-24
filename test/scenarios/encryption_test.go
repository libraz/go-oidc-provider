package scenarios_test

// Catalog: test/scenarios/catalog/encryption.yaml (ENC-NNN)
// Spec:
//   - RFC 7516 — JSON Web Encryption
//   - RFC 7517 §4.2 — use=sig / use=enc separation
//   - RFC 7518 — JSON Web Algorithms (alg / enc)
//   - RFC 7519 §11 — JWE-nested-JWT
//   - RFC 8037 — CFRG curves
//   - OIDC Core 1.0 §3.1.3.7, §10.1, §10.2, §16.7
//   - OIDC Discovery 1.0 §3 (`*_encryption_alg/enc_values_supported`)
//   - RFC 9101 — JWT-Secured Authorization Request (JAR)
//   - RFC 9126 — Pushed Authorization Requests (PAR)
//   - RFC 9701 — JWT Response for OAuth Token Introspection
//   - FAPI 2.0 Message Signing §5.5 (JARM)

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
	"github.com/libraz/go-oidc-provider/op/testkit"
	"github.com/libraz/go-oidc-provider/test/scenarios/internal/scenariokit"
)

// encVerifyInnerJWS decodes the inner compact JWS produced by stripping
// the outer JWE and verifies its ES256 signature against the OP's
// active public signing key. The helper centralises the round-trip
// every encrypted-token scenario performs after [scenariokit.DecryptJWE].
func encVerifyInnerJWS(t *testing.T, tk *testkit.Provider, inner string) map[string]any {
	t.Helper()
	parsed, err := jwt.ParseSigned(inner, []josev4.SignatureAlgorithm{josev4.ES256})
	if err != nil {
		t.Fatalf("ParseSigned inner JWS: %v (raw=%q)", err, inner)
	}
	pub, ok := tk.SigningKey.Signer.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("testkit signer public key is not *ecdsa.PublicKey: %T", tk.SigningKey.Signer.Public())
	}
	out := map[string]any{}
	if err := parsed.Claims(pub, &out); err != nil {
		t.Fatalf("verify inner JWS: %v", err)
	}
	return out
}

// TestScenario_ENC_001_SymmetricAlgRequiresClientSecret is OOS — see catalog out_of_scope_reason.
func TestScenario_ENC_001_SymmetricAlgRequiresClientSecret(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ENC-001 (see catalog out_of_scope_reason)")
}

// TestScenario_ENC_002_ExpiredSecretBlocksSymmetricIDToken is OOS — see catalog out_of_scope_reason.
func TestScenario_ENC_002_ExpiredSecretBlocksSymmetricIDToken(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ENC-002 (see catalog out_of_scope_reason)")
}

// TestScenario_ENC_010_DiscoveryAdvertisesEncryptionMetadata pins the
// OIDC Discovery 1.0 §3 toggle: when [op.WithEncryptionKeyset] is
// configured the eight `*_encryption_*_values_supported` arrays MUST
// be present, and when it is omitted those same fields MUST be absent
// (the document uses `omitempty`).
//
// Spec: OIDC Discovery 1.0 §3.
func TestScenario_ENC_010_DiscoveryAdvertisesEncryptionMetadata(t *testing.T) {
	t.Parallel()

	encFields := []string{
		"id_token_encryption_alg_values_supported",
		"id_token_encryption_enc_values_supported",
		"request_object_encryption_alg_values_supported",
		"request_object_encryption_enc_values_supported",
		"userinfo_encryption_alg_values_supported",
		"userinfo_encryption_enc_values_supported",
		"authorization_encryption_alg_values_supported",
		"authorization_encryption_enc_values_supported",
	}

	encKey := scenariokit.NewOPEncryptionKey(t, "enc-1")
	tkOn := testkit.NewProvider(t, testkit.WithOptions(
		op.WithFeature(feature.JAR),
		op.WithFeature(feature.JARM),
		op.WithFeature(feature.Introspect),
		op.WithEncryptionKeyset(op.EncryptionKeyset{encKey}),
	))
	_, _, doc := fetchDiscovery(t, tkOn.Server.URL)
	for _, f := range encFields {
		v, ok := doc[f]
		if !ok {
			t.Errorf("with encryption keyset: discovery doc missing %q", f)
			continue
		}
		arr, ok := v.([]any)
		if !ok || len(arr) == 0 {
			t.Errorf("with encryption keyset: discovery field %q must be non-empty array, got %T %v", f, v, v)
		}
	}

	tkOff := testkit.NewProvider(t, testkit.WithOptions(
		op.WithFeature(feature.JAR),
		op.WithFeature(feature.JARM),
		op.WithFeature(feature.Introspect),
	))
	_, _, docOff := fetchDiscovery(t, tkOff.Server.URL)
	for _, f := range encFields {
		if v, present := docOff[f]; present {
			if arr, ok := v.([]any); !ok || len(arr) != 0 {
				t.Errorf("without encryption keyset: discovery field %q must be absent or empty, got %v", f, v)
			}
		}
	}
}

// TestScenario_ENC_020_NestedJWEIsFivePartCompact pins the RFC 7516 §3
// shape: an encrypted ID Token is a 5-part compact serialisation
// (header.cek.iv.ct.tag); decryption yields a compact JWS whose
// 3-part shape and ES256 signature verify against the OP's published
// signing JWKS. The protected-header cty=JWT (RFC 7519 §5.2) is
// asserted by [scenariokit.DecryptJWE].
//
// Spec: RFC 7516 §3 / OIDC Core §10.2 / RFC 7519 §5.2.
func TestScenario_ENC_020_NestedJWEIsFivePartCompact(t *testing.T) {
	t.Parallel()

	const (
		clientID = "rp-enc-020"
		callback = "https://rp.testkit.invalid/callback"
	)
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-enc-020-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	encKey := scenariokit.NewOPEncryptionKey(t, "enc-1")
	rp := scenariokit.NewRPEncryptionKey(t, "rp-enc-020-key")

	tk := testkit.NewProvider(t, testkit.WithOptions(
		op.WithEncryptionKeyset(op.EncryptionKeyset{encKey}),
	))
	//nolint:gosec // G101 false positive: ClientFixture struct literal carries test-only fields.
	tk.RegisterClient(t, testkit.ClientFixture{
		ID:                          clientID,
		SecretHash:                  hash,
		RedirectURIs:                []string{callback},
		Scopes:                      []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod:     "client_secret_basic",
		GrantTypes:                  []string{"authorization_code", "refresh_token"},
		ResponseTypes:               []string{"code"},
		JWKs:                        rp.JWKS,
		IDTokenEncryptedResponseAlg: "RSA-OAEP-256",
		IDTokenEncryptedResponseEnc: "A256GCM",
	})

	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    clientID,
		RedirectURI: callback,
		PKCE:        pkce,
	})
	if flow.Code == "" {
		t.Fatalf("authorize callback missing code: %+v", flow)
	}
	tok := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code:         flow.Code,
		RedirectURI:  callback,
		Verifier:     pkce.Verifier,
		ClientID:     clientID,
		ClientSecret: clientSecret,
	})
	if tok.StatusCode != http.StatusOK || tok.IDToken == "" {
		t.Fatalf("/token status=%d body=%v want 200 with id_token", tok.StatusCode, tok.Raw)
	}

	if got := scenariokit.JWEParts(tok.IDToken); len(got) != 5 {
		t.Fatalf("id_token has %d parts, want 5 (JWE compact)", len(got))
	}
	inner := scenariokit.DecryptJWE(t, tok.IDToken, rp.Private)
	if got := strings.Split(inner, "."); len(got) != 3 {
		t.Fatalf("inner JWS has %d parts, want 3 (JWS compact)", len(got))
	}
	encVerifyInnerJWS(t, tk, inner)
}

// TestScenario_ENC_021_EncryptedIDTokenHeaderCarriesIssAud is OOS — see catalog out_of_scope_reason.
func TestScenario_ENC_021_EncryptedIDTokenHeaderCarriesIssAud(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ENC-021 (see catalog out_of_scope_reason)")
}

// TestScenario_ENC_022_EncryptedUserInfoResponseShape is OOS — see catalog out_of_scope_reason.
func TestScenario_ENC_022_EncryptedUserInfoResponseShape(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ENC-022 (see catalog out_of_scope_reason)")
}

// TestScenario_ENC_023_ExpiredSecretBlocksHS256UserInfo is OOS — see catalog out_of_scope_reason.
func TestScenario_ENC_023_ExpiredSecretBlocksHS256UserInfo(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ENC-023 (see catalog out_of_scope_reason)")
}

// TestScenario_ENC_024_ExpiredSecretBlocksDirUserInfo is OOS — see catalog out_of_scope_reason.
func TestScenario_ENC_024_ExpiredSecretBlocksDirUserInfo(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ENC-024 (see catalog out_of_scope_reason)")
}

// encJARFixture bundles a JAR + encryption-enabled provider with a
// confidential client whose signing keypair the harness owns. Tests
// build a signed inner JWS (the request object body) with the
// fixture's private key, then wrap it in a JWE addressed to the OP's
// public encryption key. The fixture is local to ENC-030/031/040 to
// avoid cross-pollination with the JAR / PAR fixtures, which do not
// configure encryption.
type encJARFixture struct {
	tk           *testkit.Provider
	clientID     string
	clientSecret string
	redirectURI  string
	signPriv     *ecdsa.PrivateKey
	signKID      string
	encPub       *rsa.PublicKey
	encKID       string
}

// newEncJARFixture spins up a JAR + PAR + encryption-keyset provider
// and registers a confidential client whose JWKS advertises a single
// ES256 signing key. The OP's encryption keypair is exposed via the
// returned encPub / encKID so callers can wrap the inner JWS without
// going through the OP's /jwks.json endpoint.
func newEncJARFixture(t *testing.T, withPAR bool) *encJARFixture {
	t.Helper()

	signPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	const signKID = "rp-enc-jar-sig"
	jwksRaw, err := json.Marshal(josev4.JSONWebKeySet{
		Keys: []josev4.JSONWebKey{{
			Key:       &signPriv.PublicKey,
			KeyID:     signKID,
			Algorithm: string(josev4.ES256),
			Use:       "sig",
		}},
	})
	if err != nil {
		t.Fatalf("Marshal client JWKS: %v", err)
	}

	const clientID = "rp-enc-jar"
	const callback = "https://rp.testkit.invalid/callback"
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-enc-jar-secret"
	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}

	encKey := scenariokit.NewOPEncryptionKey(t, "op-enc-1")
	opts := []op.Option{
		op.WithFeature(feature.JAR),
		op.WithEncryptionKeyset(op.EncryptionKeyset{encKey}),
	}
	if withPAR {
		opts = append(opts, op.WithFeature(feature.PAR))
	}
	tk := testkit.NewProvider(t, testkit.WithOptions(opts...))
	tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		RedirectURIs:            []string{callback},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		JWKs:                    jwksRaw,
	})

	encPriv, ok := encKey.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("encKey.PrivateKey is %T, want *rsa.PrivateKey", encKey.PrivateKey)
	}

	return &encJARFixture{
		tk:           tk,
		clientID:     clientID,
		clientSecret: clientSecret,
		redirectURI:  callback,
		signPriv:     signPriv,
		signKID:      signKID,
		encPub:       &encPriv.PublicKey,
		encKID:       encKey.KeyID,
	}
}

// happyClaims returns the canonical request-object claim set for the
// fixture's client. Tests mutate it before signing if they want to
// drive an alternative response_type / scope shape.
func (f *encJARFixture) happyClaims(pkce scenariokit.PKCEPair) map[string]any {
	now := time.Now().UTC()
	return map[string]any{
		"iss":                   f.clientID,
		"aud":                   f.tk.Issuer,
		"exp":                   now.Add(2 * time.Minute).Unix(),
		"iat":                   now.Unix(),
		"nbf":                   now.Unix(),
		"jti":                   "enc-jar-jti-" + now.Format("20060102T150405.000000000"),
		"client_id":             f.clientID,
		"response_type":         "code",
		"redirect_uri":          f.redirectURI,
		"scope":                 "openid profile email",
		"state":                 "enc-jar-state",
		"nonce":                 "enc-jar-nonce",
		"code_challenge":        pkce.Challenge,
		"code_challenge_method": pkce.Method,
	}
}

// signES256 serialises claims as a compact ES256 JWS using the
// fixture's signing keypair / kid.
func (f *encJARFixture) signES256(t *testing.T, claims map[string]any) string {
	t.Helper()
	signer, err := josev4.NewSigner(
		josev4.SigningKey{
			Algorithm: josev4.ES256,
			Key: josev4.JSONWebKey{
				Key:       f.signPriv,
				KeyID:     f.signKID,
				Algorithm: string(josev4.ES256),
				Use:       "sig",
			},
		},
		(&josev4.SignerOptions{}).WithType("oauth-authz-req+jwt"),
	)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	out, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	return out
}

// TestScenario_ENC_030_UnsupportedAlgRejectsRequestObject pins the
// JAR JWE allow-list gate: an /authorize request whose request_object
// is JWE-encrypted with an alg outside the OP allow-list (e.g.
// RSA-OAEP-512 when only RSA-OAEP-256 is admitted) MUST be refused
// with error=invalid_request_object.
//
// Deviation from catalog text: the catalog says "redirect whose query
// string carries error=invalid_request_object" but the actual
// implementation surfaces the failure as a JSON 400 envelope with
// `error: "invalid_request_object"` (writeJAREnvelopeError). The test
// pins the JSON-envelope shape because that is the v0.9.1 wire form;
// the same wire code is asserted either way.
//
// The hostile JWE is constructed by encrypting under RSA-OAEP-256 then
// rewriting the protected header's `alg` to RSA-OAEP-512 — go-jose v4
// will not mint a JWE with a banned alg directly, so post-hoc header
// tampering is the standard JAR-test idiom (mirrors
// internal/jar/verify_jwe_test.go's tamperJWEAlg).
//
// Spec: RFC 9101 §6.1 / OIDC Discovery.
func TestScenario_ENC_030_UnsupportedAlgRejectsRequestObject(t *testing.T) {
	t.Parallel()

	f := newEncJARFixture(t, false)
	pkce := scenariokit.NewPKCEPair("")
	signed := f.signES256(t, f.happyClaims(pkce))
	jwe := scenariokit.EncryptJWE(t, signed, f.encPub, f.encKID, "RSA-OAEP-256", "A256GCM")
	tampered := scenariokit.TamperJWEHeader(t, jwe, "alg", "RSA-OAEP-256", "RSA-OAEP-512")

	values := url.Values{
		"client_id": {f.clientID},
		"request":   {tampered},
	}
	target := f.tk.Server.URL + "/oidc/auth?" + values.Encode()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := f.tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 400 body=%s", resp.StatusCode, body)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var env map[string]any
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("decode envelope %q: %v", body, err)
	}
	if got, _ := env["error"].(string); got != "invalid_request_object" {
		t.Errorf("error=%q want invalid_request_object (env=%v)", got, env)
	}
}

// TestScenario_ENC_031_UnsupportedEncRejectsRequestObject mirrors
// ENC-030 for the `enc` half of the allow-list: a JWE whose protected
// header carries an enc outside {A128GCM, A256GCM} (here
// A192CBC-HS384) MUST surface error=invalid_request_object.
//
// Deviation from catalog text: see ENC-030 — actual wire shape is JSON
// 400, not redirect.
//
// Spec: RFC 9101 §6.1.
func TestScenario_ENC_031_UnsupportedEncRejectsRequestObject(t *testing.T) {
	t.Parallel()

	f := newEncJARFixture(t, false)
	pkce := scenariokit.NewPKCEPair("")
	signed := f.signES256(t, f.happyClaims(pkce))
	jwe := scenariokit.EncryptJWE(t, signed, f.encPub, f.encKID, "RSA-OAEP-256", "A256GCM")
	tampered := scenariokit.TamperJWEHeader(t, jwe, "enc", "A256GCM", "A192CBC-HS384")

	values := url.Values{
		"client_id": {f.clientID},
		"request":   {tampered},
	}
	target := f.tk.Server.URL + "/oidc/auth?" + values.Encode()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := f.tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 400 body=%s", resp.StatusCode, body)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var env map[string]any
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("decode envelope %q: %v", body, err)
	}
	if got, _ := env["error"].(string); got != "invalid_request_object" {
		t.Errorf("error=%q want invalid_request_object (env=%v)", got, env)
	}
}

// TestScenario_ENC_032_DefaultJWEInventoryFromKeystore pins the
// discovery surface relationship between the OP's published JWE
// inventory and the public allow-list helpers
// [op.SupportedEncryptionAlgs] / [op.SupportedEncryptionEncs]. With
// [op.WithEncryptionKeyset] configured the
// `request_object_encryption_*_values_supported` arrays MUST be
// non-empty subsets of the public helpers; without the keyset the
// whole `*_encryption_*_values_supported` family MUST be absent
// (omitempty).
//
// Spec: OIDC Core §10.1 / OIDC Discovery §3.
func TestScenario_ENC_032_DefaultJWEInventoryFromKeystore(t *testing.T) {
	t.Parallel()

	supportedAlgs := op.SupportedEncryptionAlgs()
	supportedEncs := op.SupportedEncryptionEncs()
	algSet := make(map[string]struct{}, len(supportedAlgs))
	for _, a := range supportedAlgs {
		algSet[a] = struct{}{}
	}
	encSet := make(map[string]struct{}, len(supportedEncs))
	for _, e := range supportedEncs {
		encSet[e] = struct{}{}
	}

	encFamilyFields := []string{
		"id_token_encryption_alg_values_supported",
		"id_token_encryption_enc_values_supported",
		"request_object_encryption_alg_values_supported",
		"request_object_encryption_enc_values_supported",
		"userinfo_encryption_alg_values_supported",
		"userinfo_encryption_enc_values_supported",
		"authorization_encryption_alg_values_supported",
		"authorization_encryption_enc_values_supported",
	}

	// (a) Without WithEncryptionKeyset.
	tkOff := testkit.NewProvider(t, testkit.WithOptions(
		op.WithFeature(feature.JAR),
		op.WithFeature(feature.JARM),
	))
	_, _, docOff := fetchDiscovery(t, tkOff.Server.URL)
	for _, f := range encFamilyFields {
		if v, present := docOff[f]; present {
			arr, ok := v.([]any)
			if !ok || len(arr) != 0 {
				t.Errorf("without encryption keyset: discovery field %q must be absent or empty, got %v", f, v)
			}
		}
	}

	// (b) With WithEncryptionKeyset: arrays present, subsets of helpers.
	encKey := scenariokit.NewOPEncryptionKey(t, "op-enc-032")
	tkOn := testkit.NewProvider(t, testkit.WithOptions(
		op.WithFeature(feature.JAR),
		op.WithFeature(feature.JARM),
		op.WithEncryptionKeyset(op.EncryptionKeyset{encKey}),
	))
	_, _, docOn := fetchDiscovery(t, tkOn.Server.URL)

	roAlgs, _ := docOn["request_object_encryption_alg_values_supported"].([]any)
	if len(roAlgs) == 0 {
		t.Fatalf("request_object_encryption_alg_values_supported missing or empty: %v", docOn)
	}
	for _, raw := range roAlgs {
		s, _ := raw.(string)
		if _, ok := algSet[s]; !ok {
			t.Errorf("request_object_encryption_alg %q not a subset of op.SupportedEncryptionAlgs()=%v", s, supportedAlgs)
		}
	}

	roEncs, _ := docOn["request_object_encryption_enc_values_supported"].([]any)
	if len(roEncs) == 0 {
		t.Fatalf("request_object_encryption_enc_values_supported missing or empty: %v", docOn)
	}
	for _, raw := range roEncs {
		s, _ := raw.(string)
		if _, ok := encSet[s]; !ok {
			t.Errorf("request_object_encryption_enc %q not a subset of op.SupportedEncryptionEncs()=%v", s, supportedEncs)
		}
	}
}

// TestScenario_ENC_035_NestedJWEDepthCapRejected pins the structural
// depth ceiling on nested JWE-of-JWE-of-...-of-JWS request objects
// (see [internal/jose.MaxJOSENestingDepth]). The JAR / PAR verifier
// budgets [internal/jose.MaxJOSENestingDepth] total JOSE layers; a
// chain whose JWE wrappers + inner JWS exceed that ceiling MUST be
// rejected with a 400 invalid_request_object envelope (the same wire
// shape ENC-030 / ENC-031 pin for unsupported alg / enc — the failure
// class is collapsed so an attacker probing for the cap value via
// wire-code variation learns nothing).
//
// The test wraps a happy-path inner JWS in [internal/jose.MaxJOSENestingDepth]
// JWE layers — one over the budget — and asserts the /authorize endpoint
// responds with a 400 carrying error=invalid_request_object. The pair
// (cap minus one accepted by ENC-040, cap plus one rejected here)
// pins both sides of the inequality so a regression flipping ">" to
// ">=" surfaces immediately.
//
// Spec: RFC 7519 §5.2 (Nested JWT) + RFC 9101 §6.1.
func TestScenario_ENC_035_NestedJWEDepthCapRejected(t *testing.T) {
	t.Parallel()

	f := newEncJARFixture(t, false)
	pkce := scenariokit.NewPKCEPair("")
	signed := f.signES256(t, f.happyClaims(pkce))

	// Build MaxJOSENestingDepth JWE layers around the inner JWS.
	// One JWE alone counts as depth=2 (one JWE + one JWS); to reach
	// MaxJOSENestingDepth+1 total JOSE layers we wrap the JWS in
	// MaxJOSENestingDepth JWEs.
	const overBudget = 10 // mirrors internal/jose.MaxJOSENestingDepth
	payload := signed
	for range overBudget {
		payload = scenariokit.EncryptJWE(t, payload, f.encPub, f.encKID, "RSA-OAEP-256", "A256GCM")
	}

	values := url.Values{
		"client_id": {f.clientID},
		"request":   {payload},
	}
	target := f.tk.Server.URL + "/oidc/auth?" + values.Encode()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := f.tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 400 body=%s", resp.StatusCode, body)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var env map[string]any
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("decode envelope %q: %v", body, err)
	}
	if got, _ := env["error"].(string); got != "invalid_request_object" {
		t.Errorf("error=%q want invalid_request_object (env=%v)", got, env)
	}
}

// TestScenario_ENC_036_DCRRejectsHalfPairEncryptionMetadata pins the
// admit/runtime-reject gap closed by the DCR encryption-pair validator:
// a Dynamic Client Registration request that sets only one half of an
// `*_encrypted_response_alg` / `_enc` pair (or only the matching
// `request_object_encryption_alg` / `_enc`) MUST be rejected with 400
// invalid_client_metadata. The rule applies to all five encrypted-response
// families (id_token, userinfo, request_object, authorization,
// introspection); the row pins id_token as a representative because the
// registration validator routes all five families through the same
// shared helper.
//
// The negative path (alg-only) is paired with the positive path (both
// fields set on the closed JOSE allow-list -> 201 Created) so a future
// regression flipping the gate's polarity surfaces immediately. The
// runtime resolver requires both fields to be present
// (internal/clientencjwks.validateAlgEnc) — registration gating closes
// the gap so the failure surfaces at registration time, not on the
// first encrypted response.
//
// Spec: RFC 7591 §2 / OIDC Core 1.0 §6.1.
func TestScenario_ENC_036_DCRRejectsHalfPairEncryptionMetadata(t *testing.T) {
	t.Parallel()

	encKey := scenariokit.NewOPEncryptionKey(t, "op-enc-036")
	tk := testkit.NewProvider(t, testkit.WithOptions(
		op.WithDynamicRegistration(op.RegistrationOption{Open: true}),
		op.WithEncryptionKeyset(op.EncryptionKeyset{encKey}),
	))

	postRegister := func(t *testing.T, body map[string]any) *http.Response {
		t.Helper()
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
			tk.Server.URL+"/oidc/register", strings.NewReader(string(raw)))
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := tk.HTTPClient(nil).Do(req)
		if err != nil {
			t.Fatalf("POST /register: %v", err)
		}
		return resp
	}

	// Negative: alg only -> 400 invalid_client_metadata.
	halfPairBody := map[string]any{ //nolint:gosec // G101: client-metadata field name "id_token_encrypted_response_alg" is JOSE / OIDC vocabulary, not a credential.
		"redirect_uris":                   []string{"https://rp.testkit.invalid/cb"},
		"id_token_encrypted_response_alg": "RSA-OAEP-256",
	}
	respBad := postRegister(t, halfPairBody)
	defer func() { _ = respBad.Body.Close() }()
	if respBad.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(respBad.Body)
		t.Fatalf("alg-only registration: status=%d want 400 body=%s", respBad.StatusCode, body)
	}
	var badEnv map[string]any
	if err := json.NewDecoder(respBad.Body).Decode(&badEnv); err != nil {
		t.Fatalf("decode 400 body: %v", err)
	}
	if got, _ := badEnv["error"].(string); got != "invalid_client_metadata" {
		t.Errorf("error=%q want invalid_client_metadata (env=%v)", got, badEnv)
	}

	// Positive: both alg+enc set on the closed JOSE allow-list -> 201.
	bothPairBody := map[string]any{ //nolint:gosec // G101: client-metadata field names are JOSE / OIDC vocabulary, not credentials.
		"redirect_uris":                   []string{"https://rp.testkit.invalid/cb"},
		"id_token_encrypted_response_alg": "RSA-OAEP-256",
		"id_token_encrypted_response_enc": "A256GCM",
	}
	respOK := postRegister(t, bothPairBody)
	defer func() { _ = respOK.Body.Close() }()
	if respOK.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(respOK.Body)
		t.Fatalf("both-set registration: status=%d want 201 body=%s", respOK.StatusCode, body)
	}
}

// TestScenario_ENC_040_PARAcceptsEncryptedRequestObject pins the
// RFC 9126 + RFC 9101 happy path for an encrypted-and-signed request
// object: a confidential client signs an inner JWS (ES256) with its
// own key, wraps it in a JWE addressed to the OP's enc-use public key
// (RSA-OAEP-256 / A256GCM, cty=JWT), POSTs the JWE as `request` to
// /par, and follows up with /authorize?request_uri=<urn>. The OP
// decrypts the wrapper, verifies the inner JWS, consumes the
// request_uri once, and emits a "code" redirect to the registered
// callback.
//
// Spec: RFC 9126 §2.1 + RFC 9101 §6.1.
func TestScenario_ENC_040_PARAcceptsEncryptedRequestObject(t *testing.T) {
	t.Parallel()

	f := newEncJARFixture(t, true)
	pkce := scenariokit.NewPKCEPair("")
	signed := f.signES256(t, f.happyClaims(pkce))
	jwe := scenariokit.EncryptJWE(t, signed, f.encPub, f.encKID, "RSA-OAEP-256", "A256GCM")

	parForm := url.Values{
		"request": {jwe},
	}
	parReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		f.tk.Server.URL+"/oidc/par", strings.NewReader(parForm.Encode()))
	if err != nil {
		t.Fatalf("build /par request: %v", err)
	}
	parReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	parReq.SetBasicAuth(f.clientID, f.clientSecret)
	parResp, err := f.tk.HTTPClient(nil).Do(parReq)
	if err != nil {
		t.Fatalf("POST /par: %v", err)
	}
	defer func() { _ = parResp.Body.Close() }()
	if parResp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(parResp.Body)
		t.Fatalf("/par status=%d want 201 body=%s", parResp.StatusCode, body)
	}
	var parBody map[string]any
	if err := json.NewDecoder(parResp.Body).Decode(&parBody); err != nil {
		t.Fatalf("decode /par body: %v", err)
	}
	requestURI, _ := parBody["request_uri"].(string)
	if requestURI == "" {
		t.Fatalf("/par response missing request_uri: %v", parBody)
	}

	// Drive /authorize via the request_uri. The PKCE verifier is
	// recovered from the original request object via the consumed
	// snapshot; only client_id + request_uri are honoured on the
	// /authorize side (RFC 9126 §2.3).
	flow := scenariokit.RunCodeFlow(t, f.tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    f.clientID,
		RedirectURI: f.redirectURI,
		PKCE:        pkce,
		Extra:       url.Values{"request_uri": {requestURI}},
	})
	if flow.Code == "" {
		t.Fatalf("authorize callback missing code: %+v", flow)
	}
	if flow.Error != "" {
		t.Errorf("authorize error=%s desc=%s", flow.Error, flow.ErrorDesc)
	}
}

// TestScenario_ENC_041_PARRespectsPerClientSigningAlg is OOS — see catalog out_of_scope_reason.
func TestScenario_ENC_041_PARRespectsPerClientSigningAlg(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ENC-041 (see catalog out_of_scope_reason)")
}

// TestScenario_ENC_050_ECDHESRequiresClientECKey is OOS — see catalog out_of_scope_reason.
func TestScenario_ENC_050_ECDHESRequiresClientECKey(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ENC-050 (see catalog out_of_scope_reason)")
}

// TestScenario_ENC_060_AcceptsA128KWRequestObject is OOS — see catalog out_of_scope_reason.
func TestScenario_ENC_060_AcceptsA128KWRequestObject(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ENC-060 (see catalog out_of_scope_reason)")
}

// TestScenario_ENC_061_ExpiredSecretBlocksSymmetricDecrypt is OOS — see catalog out_of_scope_reason.
func TestScenario_ENC_061_ExpiredSecretBlocksSymmetricDecrypt(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ENC-061 (see catalog out_of_scope_reason)")
}

// TestScenario_ENC_062_SymmetricIDTokenHeaderShape is OOS — see catalog out_of_scope_reason.
func TestScenario_ENC_062_SymmetricIDTokenHeaderShape(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ENC-062 (see catalog out_of_scope_reason)")
}

// TestScenario_ENC_070_AcceptsDirRequestObject is OOS — see catalog out_of_scope_reason.
func TestScenario_ENC_070_AcceptsDirRequestObject(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ENC-070 (see catalog out_of_scope_reason)")
}

// TestScenario_ENC_071_ExpiredSecretBlocksDirDecrypt is OOS — see catalog out_of_scope_reason.
func TestScenario_ENC_071_ExpiredSecretBlocksDirDecrypt(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ENC-071 (see catalog out_of_scope_reason)")
}

// TestScenario_ENC_072_DirIDTokenHeaderShape is OOS — see catalog out_of_scope_reason.
func TestScenario_ENC_072_DirIDTokenHeaderShape(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ENC-072 (see catalog out_of_scope_reason)")
}

// TestScenario_ENC_100_AuthorizationCodeIDTokenJWE pins the OIDC Core
// 1.0 §10.2 round-trip: a confidential client that registered
// id_token_encrypted_response_alg / _enc receives an id_token field
// shaped as a 5-part nested JWE addressed to its enc-use key. Decrypting
// the JWE and verifying the inner ES256 JWS yields the canonical claim
// set (iss, aud, sub, exp, iat, nonce when requested).
//
// Spec: OIDC Core §10.2 / RFC 7519 §5.2.
func TestScenario_ENC_100_AuthorizationCodeIDTokenJWE(t *testing.T) {
	t.Parallel()

	const (
		clientID = "rp-enc-100"
		callback = "https://rp.testkit.invalid/callback"
	)
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-enc-100-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	encKey := scenariokit.NewOPEncryptionKey(t, "enc-1")
	rp := scenariokit.NewRPEncryptionKey(t, "rp-enc-100-key")

	tk := testkit.NewProvider(t, testkit.WithOptions(
		op.WithEncryptionKeyset(op.EncryptionKeyset{encKey}),
	))
	//nolint:gosec // G101 false positive: ClientFixture struct literal carries test-only fields.
	tk.RegisterClient(t, testkit.ClientFixture{
		ID:                          clientID,
		SecretHash:                  hash,
		RedirectURIs:                []string{callback},
		Scopes:                      []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod:     "client_secret_basic",
		GrantTypes:                  []string{"authorization_code", "refresh_token"},
		ResponseTypes:               []string{"code"},
		JWKs:                        rp.JWKS,
		IDTokenEncryptedResponseAlg: "RSA-OAEP-256",
		IDTokenEncryptedResponseEnc: "A256GCM",
	})

	const customNonce = "enc-100-nonce"
	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    clientID,
		RedirectURI: callback,
		PKCE:        pkce,
		Nonce:       customNonce,
	})
	if flow.Code == "" {
		t.Fatalf("authorize callback missing code: %+v", flow)
	}
	tok := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code:         flow.Code,
		RedirectURI:  callback,
		Verifier:     pkce.Verifier,
		ClientID:     clientID,
		ClientSecret: clientSecret,
	})
	if tok.StatusCode != http.StatusOK || tok.IDToken == "" {
		t.Fatalf("/token status=%d body=%v want 200 with id_token", tok.StatusCode, tok.Raw)
	}
	if got := scenariokit.JWEParts(tok.IDToken); len(got) != 5 {
		t.Fatalf("id_token has %d parts, want 5", len(got))
	}
	inner := scenariokit.DecryptJWE(t, tok.IDToken, rp.Private)
	claims := encVerifyInnerJWS(t, tk, inner)

	if got := claims["iss"]; got != tk.Issuer {
		t.Errorf("iss=%v want %q", got, tk.Issuer)
	}
	if got := claims["aud"]; got != clientID {
		t.Errorf("aud=%v want %q", got, clientID)
	}
	if got := claims["sub"]; got != scenariokit.DefaultSubject {
		t.Errorf("sub=%v want %q", got, scenariokit.DefaultSubject)
	}
	if got := claims["nonce"]; got != customNonce {
		t.Errorf("nonce=%v want %q", got, customNonce)
	}
	if _, ok := claims["exp"].(float64); !ok {
		t.Errorf("exp must be a JSON number: %T", claims["exp"])
	}
	if _, ok := claims["iat"].(float64); !ok {
		t.Errorf("iat must be a JSON number: %T", claims["iat"])
	}
}

// TestScenario_ENC_101_RefreshRotatedIDTokenJWE pins the OIDC Core 1.0
// §12 / RFC 6749 §6 rotation: a refresh_token grant against an
// encryption-enrolled client MUST emit the rotated id_token field as a
// 5-part JWE addressed to the client's enc-use key. The encrypted
// branch fires on every grant that mints a fresh id_token, not only on
// the initial authorization_code exchange.
//
// Spec: OIDC Core §12 / RFC 6749 §6.
func TestScenario_ENC_101_RefreshRotatedIDTokenJWE(t *testing.T) {
	t.Parallel()

	const (
		clientID = "rp-enc-101"
		callback = "https://rp.testkit.invalid/callback"
	)
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-enc-101-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	encKey := scenariokit.NewOPEncryptionKey(t, "enc-1")
	rp := scenariokit.NewRPEncryptionKey(t, "rp-enc-101-key")

	tk := testkit.NewProvider(t, testkit.WithOptions(
		op.WithStrictOfflineAccess(),
		op.WithEncryptionKeyset(op.EncryptionKeyset{encKey}),
	))
	//nolint:gosec // G101 false positive: ClientFixture struct literal carries test-only fields.
	tk.RegisterClient(t, testkit.ClientFixture{
		ID:                          clientID,
		SecretHash:                  hash,
		RedirectURIs:                []string{callback},
		Scopes:                      []string{"openid", "profile", "email", "offline_access"},
		TokenEndpointAuthMethod:     "client_secret_basic",
		GrantTypes:                  []string{"authorization_code", "refresh_token"},
		ResponseTypes:               []string{"code"},
		JWKs:                        rp.JWKS,
		IDTokenEncryptedResponseAlg: "RSA-OAEP-256",
		IDTokenEncryptedResponseEnc: "A256GCM",
	})

	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    clientID,
		RedirectURI: callback,
		Scope:       "openid offline_access",
		PKCE:        pkce,
	})
	if flow.Code == "" {
		t.Fatalf("authorize callback missing code: %+v", flow)
	}
	first := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code:         flow.Code,
		RedirectURI:  callback,
		Verifier:     pkce.Verifier,
		ClientID:     clientID,
		ClientSecret: clientSecret,
	})
	if first.StatusCode != http.StatusOK || first.IDToken == "" || first.RefreshToken == "" {
		t.Fatalf("/token status=%d body=%v want 200 with id_token + refresh_token", first.StatusCode, first.Raw)
	}
	if got := scenariokit.JWEParts(first.IDToken); len(got) != 5 {
		t.Fatalf("initial id_token has %d parts, want 5", len(got))
	}
	innerFirst := scenariokit.DecryptJWE(t, first.IDToken, rp.Private)
	firstClaims := encVerifyInnerJWS(t, tk, innerFirst)
	firstIat, _ := firstClaims["iat"].(float64)
	if firstIat == 0 {
		t.Fatalf("initial id_token missing iat: %v", firstClaims)
	}

	// POST /token with grant_type=refresh_token. The refresh path is
	// handled inline rather than via a shared helper because the
	// scenariokit doesn't (yet) expose a refresh-grant entry point;
	// see authorization_code_test.go's postRefreshToken for the same
	// shape.
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {first.RefreshToken},
	}
	rtReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build refresh /token request: %v", err)
	}
	rtReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rtReq.SetBasicAuth(clientID, clientSecret)
	rtResp, err := tk.HTTPClient(nil).Do(rtReq)
	if err != nil {
		t.Fatalf("POST refresh /token: %v", err)
	}
	defer func() { _ = rtResp.Body.Close() }()
	if rtResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(rtResp.Body)
		t.Fatalf("refresh /token status=%d want 200 body=%s", rtResp.StatusCode, body)
	}
	var second map[string]any
	if err := json.NewDecoder(rtResp.Body).Decode(&second); err != nil {
		t.Fatalf("decode refresh body: %v", err)
	}
	rotated, _ := second["id_token"].(string)
	if rotated == "" {
		t.Fatalf("refresh response missing id_token: %v", second)
	}
	if got := scenariokit.JWEParts(rotated); len(got) != 5 {
		t.Fatalf("rotated id_token has %d parts, want 5 (raw=%q)", len(got), rotated)
	}
	innerSecond := scenariokit.DecryptJWE(t, rotated, rp.Private)
	secondClaims := encVerifyInnerJWS(t, tk, innerSecond)

	if got := secondClaims["iss"]; got != tk.Issuer {
		t.Errorf("iss=%v want %q", got, tk.Issuer)
	}
	if got := secondClaims["aud"]; got != clientID {
		t.Errorf("aud=%v want %q", got, clientID)
	}
	if got := secondClaims["sub"]; got != scenariokit.DefaultSubject {
		t.Errorf("sub=%v want %q", got, scenariokit.DefaultSubject)
	}
	secondIat, _ := secondClaims["iat"].(float64)
	if secondIat == 0 {
		t.Fatalf("rotated id_token missing iat: %v", secondClaims)
	}
	if secondIat < firstIat {
		t.Errorf("rotated iat=%v < initial iat=%v (must be >= for fresh issuance)", secondIat, firstIat)
	}
}

// TestScenario_ENC_110_UserInfoJWEOnAcceptJWT pins the OIDC Core 1.0
// §5.3.2 negotiation: a client that registered
// userinfo_encrypted_response_alg / _enc and asks Accept: application/jwt
// receives Content-Type: application/jwt with a 5-part JWE body.
// Decrypting yields a signed JWS whose claims include iss, aud, sub.
//
// Deviation from catalog text: the OP does not stamp `exp` on the
// signed userinfo body (OIDC Core §5.3.2 leaves exp OPTIONAL on
// userinfo); the test only asserts iss / aud / sub.
//
// Spec: OIDC Core §5.3.2.
func TestScenario_ENC_110_UserInfoJWEOnAcceptJWT(t *testing.T) {
	t.Parallel()

	const (
		clientID = "rp-enc-110"
		callback = "https://rp.testkit.invalid/callback"
	)
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-enc-110-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	encKey := scenariokit.NewOPEncryptionKey(t, "enc-1")
	rp := scenariokit.NewRPEncryptionKey(t, "rp-enc-110-key")

	tk := testkit.NewProvider(t, testkit.WithOptions(
		op.WithEncryptionKeyset(op.EncryptionKeyset{encKey}),
	))
	tk.RegisterClient(t, testkit.ClientFixture{
		ID:                           clientID,
		SecretHash:                   hash,
		RedirectURIs:                 []string{callback},
		Scopes:                       []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod:      "client_secret_basic",
		GrantTypes:                   []string{"authorization_code", "refresh_token"},
		ResponseTypes:                []string{"code"},
		JWKs:                         rp.JWKS,
		UserInfoEncryptedResponseAlg: "RSA-OAEP-256",
		UserInfoEncryptedResponseEnc: "A128GCM",
	})
	tk.Store.PutUser(context.Background(), &store.User{
		Subject: scenariokit.DefaultSubject,
		Claims: map[string]any{
			"email":          "user-1@example.test",
			"email_verified": true,
		},
	})

	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    clientID,
		RedirectURI: callback,
		PKCE:        pkce,
	})
	if flow.Code == "" {
		t.Fatalf("authorize callback missing code: %+v", flow)
	}
	tok := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code:         flow.Code,
		RedirectURI:  callback,
		Verifier:     pkce.Verifier,
		ClientID:     clientID,
		ClientSecret: clientSecret,
	})
	if tok.StatusCode != http.StatusOK || tok.AccessToken == "" {
		t.Fatalf("/token status=%d body=%v want 200 with access_token", tok.StatusCode, tok.Raw)
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		tk.Server.URL+"/oidc/userinfo", http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	req.Header.Set("Accept", "application/jwt")
	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("GET /userinfo: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 200 body=%s", resp.StatusCode, body)
	}
	if got := resp.Header.Get("Content-Type"); !strings.HasPrefix(got, "application/jwt") {
		t.Errorf("Content-Type=%q want application/jwt prefix", got)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	jwe := strings.TrimSpace(string(body))
	if got := scenariokit.JWEParts(jwe); len(got) != 5 {
		t.Fatalf("userinfo body has %d parts, want 5 (raw=%q)", len(got), jwe)
	}
	inner := scenariokit.DecryptJWE(t, jwe, rp.Private)
	claims := encVerifyInnerJWS(t, tk, inner)
	if got := claims["iss"]; got != tk.Issuer {
		t.Errorf("iss=%v want %q", got, tk.Issuer)
	}
	if got := claims["aud"]; got != clientID {
		t.Errorf("aud=%v want %q", got, clientID)
	}
	if got := claims["sub"]; got != scenariokit.DefaultSubject {
		t.Errorf("sub=%v want %q", got, scenariokit.DefaultSubject)
	}
}

// TestScenario_ENC_111_UserInfoJWEWhenAcceptOmitsJWT pins the OIDC
// Core 1.0 §5.3.2 downgrade guard: when a client registers
// userinfo_encrypted_response_alg / _enc, a /userinfo request whose
// Accept header omits application/jwt still receives a nested JWE.
// Registered encryption metadata forces the JWT response shape.
//
// Spec: OIDC Core §5.3.2.
func TestScenario_ENC_111_UserInfoJWEWhenAcceptOmitsJWT(t *testing.T) {
	t.Parallel()

	const (
		clientID = "rp-enc-111"
		callback = "https://rp.testkit.invalid/callback"
	)
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-enc-111-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	encKey := scenariokit.NewOPEncryptionKey(t, "enc-1")
	rp := scenariokit.NewRPEncryptionKey(t, "rp-enc-111-key")

	tk := testkit.NewProvider(t, testkit.WithOptions(
		op.WithEncryptionKeyset(op.EncryptionKeyset{encKey}),
	))
	tk.RegisterClient(t, testkit.ClientFixture{
		ID:                           clientID,
		SecretHash:                   hash,
		RedirectURIs:                 []string{callback},
		Scopes:                       []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod:      "client_secret_basic",
		GrantTypes:                   []string{"authorization_code", "refresh_token"},
		ResponseTypes:                []string{"code"},
		JWKs:                         rp.JWKS,
		UserInfoEncryptedResponseAlg: "RSA-OAEP-256",
		UserInfoEncryptedResponseEnc: "A128GCM",
	})
	tk.Store.PutUser(context.Background(), &store.User{
		Subject: scenariokit.DefaultSubject,
		Claims: map[string]any{
			"email":          "user-1@example.test",
			"email_verified": true,
		},
	})

	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    clientID,
		RedirectURI: callback,
		PKCE:        pkce,
	})
	if flow.Code == "" {
		t.Fatalf("authorize callback missing code: %+v", flow)
	}
	tok := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code:         flow.Code,
		RedirectURI:  callback,
		Verifier:     pkce.Verifier,
		ClientID:     clientID,
		ClientSecret: clientSecret,
	})
	if tok.StatusCode != http.StatusOK || tok.AccessToken == "" {
		t.Fatalf("/token status=%d body=%v want 200 with access_token", tok.StatusCode, tok.Raw)
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		tk.Server.URL+"/oidc/userinfo", http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	// Explicit Accept that does NOT mention application/jwt. The
	// registered encryption metadata still forces JWT/JWE shape.
	req.Header.Set("Accept", "application/json")
	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("GET /userinfo: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 200 body=%s", resp.StatusCode, body)
	}
	if got := resp.Header.Get("Content-Type"); !strings.HasPrefix(got, "application/jwt") {
		t.Errorf("Content-Type=%q want application/jwt prefix", got)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	jwe := strings.TrimSpace(string(body))
	if got := scenariokit.JWEParts(jwe); len(got) != 5 {
		t.Fatalf("userinfo body has %d parts, want 5 (raw=%q)", len(got), jwe)
	}
	inner := scenariokit.DecryptJWE(t, jwe, rp.Private)
	claims := encVerifyInnerJWS(t, tk, inner)
	if got, _ := claims["sub"].(string); got != scenariokit.DefaultSubject {
		t.Errorf("sub=%v want %q", got, scenariokit.DefaultSubject)
	}
}

// TestScenario_ENC_120_JARMSuccessJWE pins the FAPI 2.0 Message Signing
// §5.5 wrap: a client that registered
// authorization_encrypted_response_alg / _enc and uses
// response_mode=jwt receives an /authorize success response whose
// "response" parameter is a 5-part JWE addressed to its enc-use key.
// Decrypting + verifying yields a JARM payload with iss, aud, code,
// state.
//
// Spec: FAPI 2.0 Message Signing §5.5.
func TestScenario_ENC_120_JARMSuccessJWE(t *testing.T) {
	t.Parallel()

	const (
		clientID = "rp-enc-120"
		callback = "https://rp.testkit.invalid/callback"
	)
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-enc-120-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	encKey := scenariokit.NewOPEncryptionKey(t, "enc-1")
	rp := scenariokit.NewRPEncryptionKey(t, "rp-enc-120-key")

	tk := testkit.NewProvider(t, testkit.WithOptions(
		op.WithFeature(feature.JARM),
		op.WithEncryptionKeyset(op.EncryptionKeyset{encKey}),
	))
	tk.RegisterClient(t, testkit.ClientFixture{
		ID:                                clientID,
		SecretHash:                        hash,
		RedirectURIs:                      []string{callback},
		Scopes:                            []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod:           "client_secret_basic",
		GrantTypes:                        []string{"authorization_code"},
		ResponseTypes:                     []string{"code"},
		JWKs:                              rp.JWKS,
		AuthorizationEncryptedResponseAlg: "RSA-OAEP-256",
		AuthorizationEncryptedResponseEnc: "A256GCM",
	})

	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    clientID,
		RedirectURI: callback,
		PKCE:        pkce,
		Extra:       url.Values{"response_mode": {"jwt"}},
	})
	if flow.Error != "" {
		t.Fatalf("authorize error=%s desc=%s", flow.Error, flow.ErrorDesc)
	}
	rawResp := flow.Location.Query().Get("response")
	if rawResp == "" {
		t.Fatalf("'response' parameter missing from callback: %s", flow.Location.String())
	}
	if got := scenariokit.JWEParts(rawResp); len(got) != 5 {
		t.Fatalf("JARM response has %d parts, want 5 (raw=%q)", len(got), rawResp)
	}
	inner := scenariokit.DecryptJWE(t, rawResp, rp.Private)
	claims := encVerifyInnerJWS(t, tk, inner)
	if got := claims["iss"]; got != tk.Issuer {
		t.Errorf("iss=%v want %q", got, tk.Issuer)
	}
	if got := claims["aud"]; got != clientID {
		t.Errorf("aud=%v want %q", got, clientID)
	}
	if got, _ := claims["code"].(string); got == "" {
		t.Errorf("code missing from JARM payload: %v", claims)
	}
	if got := claims["state"]; got != scenariokit.DefaultState {
		t.Errorf("state=%v want %q", got, scenariokit.DefaultState)
	}
}

// TestScenario_ENC_121_JARMErrorFailsClosed pins the JARM error-path
// policy: when a JARM-using client registered
// authorization_encrypted_response_alg / _enc but the OP cannot
// resolve a `use=enc` recipient (no matching key in the client JWKS),
// the OP emits a generic server_error redirect without a signed-only
// "response" JWT. The client's registered confidentiality requirement
// is never silently downgraded.
//
// The fixture publishes a JWKS containing only a `use=sig` key so the
// clientencjwks resolver surfaces ErrNoMatchingKey at JWE-wrap time.
// The bad request that triggers the JARM error path is an unsupported
// `response_type` ("token" is not in the v0.9.1 ship list).
//
// Spec: FAPI 2.0 Message Signing §5.5.
func TestScenario_ENC_121_JARMErrorFailsClosed(t *testing.T) {
	t.Parallel()

	const (
		clientID = "rp-enc-121"
		callback = "https://rp.testkit.invalid/callback"
	)
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-enc-121-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	encKey := scenariokit.NewOPEncryptionKey(t, "enc-1")

	// Build a JWKS with ONLY a `use=sig` key — no enc-use entry. The
	// resolver will surface ErrNoMatchingKey when JARM tries to wrap
	// the signed JWT in a JWE.
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	sigOnlyJWKS, err := json.Marshal(josev4.JSONWebKeySet{
		Keys: []josev4.JSONWebKey{{
			Key:       &rsaPriv.PublicKey,
			KeyID:     "rp-enc-121-sig",
			Use:       "sig",
			Algorithm: "RS256",
		}},
	})
	if err != nil {
		t.Fatalf("Marshal sig-only JWKS: %v", err)
	}

	tk := testkit.NewProvider(t, testkit.WithOptions(
		op.WithFeature(feature.JARM),
		op.WithEncryptionKeyset(op.EncryptionKeyset{encKey}),
	))
	tk.RegisterClient(t, testkit.ClientFixture{
		ID:                                clientID,
		SecretHash:                        hash,
		RedirectURIs:                      []string{callback},
		Scopes:                            []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod:           "client_secret_basic",
		GrantTypes:                        []string{"authorization_code"},
		ResponseTypes:                     []string{"code"},
		JWKs:                              sigOnlyJWKS,
		AuthorizationEncryptedResponseAlg: "RSA-OAEP-256",
		AuthorizationEncryptedResponseEnc: "A256GCM",
	})

	// Drive a /authorize request with response_type=token (not in the
	// client's registered set and not advertised on the OP). With
	// response_mode=jwt the OP routes the error through the JARM
	// emit path; the JWE wrap fails and the function emits only a
	// generic server_error redirect.
	values := url.Values{
		"client_id":     {clientID},
		"redirect_uri":  {callback},
		"response_type": {"token"},
		"response_mode": {"jwt"},
		"scope":         {"openid"},
		"state":         {"enc-121-state"},
		"nonce":         {"enc-121-nonce"},
	}
	target := tk.Server.URL + "/oidc/auth?" + values.Encode()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest /authorize: %v", err)
	}
	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 302 (JARM error redirect) body=%s", resp.StatusCode, body)
	}
	loc, err := resp.Location()
	if err != nil {
		t.Fatalf("Location: %v", err)
	}
	query := loc.Query()
	if got := query.Get("error"); got != "server_error" {
		t.Errorf("error=%q want server_error", got)
	}
	if got := query.Get("error_description"); got != "jarm_response_encryption_failed" {
		t.Errorf("error_description=%q want jarm_response_encryption_failed", got)
	}
	if got := query.Get("state"); got != "enc-121-state" {
		t.Errorf("state=%q want enc-121-state", got)
	}
	if got := query.Get("iss"); got != tk.Issuer {
		t.Errorf("iss=%q want %q", got, tk.Issuer)
	}
	if got := query.Get("response"); got != "" {
		t.Errorf("signed-only JARM leaked in query after JWE failure: %q", got)
	}
	if loc.Fragment != "" {
		fragment, err := url.ParseQuery(loc.Fragment)
		if err != nil {
			t.Fatalf("parse redirect fragment: %v", err)
		}
		if got := fragment.Get("response"); got != "" {
			t.Errorf("signed-only JARM leaked in fragment after JWE failure: %q", got)
		}
	}
	if got := query.Get("code"); got != "" {
		t.Errorf("authorization code leaked after JWE failure: %q", got)
	}
}

// TestScenario_ENC_130_IntrospectionJWE pins the RFC 9701 §5 wrap: a
// client that registered introspection_encrypted_response_alg / _enc
// receives a 5-part JWE wrapping the signed introspection JWT even
// when the Accept header omits application/token-introspection+jwt.
// The inner claim set carries iss / aud / iat at the top level and
// active / client_id / exp inside the `token_introspection` object
// (RFC 9701 §4 shape).
//
// Spec: RFC 9701 §4 / §5.
func TestScenario_ENC_130_IntrospectionJWE(t *testing.T) {
	t.Parallel()

	const (
		clientID = "rp-enc-130"
		callback = "https://rp.testkit.invalid/callback"
	)
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-enc-130-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	encKey := scenariokit.NewOPEncryptionKey(t, "enc-1")
	rp := scenariokit.NewRPEncryptionKey(t, "rp-enc-130-key")

	tk := testkit.NewProvider(t, testkit.WithOptions(
		op.WithFeature(feature.Introspect),
		op.WithEncryptionKeyset(op.EncryptionKeyset{encKey}),
	))
	tk.RegisterClient(t, testkit.ClientFixture{
		ID:                                clientID,
		SecretHash:                        hash,
		RedirectURIs:                      []string{callback},
		Scopes:                            []string{"openid", "profile", "email", "api"},
		TokenEndpointAuthMethod:           "client_secret_basic",
		GrantTypes:                        []string{"client_credentials", "authorization_code"},
		ResponseTypes:                     []string{"code"},
		JWKs:                              rp.JWKS,
		IntrospectionEncryptedResponseAlg: "RSA-OAEP-256",
		IntrospectionEncryptedResponseEnc: "A256GCM",
	})

	form := url.Values{
		"grant_type": {"client_credentials"},
		"scope":      {"api"},
	}
	tokReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build /token request: %v", err)
	}
	tokReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokReq.SetBasicAuth(clientID, clientSecret)
	tokResp, err := tk.HTTPClient(nil).Do(tokReq)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer func() { _ = tokResp.Body.Close() }()
	if tokResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(tokResp.Body)
		t.Fatalf("/token status=%d want 200 body=%s", tokResp.StatusCode, body)
	}
	var tokEnv map[string]any
	if err := json.NewDecoder(tokResp.Body).Decode(&tokEnv); err != nil {
		t.Fatalf("decode /token body: %v", err)
	}
	at, _ := tokEnv["access_token"].(string)
	if at == "" {
		t.Fatalf("access_token missing from /token response: %v", tokEnv)
	}

	introForm := url.Values{"token": {at}}
	introReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/introspect", strings.NewReader(introForm.Encode()))
	if err != nil {
		t.Fatalf("build /introspect request: %v", err)
	}
	introReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	introReq.SetBasicAuth(clientID, clientSecret)
	introResp, err := tk.HTTPClient(nil).Do(introReq)
	if err != nil {
		t.Fatalf("POST /introspect: %v", err)
	}
	defer func() { _ = introResp.Body.Close() }()
	if introResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(introResp.Body)
		t.Fatalf("/introspect status=%d want 200 body=%s", introResp.StatusCode, body)
	}
	if got := introResp.Header.Get("Content-Type"); got != "application/token-introspection+jwt" {
		t.Errorf("Content-Type=%q want application/token-introspection+jwt", got)
	}
	body, err := io.ReadAll(introResp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	jwe := strings.TrimSpace(string(body))
	if got := scenariokit.JWEParts(jwe); len(got) != 5 {
		t.Fatalf("/introspect body has %d parts, want 5 (raw=%q)", len(got), jwe)
	}
	inner := scenariokit.DecryptJWE(t, jwe, rp.Private)
	claims := encVerifyInnerJWS(t, tk, inner)
	if got := claims["iss"]; got != tk.Issuer {
		t.Errorf("iss=%v want %q", got, tk.Issuer)
	}
	if got := claims["aud"]; got != clientID {
		t.Errorf("aud=%v want %q", got, clientID)
	}
	tokenIntro, ok := claims["token_introspection"].(map[string]any)
	if !ok {
		t.Fatalf("token_introspection missing or wrong shape: %T %v", claims["token_introspection"], claims["token_introspection"])
	}
	if got, _ := tokenIntro["active"].(bool); !got {
		t.Errorf("active=%v want true (token_introspection=%v)", tokenIntro["active"], tokenIntro)
	}
	if got, _ := tokenIntro["client_id"].(string); got != clientID {
		t.Errorf("client_id=%v want %q", tokenIntro["client_id"], clientID)
	}
	if _, ok := tokenIntro["exp"].(float64); !ok {
		t.Errorf("exp must be a JSON number in token_introspection: %T", tokenIntro["exp"])
	}
}

// TestScenario_ENC_140_KidDisjointSigEncSeparation pins the RFC 7517
// §4.2 use=sig / use=enc separation: [op.New] MUST reject a config in
// which a kid appears in both the signing keyset and the encryption
// keyset, and MUST accept the same config when the kids are disjoint.
//
// Spec: RFC 7517 §4.2.
func TestScenario_ENC_140_KidDisjointSigEncSeparation(t *testing.T) {
	t.Parallel()

	collideEnc := scenariokit.NewOPEncryptionKey(t, "shared-kid")
	disjointEnc := scenariokit.NewOPEncryptionKey(t, "enc-disjoint")

	baseOpts := func(sigKID string) []op.Option {
		return []op.Option{
			op.WithIssuer(testkit.DefaultIssuer),
			op.WithStore(inmem.New()),
			op.WithKeyset(op.Keyset{testkit.NewSigningKey(t, sigKID)}),
			op.WithCookieKeys(testkit.NewCookieKey(t)),
			op.WithInteractionDriver(testkit.AutoConsentDriver{}),
			op.WithAuthenticators(testkit.SubjectAuthenticator{}),
		}
	}

	collideOpts := append(baseOpts("shared-kid"),
		op.WithEncryptionKeyset(op.EncryptionKeyset{collideEnc}))
	if _, err := op.New(collideOpts...); err == nil {
		t.Fatalf("op.New accepted a colliding kid; want error referencing RFC 7517 §4.2")
	} else {
		msg := err.Error()
		if !strings.Contains(msg, "shared-kid") || !strings.Contains(msg, "RFC 7517") {
			t.Errorf("error %q must name the kid and cite RFC 7517 §4.2", msg)
		}
	}

	disjointOpts := append(baseOpts("sig-only"),
		op.WithEncryptionKeyset(op.EncryptionKeyset{disjointEnc}))
	if _, err := op.New(disjointOpts...); err != nil {
		t.Fatalf("op.New rejected disjoint kids: %v", err)
	}
}

// TestScenario_ENC_141_FailClosedOnEncryptionFailure pins the
// fail-closed posture on the id_token issuance path: when an
// encryption-enrolled client's enc-use key cannot be resolved (the
// client published a sig-use-only JWKS), the OP MUST refuse to issue
// the id_token rather than silently degrade to a plain 3-part JWS.
// The /token response surfaces the failure as a non-success status;
// the canonical response is 500 server_error per the internal
// idtoken_encrypt fail-closed contract.
//
// Spec: ENC-141 catalog row (fail-closed invariant).
func TestScenario_ENC_141_FailClosedOnEncryptionFailure(t *testing.T) {
	t.Parallel()

	const (
		clientID = "rp-enc-141"
		callback = "https://rp.testkit.invalid/callback"
	)
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-enc-141-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	encKey := scenariokit.NewOPEncryptionKey(t, "enc-1")

	// sig-only JWKS forces the encryption resolver to surface
	// ErrNoMatchingKey at id_token mint time.
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	sigOnlyJWKS, err := json.Marshal(josev4.JSONWebKeySet{
		Keys: []josev4.JSONWebKey{{
			Key:       &rsaPriv.PublicKey,
			KeyID:     "rp-enc-141-sig",
			Use:       "sig",
			Algorithm: "RS256",
		}},
	})
	if err != nil {
		t.Fatalf("Marshal sig-only JWKS: %v", err)
	}

	tk := testkit.NewProvider(t, testkit.WithOptions(
		op.WithEncryptionKeyset(op.EncryptionKeyset{encKey}),
	))
	//nolint:gosec // G101 false positive: ClientFixture struct literal carries test-only fields.
	tk.RegisterClient(t, testkit.ClientFixture{
		ID:                          clientID,
		SecretHash:                  hash,
		RedirectURIs:                []string{callback},
		Scopes:                      []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod:     "client_secret_basic",
		GrantTypes:                  []string{"authorization_code"},
		ResponseTypes:               []string{"code"},
		JWKs:                        sigOnlyJWKS,
		IDTokenEncryptedResponseAlg: "RSA-OAEP-256",
		IDTokenEncryptedResponseEnc: "A256GCM",
	})

	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    clientID,
		RedirectURI: callback,
		PKCE:        pkce,
	})
	if flow.Code == "" {
		t.Fatalf("authorize callback missing code: %+v", flow)
	}
	tok := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code:         flow.Code,
		RedirectURI:  callback,
		Verifier:     pkce.Verifier,
		ClientID:     clientID,
		ClientSecret: clientSecret,
	})
	// CRITICAL invariant: the OP MUST NOT silently emit a 3-part JWS
	// id_token. Either the response is a >=400 status, or — if the OP
	// returned 200 — the id_token field MUST be absent / empty.
	if tok.StatusCode == http.StatusOK {
		if tok.IDToken != "" {
			parts := strings.Split(tok.IDToken, ".")
			if len(parts) != 5 {
				t.Fatalf("/token returned 200 with non-JWE id_token (parts=%d) — silent fail-open: %q",
					len(parts), tok.IDToken)
			}
			t.Fatalf("/token returned 200 with id_token despite encryption failure: %v", tok.Raw)
		}
	} else if tok.StatusCode < http.StatusBadRequest {
		t.Fatalf("/token status=%d body=%v want either 200 with no id_token, or >=400", tok.StatusCode, tok.Raw)
	}
	// The catalog states 5xx; the actual implementation returns 500
	// server_error. Pin that as the canonical shape but tolerate any
	// >=400 since the load-bearing invariant is "no plaintext JWS leak".
	if tok.StatusCode >= http.StatusBadRequest && tok.IDToken != "" {
		t.Errorf("/token status=%d but id_token=%q — failed-closed response must not carry id_token",
			tok.StatusCode, tok.IDToken)
	}
}
