package scenarios_test

// Catalog: test/scenarios/catalog/token_formats_jwt.yaml (TFJ-NNN)
// Spec:
//   - RFC 9068 — JWT Profile for OAuth 2.0 Access Tokens
//   - RFC 7515 / 7516 / 7517 / 7518 / 7519 — JOSE
//   - RFC 8725 — JWT Best Current Practices
//   - OIDC Core 1.0 §10
//   - RFC 8705 — `cnf.x5t#S256`
//   - RFC 9449 — `cnf.jkt`

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/testkit"
	"github.com/libraz/go-oidc-provider/test/scenarios/internal/scenariokit"
)

// decodeTFJJWTSegments splits a JWS Compact Serialisation into its
// header and payload maps. The signature segment is left untouched
// because the scenario suite asserts on the wire envelope rather than
// re-verifying the signature (the OP's keyset is exercised by the
// jwks_test.go suite).
func decodeTFJJWTSegments(t *testing.T, raw string) (header, payload map[string]any) {
	t.Helper()
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatalf("jwt has %d parts, want 3 (Compact Serialisation)", len(parts))
	}
	hraw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	if err := json.Unmarshal(hraw, &header); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}
	praw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if err := json.Unmarshal(praw, &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	return header, payload
}

// runTFJCodeFlowJWT registers a confidential client wired for the
// JWT-AT default and drives a happy-path /authorize → /token round
// trip, returning the access token. Used by TFJ-027 and TFJ-028.
func runTFJCodeFlowJWT(t *testing.T, clientID, callback, secret string) (*testkit.Provider, scenariokit.TokenResponse) {
	t.Helper()
	hash, err := op.HashClientSecret(secret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	tk := testkit.NewProvider(t, testkit.WithOptions(
		op.WithAccessTokenFormat(op.AccessTokenFormatJWT),
	))
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		RedirectURIs:            []string{callback},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})
	tk.Store.PutUser(context.Background(), &store.User{Subject: scenariokit.DefaultSubject})

	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    rp.ID,
		RedirectURI: callback,
		Scope:       "openid profile",
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
		ClientSecret: secret,
	})
	if tok.StatusCode != http.StatusOK {
		t.Fatalf("/token status=%d body=%v", tok.StatusCode, tok.Raw)
	}
	if tok.AccessToken == "" {
		t.Fatalf("access_token missing on /token success: %v", tok.Raw)
	}
	return tk, tok
}

func TestScenario_TFJ_001_ResourceServerSignAlgPinned(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: TFJ-001")
}

func TestScenario_TFJ_002_DefaultsWhenJWTBlockOmitted(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: TFJ-002")
}

func TestScenario_TFJ_003_DefaultsWhenJWTBlockEmpty(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: TFJ-003")
}

func TestScenario_TFJ_004_HMACSignWithRawSecret(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: TFJ-004")
}

func TestScenario_TFJ_005_HMACSignWithCryptoKey(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: TFJ-005")
}

func TestScenario_TFJ_006_HMACSignWithKeyObject(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: TFJ-006")
}

func TestScenario_TFJ_007_SignKidMustBeString(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: TFJ-007")
}

func TestScenario_TFJ_008_EncryptKidMustBeString(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: TFJ-008")
}

func TestScenario_TFJ_009_HMACSignEmitsConfiguredKid(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: TFJ-009")
}

func TestScenario_TFJ_010_PureEncryptedJWTEnvelope(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: TFJ-010")
}

func TestScenario_TFJ_011_PureEncryptedJWTWithKeyObject(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: TFJ-011")
}

func TestScenario_TFJ_012_PureEncryptedJWTWithCryptoKey(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: TFJ-012")
}

func TestScenario_TFJ_013_PureEncryptedJWTEmitsConfiguredKid(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: TFJ-013")
}

func TestScenario_TFJ_014_NestedJWTExplicitSignAndEncrypt(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: TFJ-014")
}

func TestScenario_TFJ_015_NestedJWTEmitsConfiguredKid(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: TFJ-015")
}

func TestScenario_TFJ_016_NestedJWTImplicitSignAlg(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: TFJ-016")
}

func TestScenario_TFJ_017_AlgNoneRejectedAtSave(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: TFJ-017")
}

func TestScenario_TFJ_018_HMACMissingKeyRejected(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: TFJ-018")
}

func TestScenario_TFJ_019_HMACWithAsymmetricPublicKeyRejected(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: TFJ-019")
}

func TestScenario_TFJ_020_HMACWithAsymmetricPrivateKeyRejected(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: TFJ-020")
}

func TestScenario_TFJ_021_AsymmetricSignNoMatchingKeystoreKey(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: TFJ-021")
}

func TestScenario_TFJ_022_EncryptKeyMustNotBePrivate(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: TFJ-022")
}

func TestScenario_TFJ_023_AsymmetricEncryptRequiresSign(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: TFJ-023")
}

func TestScenario_TFJ_024_EncryptMissingAlgRejected(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: TFJ-024")
}

func TestScenario_TFJ_025_EncryptMissingEncRejected(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: TFJ-025")
}

func TestScenario_TFJ_026_EncryptMissingKeyRejected(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: TFJ-026")
}

// TestScenario_TFJ_027_JWTAccessTokenNotPersisted verifies RFC 9068 §1's
// self-contained property: the JWT-formatted access token is never
// persisted server-side. The wire-level evidence is that the OP's
// opaque-access-token substore — the only persistence path the public
// store surface exposes for access tokens — has no row keyed by the
// JWT bytes after issuance. A JWT that survives a happy-path /token
// exchange MUST be reconstructable purely from its claims; the OP
// MUST NOT shadow it in the opaque table.
//
// Spec: RFC 9068 §1.
func TestScenario_TFJ_027_JWTAccessTokenNotPersisted(t *testing.T) {
	t.Parallel()

	const (
		clientID = "rp-tfj-027"
		callback = "https://rp.testkit.invalid/callback"
	)
	//nolint:gosec // G101: test fixture, not a real credential.
	const clientSecret = "rp-tfj-027-secret"

	tk, tok := runTFJCodeFlowJWT(t, clientID, callback, clientSecret)

	// Sanity: the issued AT is a JWS (three dot-separated segments).
	if got := strings.Count(tok.AccessToken, "."); got != 2 {
		t.Fatalf("access_token dot count=%d want 2 (JWS Compact Serialisation): %q", got, tok.AccessToken)
	}

	// The JWT MUST NOT have been shadowed in the opaque store. The
	// opaque substore is the only access-token persistence surface
	// the public Store contract exposes; a JWT-formatted AT keyed by
	// its wire bytes (or its jti) in that table would be a regression
	// against the §1 invariant. testkit.Provider always wires an
	// inmem.Store whose OpaqueAccessTokens substore is non-nil.
	opaque := tk.Store.OpaqueAccessTokens()
	if opaque == nil {
		t.Fatal("inmem store unexpectedly returned nil OpaqueAccessTokens substore")
	}
	if rec, err := opaque.Find(context.Background(), tok.AccessToken); err == nil {
		t.Errorf("JWT AT unexpectedly found in OpaqueAccessTokens by raw bytes: %+v", rec)
	} else if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Find(JWT bytes) err=%v want ErrNotFound", err)
	}

	// Decode the JWT to extract the jti and assert the substore has
	// no row keyed by that either. (The OP would never key on jti,
	// but the assertion guards against a future regression that
	// shadowed JWTs by claim id.)
	_, payload := decodeTFJJWTSegments(t, tok.AccessToken)
	jti, _ := payload["jti"].(string)
	if jti == "" {
		t.Fatalf("JWT AT payload missing jti: %v", payload)
	}
	if rec, err := opaque.Find(context.Background(), jti); err == nil {
		t.Errorf("JWT AT unexpectedly found in OpaqueAccessTokens by jti=%q: %+v", jti, rec)
	} else if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Find(jti) err=%v want ErrNotFound", err)
	}
}

// TestScenario_TFJ_028_AccessTokenJWTPayloadShape pins the RFC 9068 §2
// envelope shape for a bearer JWT access token. The header MUST carry
// typ=at+jwt, alg=ES256, and a kid pointing at the active signing
// key. The payload MUST carry iss, sub, client_id, aud, scope, jti,
// iat, and exp. The cnf claim MUST be absent on the bearer default —
// it appears only when the token is sender-constrained (RFC 8705
// x5t#S256 or RFC 9449 jkt).
//
// Spec: RFC 9068 §2 / §2.1 / §2.2.
func TestScenario_TFJ_028_AccessTokenJWTPayloadShape(t *testing.T) {
	t.Parallel()

	const (
		clientID = "rp-tfj-028"
		callback = "https://rp.testkit.invalid/callback"
	)
	//nolint:gosec // G101: test fixture, not a real credential.
	const clientSecret = "rp-tfj-028-secret"

	tk, tok := runTFJCodeFlowJWT(t, clientID, callback, clientSecret)
	header, payload := decodeTFJJWTSegments(t, tok.AccessToken)

	// Header.
	if got := header["typ"]; got != "at+jwt" {
		t.Errorf("header typ=%v want \"at+jwt\" (RFC 9068 §2.1)", got)
	}
	if got := header["alg"]; got != "ES256" {
		t.Errorf("header alg=%v want \"ES256\" (project pins ES256 as sole issuance alg)", got)
	}
	if kid, _ := header["kid"].(string); kid == "" {
		t.Errorf("header kid missing; RFC 9068 §2.1 requires the verifier to select the key by kid")
	}

	// Payload — required claims.
	if got := payload["iss"]; got != tk.Issuer {
		t.Errorf("payload iss=%v want %q (issuer URL)", got, tk.Issuer)
	}
	if got := payload["sub"]; got != scenariokit.DefaultSubject {
		t.Errorf("payload sub=%v want %q (the authenticated end-user)", got, scenariokit.DefaultSubject)
	}
	if got := payload["client_id"]; got != clientID {
		t.Errorf("payload client_id=%v want %q", got, clientID)
	}
	if jti, _ := payload["jti"].(string); jti == "" {
		t.Error("payload jti missing; RFC 9068 §2.2 requires a unique identifier")
	}
	if _, ok := payload["iat"].(float64); !ok {
		t.Errorf("payload iat=%v (%T) want a numeric Unix timestamp", payload["iat"], payload["iat"])
	}
	if _, ok := payload["exp"].(float64); !ok {
		t.Errorf("payload exp=%v (%T) want a numeric Unix timestamp", payload["exp"], payload["exp"])
	}
	// "aud" may be a string or array per RFC 7519 §4.1.3; tolerate
	// both shapes and assert presence.
	switch aud := payload["aud"].(type) {
	case string:
		if aud == "" {
			t.Error("payload aud is empty string; want a resource identifier or the issuer audience")
		}
	case []any:
		if len(aud) == 0 {
			t.Error("payload aud is empty array; want at least one entry")
		}
	default:
		t.Errorf("payload aud=%v (%T) want string or []any", payload["aud"], payload["aud"])
	}
	// "scope" is a space-delimited string per RFC 6749 §3.3 (RFC
	// 9068 §2.2.3 inherits the encoding).
	scope, _ := payload["scope"].(string)
	if scope == "" {
		t.Error("payload scope missing; RFC 9068 §2.2.3 requires the granted scope")
	} else if !strings.Contains(scope, "openid") {
		t.Errorf("payload scope=%q must include \"openid\" (granted to this RP)", scope)
	}

	// cnf MUST be absent for a bearer token — sender-constraint is
	// covered by the dpop / mtls catalogs.
	if _, present := payload["cnf"]; present {
		t.Errorf("payload cnf=%v unexpectedly present on bearer token; cnf is reserved for DPoP / mTLS sender-constrained tokens", payload["cnf"])
	}
}

func TestScenario_TFJ_029_PairwiseAccessTokenJWTPayloadShape(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: TFJ-029")
}

// TestScenario_TFJ_030_ClientCredentialsJWTPayloadShape pins the RFC
// 9068 §2.2 envelope shape for a JWT access token issued via the
// client_credentials grant. The token has no end-user identity, so
// the payload MUST set sub=client_id and MUST NOT carry an
// auth-time / acr / amr block. The header retains typ=at+jwt /
// alg=ES256 / kid as in the user-bound flow. cnf MUST be absent on
// the bearer default; it appears only when the token is sender-
// constrained.
//
// Spec: RFC 9068 §2.2.
func TestScenario_TFJ_030_ClientCredentialsJWTPayloadShape(t *testing.T) {
	t.Parallel()

	const (
		clientID = "rp-tfj-030"
		resource = "https://api.tfj-030.example/"
	)
	//nolint:gosec // G101: test fixture, not a real credential.
	const clientSecret = "rp-tfj-030-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	tk := testkit.NewProvider(t, testkit.WithOptions(
		op.WithAccessTokenFormat(op.AccessTokenFormatJWT),
	))
	tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		Scopes:                  []string{"read"},
		Resources:               []string{resource},
		GrantTypes:              []string{"client_credentials"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})

	form := url.Values{
		"grant_type": {"client_credentials"},
		"scope":      {"read"},
		"resource":   {resource},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build /token request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, clientSecret)

	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("/token status=%d want 200 body=%s", resp.StatusCode, raw)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode /token body: %v", err)
	}
	at, _ := body["access_token"].(string)
	if at == "" {
		t.Fatalf("access_token missing on /token success: %v", body)
	}
	if got := strings.Count(at, "."); got != 2 {
		t.Fatalf("access_token dot count=%d want 2 (JWS Compact Serialisation): %q", got, at)
	}

	header, payload := decodeTFJJWTSegments(t, at)

	// Header — same shape as the user-bound JWT AT.
	if got := header["typ"]; got != "at+jwt" {
		t.Errorf("header typ=%v want \"at+jwt\"", got)
	}
	if got := header["alg"]; got != "ES256" {
		t.Errorf("header alg=%v want \"ES256\"", got)
	}
	if kid, _ := header["kid"].(string); kid == "" {
		t.Errorf("header kid missing")
	}

	// Payload — sub MUST equal client_id (no end-user identity).
	if got := payload["sub"]; got != clientID {
		t.Errorf("payload sub=%v want %q (RFC 9068 §2.2: sub MUST equal client_id on the cc grant)", got, clientID)
	}
	if got := payload["client_id"]; got != clientID {
		t.Errorf("payload client_id=%v want %q", got, clientID)
	}
	if got := payload["iss"]; got != tk.Issuer {
		t.Errorf("payload iss=%v want %q", got, tk.Issuer)
	}
	if jti, _ := payload["jti"].(string); jti == "" {
		t.Error("payload jti missing; RFC 9068 §2.2 requires a unique identifier")
	}
	if _, ok := payload["iat"].(float64); !ok {
		t.Errorf("payload iat=%v (%T) want a numeric Unix timestamp", payload["iat"], payload["iat"])
	}
	if _, ok := payload["exp"].(float64); !ok {
		t.Errorf("payload exp=%v (%T) want a numeric Unix timestamp", payload["exp"], payload["exp"])
	}
	switch aud := payload["aud"].(type) {
	case string:
		if aud != resource {
			t.Errorf("payload aud=%q want %q (RFC 8707 §3 binds the resource indicator)", aud, resource)
		}
	case []any:
		found := false
		for _, v := range aud {
			if s, _ := v.(string); s == resource {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("payload aud=%v missing resource %q", aud, resource)
		}
	default:
		t.Errorf("payload aud=%v (%T) want string or []any", payload["aud"], payload["aud"])
	}
	if scope, _ := payload["scope"].(string); scope != "read" {
		t.Errorf("payload scope=%q want \"read\"", scope)
	}

	// No end-user attributes on the cc grant.
	for _, key := range []string{"auth_time", "acr", "amr", "nonce"} {
		if _, present := payload[key]; present {
			t.Errorf("payload[%q]=%v unexpectedly present on client_credentials JWT AT", key, payload[key])
		}
	}

	// cnf MUST be absent on the bearer default.
	if _, present := payload["cnf"]; present {
		t.Errorf("payload cnf=%v unexpectedly present on bearer client_credentials token", payload["cnf"])
	}
}

func TestScenario_TFJ_031_AccessTokenIssuedAuditEmits(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: TFJ-031")
}

func TestScenario_TFJ_032_ClientCredentialsIssuedAuditEmits(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: TFJ-032")
}

func TestScenario_TFJ_033_JWTCustomizerHookRewritesEnvelope(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: TFJ-033")
}
