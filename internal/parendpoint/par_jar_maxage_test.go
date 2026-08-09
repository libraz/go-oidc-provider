package parendpoint_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/profile"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

const (
	fapiPARClientID = "rp-par-fapi"
	fapiPARKeyID    = "rp-par-fapi-kid"
	fapiPARRedirect = "https://rp.testkit.invalid/callback"

	// requestObjectTyp is the RFC 9101 §10.8 media type for a signed
	// authorization request.
	requestObjectTyp = "oauth-authz-req+jwt"

	// assertionType is the RFC 7523 §2.2 client_assertion_type value.
	assertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
)

// fapiPARFixture is a FAPI 2.0 Baseline provider with a private_key_jwt
// client, which is the only client-authentication method the profile
// admits that this OP implements. The same ES256 key signs both the
// client_assertion and the request object, mirroring how an RP is
// normally provisioned.
type fapiPARFixture struct {
	prov     *testkit.Provider
	endpoint string
	clock    fixedClock
	priv     *ecdsa.PrivateKey
}

func newFAPIPARFixture(tb testing.TB) *fapiPARFixture {
	tb.Helper()
	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	// PAR and JAR are auto-enabled by the profile; DPoP satisfies the
	// FAPI 2.0 §3.1.4 sender-constrained-token requirement without
	// needing a TLS terminator in the test.
	prov := testkit.NewProvider(tb,
		testkit.WithClock(clock),
		testkit.WithOptions(
			op.WithProfile(profile.FAPI2Baseline),
			op.WithFeature(feature.DPoP),
		),
	)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("GenerateKey: %v", err)
	}
	jwks, err := json.Marshal(josev4.JSONWebKeySet{Keys: []josev4.JSONWebKey{{
		Key:       &priv.PublicKey,
		KeyID:     fapiPARKeyID,
		Algorithm: string(josev4.ES256),
		Use:       "sig",
	}}})
	if err != nil {
		tb.Fatalf("Marshal JWKS: %v", err)
	}
	//nolint:gosec // G101: "private_key_jwt" is the RFC 7591 auth-method name, not a secret.
	prov.RegisterClient(tb, testkit.ClientFixture{
		ID:                      fapiPARClientID,
		RedirectURIs:            []string{fapiPARRedirect},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "private_key_jwt",
		JWKs:                    jwks,
	})
	return &fapiPARFixture{
		prov:     prov,
		endpoint: prov.Server.URL + "/oidc/par",
		clock:    clock,
		priv:     priv,
	}
}

// sign serialises claims as a compact ES256 JWS carrying the supplied
// "typ" header.
func (f *fapiPARFixture) sign(tb testing.TB, typ string, claims map[string]any) string {
	tb.Helper()
	signer, err := josev4.NewSigner(
		josev4.SigningKey{
			Algorithm: josev4.ES256,
			Key: josev4.JSONWebKey{
				Key:       f.priv,
				KeyID:     fapiPARKeyID,
				Algorithm: string(josev4.ES256),
				Use:       "sig",
			},
		},
		(&josev4.SignerOptions{}).WithType(josev4.ContentType(typ)),
	)
	if err != nil {
		tb.Fatalf("NewSigner: %v", err)
	}
	out, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		tb.Fatalf("Serialize: %v", err)
	}
	return out
}

// clientAssertion mints a fresh private_key_jwt assertion. The audience
// is the OP issuer, which the assertion verifier accepts alongside the
// canonical token-endpoint URL.
func (f *fapiPARFixture) clientAssertion(tb testing.TB) string {
	tb.Helper()
	now := f.clock.now
	return f.sign(tb, "JWT", map[string]any{
		"iss": fapiPARClientID,
		"sub": fapiPARClientID,
		"aud": f.prov.Issuer,
		"jti": freshJTI(),
		"iat": now.Unix(),
		"exp": now.Add(2 * time.Minute).Unix(),
	})
}

// requestObjectMintedAt builds a signed request object whose iat / nbf
// sit at mintedAt while exp stays 5 minutes ahead of the fixture clock.
// The result is a request the FAPI profile considers valid for its
// whole 60-minute window.
func (f *fapiPARFixture) requestObjectMintedAt(tb testing.TB, mintedAt time.Time) string {
	tb.Helper()
	_, challenge := pkcePair()
	return f.sign(tb, requestObjectTyp, map[string]any{
		"iss":                   fapiPARClientID,
		"aud":                   f.prov.Issuer,
		"iat":                   mintedAt.Unix(),
		"nbf":                   mintedAt.Unix(),
		"exp":                   f.clock.now.Add(5 * time.Minute).Unix(),
		"jti":                   freshJTI(),
		"client_id":             fapiPARClientID,
		"response_type":         "code",
		"redirect_uri":          fapiPARRedirect,
		"scope":                 "openid profile email",
		"state":                 "par-fapi-state",
		"nonce":                 "par-fapi-nonce",
		"code_challenge":        challenge,
		"code_challenge_method": "S256",
	})
}

// push POSTs the signed request object with a fresh client_assertion.
func (f *fapiPARFixture) push(tb testing.TB, requestObject string) *http.Response {
	tb.Helper()
	form := url.Values{
		"client_id":             {fapiPARClientID},
		"request":               {requestObject},
		"client_assertion":      {f.clientAssertion(tb)},
		"client_assertion_type": {assertionType},
	}
	return postPARForm(tb, f.prov.HTTPClient(nil), f.endpoint, form, "", "")
}

// TestPAR_FAPIProfile_AcceptsRequestObjectOlderThanDefaultMaxAge pins
// the FAPI 2.0 Message Signing §5.6 window against the verifier's own,
// tighter default: a request object minted 30 minutes ago is inside the
// 60 minutes the profile grants and MUST be accepted. With the age cap
// left at the library default the push fails with
// invalid_request_object even though the object's exp has not passed.
func TestPAR_FAPIProfile_AcceptsRequestObjectOlderThanDefaultMaxAge(t *testing.T) {
	t.Parallel()

	f := newFAPIPARFixture(t)
	resp := f.push(t, f.requestObjectMintedAt(t, f.clock.now.Add(-30*time.Minute)))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body := decodeJSON(t, resp)
		t.Fatalf("status=%d want 201 for a request object inside the profile window (body=%v)",
			resp.StatusCode, body)
	}
	body := decodeJSON(t, resp)
	if uri, _ := body["request_uri"].(string); !strings.HasPrefix(uri, "urn:ietf:params:oauth:request_uri:") {
		t.Errorf("request_uri=%v want a PAR URN", body["request_uri"])
	}
}

// TestPAR_DefaultProfile_RejectsRequestObjectOlderThanDefaultMaxAge is
// the counterpart: a deployment that declares no profile keeps the
// tighter default replay window, so the same 30-minute-old object is
// refused.
func TestPAR_DefaultProfile_RejectsRequestObjectOlderThanDefaultMaxAge(t *testing.T) {
	t.Parallel()

	f := newJARFixture(t)
	claims := f.happyClaims()
	minted := f.clock.now.Add(-30 * time.Minute)
	claims["iat"] = minted.Unix()
	claims["nbf"] = minted.Unix()
	form := url.Values{
		"client_id": {f.rp.ID},
		"request":   {f.jarSign(t, claims)},
	}
	resp := postPARForm(t, f.prov.HTTPClient(nil), f.endpoint, form, f.rp.ID, f.secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 for an iat beyond the default max age", resp.StatusCode)
	}
	body := decodeJSON(t, resp)
	if body["error"] != "invalid_request_object" {
		t.Errorf("error=%v want invalid_request_object", body["error"])
	}
}
