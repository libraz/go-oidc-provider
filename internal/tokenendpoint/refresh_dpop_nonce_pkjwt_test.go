package tokenendpoint_test

// Regression coverage for the RFC 9449 §8 use_dpop_nonce challenge +
// private_key_jwt retry. The earlier ordering ran client authentication
// (which consumes the assertion's "jti" via [store.ConsumedJTIStore])
// ahead of DPoP verification, so a client that retried with the same
// client_assertion after the nonce challenge surfaced as
// invalid_client / ErrAssertionReplayed instead of completing the
// flow. The fix moves [verifyTokenDPoP] ahead of authenticate on
// every grant; these tests pin that behaviour against
// grant_type=refresh_token, where the OFCS fapi2-message-signing-id1
// suite first surfaced the regression.

import (
	"context"
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
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// pkjwtNonceFixture wires DPoP + a [op.DPoPNonceSource] alongside the
// private_key_jwt client registry. Mirrors [dpopNonceFixture] but
// surfaces the testkit Provider so the caller can register a JWKS-
// backed client.
func pkjwtNonceFixture(t *testing.T, source op.DPoPNonceSource) *fixture {
	t.Helper()
	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	prov := testkit.NewProvider(t,
		testkit.WithClock(clock),
		testkit.WithOptions(
			op.WithFeature(feature.DPoP),
			op.WithDPoPNonceSource(source),
		),
	)
	return &fixture{
		prov:     prov,
		endpoint: prov.Server.URL + "/oidc/token",
		clock:    clock,
	}
}

// pkjwtClient is a private_key_jwt-authenticated client paired with the
// signing key used to mint client_assertion JWTs.
type pkjwtClient struct {
	id   string
	priv *ecdsa.PrivateKey
	kid  string
}

// registerPKJWTClient seeds a confidential client with private_key_jwt
// auth, a published ES256 JWKS, and the offline_access-capable grant
// list refresh-token tests need.
func registerPKJWTClient(t *testing.T, f *fixture, id string) pkjwtClient {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	const kid = "rp-pkjwt-kid"
	jwksRaw, err := json.Marshal(josev4.JSONWebKeySet{
		Keys: []josev4.JSONWebKey{{
			Key:       &priv.PublicKey,
			KeyID:     kid,
			Algorithm: string(josev4.ES256),
			Use:       "sig",
		}},
	})
	if err != nil {
		t.Fatalf("Marshal JWKS: %v", err)
	}
	//nolint:gosec // G101 false positive: "private_key_jwt" is the OIDC auth-method name, not a credential.
	f.prov.RegisterClient(t, testkit.ClientFixture{
		ID:                      id,
		Scopes:                  []string{"openid", "offline_access"},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		TokenEndpointAuthMethod: "private_key_jwt",
		JWKs:                    jwksRaw,
	})
	return pkjwtClient{id: id, priv: priv, kid: kid}
}

// signClientAssertion mints a private_key_jwt assertion. The audience
// is the OP issuer because [op_builders.buildAssertionVerifier] wires
// the issuer in [clientauth.PrivateKeyJWTVerifier.AuxAudiences] so
// either the canonical token-endpoint URL or the issuer is accepted.
func signClientAssertion(t *testing.T, f *fixture, c pkjwtClient, jti string) string {
	t.Helper()
	signer, err := josev4.NewSigner(
		josev4.SigningKey{
			Algorithm: josev4.ES256,
			Key: josev4.JSONWebKey{
				Key:       c.priv,
				KeyID:     c.kid,
				Algorithm: string(josev4.ES256),
				Use:       "sig",
			},
		},
		(&josev4.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		t.Fatalf("NewSigner ES256: %v", err)
	}
	now := f.clock.now
	claims := map[string]any{
		"iss": c.id,
		"sub": c.id,
		"aud": f.prov.Issuer,
		"jti": jti,
		"iat": now.Unix(),
		"exp": now.Add(2 * time.Minute).Unix(),
	}
	tok, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("Serialize ES256: %v", err)
	}
	return tok
}

// postPKJWTWithDPoP issues a token-endpoint POST that authenticates via
// private_key_jwt (form-borne client_assertion) and carries a DPoP
// proof. The Basic-auth path is skipped: the form parameters carry
// the credentials.
func postPKJWTWithDPoP(t *testing.T, f *fixture, form url.Values, dpopProof string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		f.endpoint,
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if dpopProof != "" {
		req.Header.Set("DPoP", dpopProof)
	}
	resp, err := f.prov.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	return resp
}

// TestRefresh_DPoPNonce_PrivateKeyJWTRetryAdmitsSameJTI pins the
// regression. The first refresh-token request carries a DPoP proof
// without a nonce, so the OP is expected to challenge with
// use_dpop_nonce 400 BEFORE consuming the client_assertion. The
// retry presents the same assertion (same jti) and a fresh proof
// embedding the issued nonce; the OP completes the rotation.
//
// The OFCS fapi2-message-signing-id1-refresh-token plan exercises an
// equivalent flow against a real RP; this test is the in-tree
// guardrail.
func TestRefresh_DPoPNonce_PrivateKeyJWTRetryAdmitsSameJTI(t *testing.T) {
	t.Parallel()

	source := &fakeNonceSource{}
	f := pkjwtNonceFixture(t, source)
	c := registerPKJWTClient(t, f, "client-pkjwt-retry")
	key := newDPoPKey(t)

	const tokenID = "rt-pkjwt-retry" //nolint:gosec // opaque test fixture id, not a credential.
	f.seedGrant(t, &store.Grant{
		ID: "grant-pkjwt-retry", Subject: "user-1", ClientID: c.id,
		Scope: []string{"openid", "offline_access"},
	})
	f.seedRefreshToken(t, &store.RefreshToken{
		ID:       tokenID,
		ClientID: c.id,
		Subject:  "user-1",
		GrantID:  "grant-pkjwt-retry",
		Scope:    []string{"openid", "offline_access"},
		DPoPJKT:  key.jkt,
	})

	const sharedJTI = "ca-pkjwt-shared"
	assertion := signClientAssertion(t, f, c, sharedJTI)
	form := refreshForm(tokenID, "")
	form.Set("client_assertion", assertion)
	form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")

	// First attempt: proof without nonce. Expect use_dpop_nonce
	// challenge BEFORE the client_assertion jti is consumed.
	proof1 := makeDPoPProofWithNonce(t, key, "POST", f.endpoint, f.clock.now, "dpop-jti-1", "")
	resp1 := postPKJWTWithDPoP(t, f, form, proof1)
	defer resp1.Body.Close()
	if resp1.StatusCode != http.StatusBadRequest {
		t.Fatalf("first attempt status=%d want 400, body=%v", resp1.StatusCode, decodeJSON(t, resp1))
	}
	body1 := decodeJSON(t, resp1)
	if got := body1["error"]; got != "use_dpop_nonce" {
		t.Fatalf(`first attempt body.error=%v want "use_dpop_nonce"`, got)
	}
	freshNonce := resp1.Header.Get("DPoP-Nonce")
	if freshNonce == "" {
		t.Fatal("DPoP-Nonce response header missing on the challenge")
	}

	// Second attempt: same client_assertion (same jti), fresh DPoP
	// proof with the issued nonce. Must complete the rotation.
	proof2 := makeDPoPProofWithNonce(t, key, "POST", f.endpoint, f.clock.now, "dpop-jti-2", freshNonce)
	resp2 := postPKJWTWithDPoP(t, f, form, proof2)
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("retry status=%d want 200, body=%v", resp2.StatusCode, decodeJSON(t, resp2))
	}
	body2 := decodeJSON(t, resp2)
	if got := body2["token_type"]; got != "DPoP" {
		t.Errorf("retry token_type=%v want DPoP", got)
	}
	rotated, _ := body2["refresh_token"].(string)
	if rotated == "" || rotated == tokenID {
		t.Errorf("refresh_token must rotate; got %q (input %q)", rotated, tokenID)
	}
}

// TestRefresh_DPoPNonce_PrivateKeyJWTReplayStillRejected confirms the
// fix did not weaken the legitimate replay defence. Once a
// client_assertion has been consumed by a successful authentication,
// a second submission with the same jti (even with a perfectly fresh
// DPoP nonce) MUST surface as invalid_client.
func TestRefresh_DPoPNonce_PrivateKeyJWTReplayStillRejected(t *testing.T) {
	t.Parallel()

	source := &fakeNonceSource{}
	source.IssueNonce() // pre-issue so the first attempt's proof can carry a valid nonce.
	f := pkjwtNonceFixture(t, source)
	c := registerPKJWTClient(t, f, "client-pkjwt-replay")
	key := newDPoPKey(t)

	const tokenID = "rt-pkjwt-replay-1"  //nolint:gosec // opaque test fixture id, not a credential.
	const tokenID2 = "rt-pkjwt-replay-2" //nolint:gosec // opaque test fixture id, not a credential.
	for _, id := range []string{tokenID, tokenID2} {
		f.seedRefreshToken(t, &store.RefreshToken{
			ID:       id,
			ClientID: c.id,
			Subject:  "user-1",
			GrantID:  "grant-pkjwt-replay",
			Scope:    []string{"openid", "offline_access"},
			DPoPJKT:  key.jkt,
		})
	}
	f.seedGrant(t, &store.Grant{
		ID: "grant-pkjwt-replay", Subject: "user-1", ClientID: c.id,
		Scope: []string{"openid", "offline_access"},
	})

	const sharedJTI = "ca-pkjwt-replay"
	assertion := signClientAssertion(t, f, c, sharedJTI)

	// First attempt — happy path. The current nonce is the value
	// fakeNonceSource.IssueNonce() returned during fixture setup.
	currentNonce := *source.current.Load()
	proof1 := makeDPoPProofWithNonce(t, key, "POST", f.endpoint, f.clock.now, "dpop-jti-A", currentNonce)
	form1 := refreshForm(tokenID, "")
	form1.Set("client_assertion", assertion)
	form1.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	resp1 := postPKJWTWithDPoP(t, f, form1, proof1)
	defer resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("first attempt status=%d want 200, body=%v", resp1.StatusCode, decodeJSON(t, resp1))
	}

	// Second attempt — reuse the same client_assertion. The DPoP
	// proof itself is fresh (new jti, current nonce) so the reject
	// MUST come from the assertion's replay gate, not the proof's.
	currentNonce = *source.current.Load() // sliding nonce: re-read after rotation.
	proof2 := makeDPoPProofWithNonce(t, key, "POST", f.endpoint, f.clock.now, "dpop-jti-B", currentNonce)
	form2 := refreshForm(tokenID2, "")
	form2.Set("client_assertion", assertion)
	form2.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	resp2 := postPKJWTWithDPoP(t, f, form2, proof2)
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replay status=%d want 401, body=%v", resp2.StatusCode, decodeJSON(t, resp2))
	}
	if got := decodeJSON(t, resp2)["error"]; got != "invalid_client" {
		t.Errorf("replay error=%v want invalid_client", got)
	}
}
