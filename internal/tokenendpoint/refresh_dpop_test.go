package tokenendpoint_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/libraz/go-oidc-provider/internal/dpop"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// dpopFixture builds a token-endpoint fixture with the DPoP feature
// enabled. It mirrors [newFixture] but threads
// [op.WithFeature(feature.DPoP)] through testkit.
func dpopFixture(tb testing.TB) *fixture {
	tb.Helper()
	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	prov := testkit.NewProvider(tb,
		testkit.WithClock(clock),
		testkit.WithOptions(op.WithFeature(feature.DPoP)),
	)
	return &fixture{
		prov:     prov,
		endpoint: prov.Server.URL + "/oidc/token",
		clock:    clock,
	}
}

// dpopKeyPair pairs a freshly generated ECDSA P-256 signer with its
// public-key thumbprint.
type dpopKeyPair struct {
	priv crypto.Signer
	jkt  string
}

func newDPoPKey(t testing.TB) dpopKeyPair {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	jkt, err := dpop.Thumbprint(&josev4.JSONWebKey{Key: &priv.PublicKey})
	if err != nil {
		t.Fatalf("Thumbprint: %v", err)
	}
	return dpopKeyPair{priv: priv, jkt: jkt}
}

// makeDPoPProof builds a DPoP proof JWT for the given key, method, URL,
// and clock anchor. ath is the optional access-token hash.
func makeDPoPProof(t testing.TB, key dpopKeyPair, method, htu string, now time.Time, jti, ath string) string {
	t.Helper()
	pub := key.priv.Public()
	jwk := josev4.JSONWebKey{Key: pub}
	signer, err := josev4.NewSigner(
		josev4.SigningKey{Algorithm: josev4.ES256, Key: key.priv},
		(&josev4.SignerOptions{}).WithType("dpop+jwt").WithHeader("jwk", jwk),
	)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	claims := map[string]any{
		"jti": jti,
		"htm": method,
		"htu": htu,
		"iat": now.Unix(),
	}
	if ath != "" {
		claims["ath"] = ath
	}
	tok, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	return tok
}

// postWithDPoP issues a token-endpoint POST carrying both Basic auth
// and a DPoP header. dpopProof may be empty to omit the header.
func postWithDPoP(
	t testing.TB,
	endpoint string,
	form url.Values,
	basicID, basicSecret, dpopProof string,
) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		endpoint,
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(basicID, basicSecret)
	if dpopProof != "" {
		req.Header.Set("DPoP", dpopProof)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	return resp
}

// TestRefresh_DPoP_HappyPath verifies that a refresh request with a
// matching DPoP proof rotates the chain and re-binds the new tokens
// to the same thumbprint.
func TestRefresh_DPoP_HappyPath(t *testing.T) {
	t.Parallel()

	f := dpopFixture(t)
	client, secret := f.confidentialClientFixture(t)
	key := newDPoPKey(t)

	const tokenID = "rt-dpop-happy" //nolint:gosec // not a credential — opaque test fixture id.
	f.seedGrant(t, &store.Grant{
		ID: "grant-dpop-happy", Subject: "user-1", ClientID: client.ID,
		Scope: []string{"openid"},
	})
	f.seedRefreshToken(t, &store.RefreshToken{
		ID:       tokenID,
		ClientID: client.ID,
		Subject:  "user-1",
		GrantID:  "grant-dpop-happy",
		Scope:    []string{"openid"},
		DPoPJKT:  key.jkt,
	})

	form := refreshForm(tokenID, "")
	proof := makeDPoPProof(t, key, "POST", f.endpoint, f.clock.now, "jti-refresh-1", "")
	resp := postWithDPoP(t, f.endpoint, form, client.ID, secret, proof)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200, body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	body := decodeJSON(t, resp)
	if got := body["token_type"]; got != "DPoP" {
		t.Errorf("token_type=%v want DPoP", got)
	}
	rotated, _ := body["refresh_token"].(string)
	if rotated == "" || rotated == tokenID {
		t.Errorf("refresh_token must rotate; got %q (input %q)", rotated, tokenID)
	}

	// The rotated record MUST carry the same jkt so subsequent
	// refresh requests are still bound.
	rec, err := f.prov.Store.RefreshTokens().Find(context.Background(), rotated)
	if err != nil {
		t.Fatalf("Find rotated: %v", err)
	}
	if rec.DPoPJKT != key.jkt {
		t.Errorf("rotated DPoPJKT=%q want %q", rec.DPoPJKT, key.jkt)
	}
}

// TestRefresh_DPoP_MissingProof rejects a refresh of a DPoP-bound
// token when no proof is presented.
func TestRefresh_DPoP_MissingProof(t *testing.T) {
	t.Parallel()

	f := dpopFixture(t)
	client, secret := f.confidentialClientFixture(t)
	key := newDPoPKey(t)

	const tokenID = "rt-dpop-noproof" //nolint:gosec // not a credential — opaque test fixture id.
	f.seedRefreshToken(t, &store.RefreshToken{
		ID:       tokenID,
		ClientID: client.ID,
		Subject:  "user-1",
		GrantID:  "grant-dpop-noproof",
		Scope:    []string{"openid"},
		DPoPJKT:  key.jkt,
	})

	form := refreshForm(tokenID, "")
	resp := postWithDPoP(t, f.endpoint, form, client.ID, secret, "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
	if got := decodeJSON(t, resp)["error"]; got != "invalid_grant" {
		t.Errorf("error=%v want invalid_grant", got)
	}
}

// TestRefresh_DPoP_ThumbprintMismatch rejects a refresh whose proof is
// signed by a different key than the chain was bound to.
func TestRefresh_DPoP_ThumbprintMismatch(t *testing.T) {
	t.Parallel()

	f := dpopFixture(t)
	client, secret := f.confidentialClientFixture(t)
	bound := newDPoPKey(t)
	other := newDPoPKey(t)

	const tokenID = "rt-dpop-mismatch" //nolint:gosec // not a credential — opaque test fixture id.
	f.seedRefreshToken(t, &store.RefreshToken{
		ID:       tokenID,
		ClientID: client.ID,
		Subject:  "user-1",
		GrantID:  "grant-dpop-mismatch",
		Scope:    []string{"openid"},
		DPoPJKT:  bound.jkt,
	})

	form := refreshForm(tokenID, "")
	proof := makeDPoPProof(t, other, "POST", f.endpoint, f.clock.now, "jti-mismatch", "")
	resp := postWithDPoP(t, f.endpoint, form, client.ID, secret, proof)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
	if got := decodeJSON(t, resp)["error"]; got != "invalid_grant" {
		t.Errorf("error=%v want invalid_grant", got)
	}
}

// TestRefresh_DPoP_BearerChainStillWorks confirms that a bearer chain
// (no DPoPJKT) refreshes without requiring a proof, even when the
// feature is enabled.
func TestRefresh_DPoP_BearerChainStillWorks(t *testing.T) {
	t.Parallel()

	f := dpopFixture(t)
	client, secret := f.confidentialClientFixture(t)

	const tokenID = "rt-dpop-bearer" //nolint:gosec // not a credential — opaque test fixture id.
	f.seedRefreshToken(t, &store.RefreshToken{
		ID:       tokenID,
		ClientID: client.ID,
		Subject:  "user-1",
		GrantID:  "grant-bearer",
		Scope:    []string{"openid"},
	})

	form := refreshForm(tokenID, "")
	resp := postWithDPoP(t, f.endpoint, form, client.ID, secret, "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200, body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	if got := decodeJSON(t, resp)["token_type"]; got != "Bearer" {
		t.Errorf("token_type=%v want Bearer", got)
	}
}

// TestRefresh_DPoP_BearerChainNoBindOnRefreshConfidential: a bearer
// refresh-token chain held by a CONFIDENTIAL client whose refresh
// request DOES present a valid proof still gets a DPoP-bound access
// token (so the resource server enforces sender-constraint), but the
// rotated refresh-token record stays bearer. Confidential clients
// authenticate the chain through their own credentials per RFC 9449
// §5; opportunistically binding the chain to a single DPoP key would
// then lock all subsequent refreshes to that key — contradicting the
// "MAY rotate" guidance for confidential clients and breaking the
// OFCS FAPI 2.0 refresh-token module.
func TestRefresh_DPoP_BearerChainNoBindOnRefreshConfidential(t *testing.T) {
	t.Parallel()

	f := dpopFixture(t)
	client, secret := f.confidentialClientFixture(t)
	key := newDPoPKey(t)

	const tokenID = "rt-dpop-upgrade" //nolint:gosec // not a credential — opaque test fixture id.
	f.seedRefreshToken(t, &store.RefreshToken{
		ID:       tokenID,
		ClientID: client.ID,
		Subject:  "user-1",
		GrantID:  "grant-upgrade",
		Scope:    []string{"openid"},
	})

	form := refreshForm(tokenID, "")
	proof := makeDPoPProof(t, key, "POST", f.endpoint, f.clock.now, "jti-upgrade", "")
	resp := postWithDPoP(t, f.endpoint, form, client.ID, secret, proof)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	body := decodeJSON(t, resp)
	if got := body["token_type"]; got != "DPoP" {
		t.Errorf("token_type=%v want DPoP", got)
	}
	rotated, _ := body["refresh_token"].(string)
	if rotated == "" {
		t.Errorf("refresh_token must be present, body=%v", body)
	}
	rec, err := f.prov.Store.RefreshTokens().Find(context.Background(), rotated)
	if err != nil {
		t.Fatalf("Find rotated: %v", err)
	}
	if rec.DPoPJKT != "" {
		t.Errorf("rotated DPoPJKT=%q want empty (confidential client, RFC 9449 §5)", rec.DPoPJKT)
	}
}
