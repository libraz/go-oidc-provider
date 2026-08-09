package tokenendpoint_test

// The DPoP replay marker (RFC 9449 §11.1) is a durable write. Verifying
// the proof has to run before client authentication so the §8
// use_dpop_nonce challenge fires before a client_assertion jti is
// consumed, but the marker itself does not: writing it there would let
// a request that never authenticates consume storage, and would burn
// the proof of a client whose credentials were merely mistyped.
//
// The property is observable on the wire: if a rejected request had
// marked the proof, re-presenting it with correct credentials would be
// refused as a replay.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/url"
	"strings"
	"testing"

	josev4 "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
)

// writeGateProof builds an RFC 9449 §4.2 proof bound to the fixture's
// /token endpoint. The caller supplies the jti so two requests can
// deliberately share one.
func writeGateProof(tb testing.TB, f *fixture, jti string) string {
	tb.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	jwk := josev4.JSONWebKey{Key: &priv.PublicKey, Algorithm: string(josev4.ES256), Use: "sig"}
	signer, err := josev4.NewSigner(
		josev4.SigningKey{Algorithm: josev4.ES256, Key: priv},
		(&josev4.SignerOptions{}).WithType("dpop+jwt").WithHeader("jwk", jwk),
	)
	if err != nil {
		tb.Fatalf("NewSigner: %v", err)
	}
	token, err := jwt.Signed(signer).Claims(map[string]any{
		"htm": http.MethodPost,
		"htu": f.endpoint,
		"iat": f.clock.now.Unix(),
		"jti": jti,
	}).Serialize()
	if err != nil {
		tb.Fatalf("Serialize: %v", err)
	}
	return token
}

// postWithProof issues a /token redemption carrying a DPoP proof and
// HTTP Basic credentials.
func postWithProof(tb testing.TB, f *fixture, form url.Values, proof, clientID, secret string) *http.Response {
	tb.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		f.endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		tb.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, secret)
	req.Header.Set("DPoP", proof)
	resp, err := f.prov.HTTPClient(nil).Do(req)
	if err != nil {
		tb.Fatalf("POST /token: %v", err)
	}
	return resp
}

// TestToken_FailedClientAuthDoesNotConsumeDPoPProof drives one proof
// through a request that cannot authenticate and then through a request
// that can. The second attempt must not surface the replay gate: the
// rejected request had no business advancing the replay table.
func TestToken_FailedClientAuthDoesNotConsumeDPoPProof(t *testing.T) {
	t.Parallel()

	f := newFixtureWithOptions(t, op.WithFeature(feature.DPoP))
	client, secret := f.confidentialClientFixture(t)
	proof := writeGateProof(t, f, "jti-shared-across-attempts")
	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {"code-that-does-not-exist"},
		"redirect_uri": {"https://rp.testkit.invalid/callback"},
	}

	rejected := postWithProof(t, f, form, proof, client.ID, "wrong-secret")
	defer rejected.Body.Close()
	if rejected.StatusCode == http.StatusOK {
		t.Fatal("status=200; the request authenticated with a wrong secret")
	}
	if body := decodeJSON(t, rejected); body["error"] != "invalid_client" {
		t.Fatalf("error=%v want invalid_client", body["error"])
	}

	// Same proof, correct credentials. The code is still unknown, so the
	// grant validator refuses it — but the refusal must come from the
	// grant, never from the replay gate.
	retried := postWithProof(t, f, form, proof, client.ID, secret)
	defer retried.Body.Close()
	body := decodeJSON(t, retried)
	if desc, _ := body["error_description"].(string); strings.Contains(strings.ToLower(desc), "replay") {
		t.Fatalf("error_description=%q; the rejected attempt consumed the proof", desc)
	}
	if body["error"] != "invalid_grant" {
		t.Fatalf("error=%v want invalid_grant (body=%v)", body["error"], body)
	}
}

// TestToken_AuthenticatedProofIsStillSingleUse is the control: moving
// the marker behind authentication must not remove it.
func TestToken_AuthenticatedProofIsStillSingleUse(t *testing.T) {
	t.Parallel()

	f := newFixtureWithOptions(t, op.WithFeature(feature.DPoP))
	client, secret := f.confidentialClientFixture(t)
	proof := writeGateProof(t, f, "jti-used-twice")
	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {"code-that-does-not-exist"},
		"redirect_uri": {"https://rp.testkit.invalid/callback"},
	}

	first := postWithProof(t, f, form, proof, client.ID, secret)
	defer first.Body.Close()
	if body := decodeJSON(t, first); body["error"] != "invalid_grant" {
		t.Fatalf("first error=%v want invalid_grant", body["error"])
	}

	second := postWithProof(t, f, form, proof, client.ID, secret)
	defer second.Body.Close()
	body := decodeJSON(t, second)
	if body["error"] != "invalid_request" {
		t.Fatalf("second error=%v want invalid_request", body["error"])
	}
	if desc, _ := body["error_description"].(string); !strings.Contains(strings.ToLower(desc), "replay") {
		t.Fatalf("second error_description=%q want a replay mention", desc)
	}
}
