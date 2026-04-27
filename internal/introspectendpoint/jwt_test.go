package introspectendpoint_test

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	josev4 "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/libraz/go-oidc-provider/internal/introspectendpoint"
	"github.com/libraz/go-oidc-provider/internal/tokens"
)

// jwtAccept is the RFC 9701 §4 wire content-type a client sets to
// request the JWT introspection envelope. Pulled into a constant so
// each test reads the negotiation step without re-quoting the literal.
const jwtAccept = "application/token-introspection+jwt"

// postWithAccept issues a POST application/x-www-form-urlencoded
// request like [fixture.post] but additionally stamps the Accept
// header. RFC 9701 §5 negotiates the response format on Accept, so
// the JWT-path tests need a knob the JSON-path helper does not expose.
func (f *fixture) postWithAccept(tb testing.TB, form url.Values, basicID, basicSecret, accept string) *http.Response {
	tb.Helper()
	req, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		f.endpoint,
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		tb.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	if basicID != "" {
		req.SetBasicAuth(basicID, basicSecret)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		tb.Fatalf("Do: %v", err)
	}
	return resp
}

// verifyIntrospectionJWT parses raw as the RFC 9701 §4 envelope,
// verifies the JWS against the testkit's public signing key, and
// returns the decoded claim bundle. The helper fails the test on any
// structural / cryptographic fault so callers can read the result as
// a happy-path object.
func verifyIntrospectionJWT(tb testing.TB, raw string, pub *ecdsa.PublicKey) map[string]any {
	tb.Helper()
	parsed, err := jwt.ParseSigned(raw, []josev4.SignatureAlgorithm{josev4.ES256})
	if err != nil {
		tb.Fatalf("ParseSigned: %v", err)
	}
	out := map[string]any{}
	if err := parsed.Claims(pub, &out); err != nil {
		tb.Fatalf("Claims: %v", err)
	}
	assertTyp(tb, raw, "token-introspection+jwt")
	return out
}

// assertTyp decodes the JWS protected header from raw and fails the
// test when its "typ" does not match want. The check sidesteps go-jose
// v4's typed header API because the ExtraHeaders surface there is
// keyed by a private constant, not a plain string.
func assertTyp(tb testing.TB, raw, want string) {
	tb.Helper()
	dot := strings.IndexByte(raw, '.')
	if dot <= 0 {
		tb.Fatalf("compact JWS missing first segment: %q", raw)
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(raw[:dot])
	if err != nil {
		tb.Fatalf("decode header: %v", err)
	}
	var hdr struct {
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(headerBytes, &hdr); err != nil {
		tb.Fatalf("unmarshal header: %v", err)
	}
	if hdr.Typ != want {
		tb.Errorf("typ=%q want %q", hdr.Typ, want)
	}
}

// publicSigner returns the ECDSA public key backing the testkit's
// active signing entry. Tests use it to verify the JWT envelope the
// handler emits; obtaining it through the testkit avoids hard-coding
// a fixture key.
func (f *fixture) publicSigner(tb testing.TB) *ecdsa.PublicKey {
	tb.Helper()
	pub, ok := f.signer.Signer.Public().(*ecdsa.PublicKey)
	if !ok {
		tb.Fatalf("signer public key is not *ecdsa.PublicKey: %T", f.signer.Signer.Public())
	}
	return pub
}

// readBody returns the response body as a string, failing the test
// on a read fault. The handler emits the JWS as a bare body so callers
// pass the result straight into the JOSE parser.
func readBody(tb testing.TB, resp *http.Response) string {
	tb.Helper()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		tb.Fatalf("ReadAll: %v", err)
	}
	return string(raw)
}

// TestHandler_JWTResponse_AcceptHeader confirms that an active JWT
// access-token introspection emits the RFC 9701 §4 envelope when the
// caller sets Accept: application/token-introspection+jwt. The body
// is a verifiable JWS whose claims carry iss / aud / iat plus the
// nested token_introspection object.
func TestHandler_JWTResponse_AcceptHeader(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClient(t, "client-jwt-accept")
	tok := f.signAccessToken(t, func(c *tokens.AccessTokenClaims) {
		c.ClientID = client.ID
		c.Subject = "user-jwt-accept"
		c.Scope = []string{"openid", "profile"}
		c.Audience = []string{f.prov.Issuer}
	})
	form := url.Values{"token": {tok}}
	resp := f.postWithAccept(t, form, client.ID, secret, jwtAccept)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%s", resp.StatusCode, dump)
	}
	if got := resp.Header.Get("Content-Type"); got != jwtAccept {
		t.Errorf("Content-Type=%q want %q", got, jwtAccept)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control=%q want no-store", got)
	}
	body := readBody(t, resp)
	claims := verifyIntrospectionJWT(t, body, f.publicSigner(t))
	if got := claims["iss"]; got != f.prov.Issuer {
		t.Errorf("iss=%v want %q", got, f.prov.Issuer)
	}
	if got := claims["aud"]; got != client.ID {
		t.Errorf("aud=%v want %q", got, client.ID)
	}
	if _, ok := claims["iat"].(float64); !ok {
		t.Errorf("iat not numeric: %T", claims["iat"])
	}
	intro, ok := claims["token_introspection"].(map[string]any)
	if !ok {
		t.Fatalf("token_introspection not an object: %T", claims["token_introspection"])
	}
	if active, _ := intro["active"].(bool); !active {
		t.Errorf("token_introspection.active=%v want true", intro["active"])
	}
	if intro["client_id"] != client.ID {
		t.Errorf("token_introspection.client_id=%v want %q", intro["client_id"], client.ID)
	}
	if intro["sub"] != "user-jwt-accept" {
		t.Errorf("token_introspection.sub=%v want user-jwt-accept", intro["sub"])
	}
}

// TestHandler_JWTResponse_ClientMetadata confirms that a client whose
// IntrospectionSignedResponseAlg is preregistered receives a JWT
// envelope even when the request omits the Accept header. RFC 9701 §5
// rule 1 mandates the JWT path in that case.
func TestHandler_JWTResponse_ClientMetadata(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClient(t, "client-jwt-metadata")
	// Patch the registered client to opt into JWT introspection.
	mutated := *client
	mutated.IntrospectionSignedResponseAlg = "ES256"
	if err := f.prov.Store.UpdateClient(context.Background(), &mutated); err != nil {
		t.Fatalf("UpdateClient: %v", err)
	}
	tok := f.signAccessToken(t, func(c *tokens.AccessTokenClaims) {
		c.ClientID = client.ID
		c.Subject = "user-jwt-meta"
		c.Audience = []string{f.prov.Issuer}
	})
	form := url.Values{"token": {tok}}
	// Note: no Accept header — the metadata alone forces JWT.
	resp := f.postWithAccept(t, form, client.ID, secret, "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%s", resp.StatusCode, dump)
	}
	if got := resp.Header.Get("Content-Type"); got != jwtAccept {
		t.Errorf("Content-Type=%q want %q", got, jwtAccept)
	}
	body := readBody(t, resp)
	claims := verifyIntrospectionJWT(t, body, f.publicSigner(t))
	intro, ok := claims["token_introspection"].(map[string]any)
	if !ok {
		t.Fatalf("token_introspection missing: %v", claims)
	}
	if active, _ := intro["active"].(bool); !active {
		t.Errorf("token_introspection.active=%v want true", intro["active"])
	}
}

// TestHandler_JWTResponse_Inactive confirms that the JWT path still
// emits the §4 envelope for an inactive lookup. The
// token_introspection object MUST carry only "active": false per
// RFC 7662 §2.2 — the spec rule survives the JWT wrapping.
func TestHandler_JWTResponse_Inactive(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClient(t, "client-jwt-inactive")
	form := url.Values{"token": {"never-issued"}}
	resp := f.postWithAccept(t, form, client.ID, secret, jwtAccept)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%s", resp.StatusCode, dump)
	}
	if got := resp.Header.Get("Content-Type"); got != jwtAccept {
		t.Errorf("Content-Type=%q want %q", got, jwtAccept)
	}
	body := readBody(t, resp)
	claims := verifyIntrospectionJWT(t, body, f.publicSigner(t))
	if got := claims["aud"]; got != client.ID {
		t.Errorf("aud=%v want %q", got, client.ID)
	}
	intro, ok := claims["token_introspection"].(map[string]any)
	if !ok {
		t.Fatalf("token_introspection not an object: %T", claims["token_introspection"])
	}
	if active, _ := intro["active"].(bool); active {
		t.Errorf("token_introspection.active=true on inactive path; intro=%v", intro)
	}
	if len(intro) != 1 {
		t.Errorf("inactive token_introspection has %d members; want exactly 1; intro=%v", len(intro), intro)
	}
}

// TestHandler_JSONDefault confirms that an introspection request with
// neither Accept negotiation nor client metadata still receives the
// legacy JSON envelope. The regression catches a future flip of the
// negotiation rule that would break RFC 7662-only RPs.
func TestHandler_JSONDefault(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClient(t, "client-json-default")
	tok := f.signAccessToken(t, func(c *tokens.AccessTokenClaims) {
		c.ClientID = client.ID
		c.Audience = []string{f.prov.Issuer}
	})
	form := url.Values{"token": {tok}}
	resp := f.post(t, form, client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%s", resp.StatusCode, dump)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type=%q want application/json", got)
	}
	body := decodeJSON(t, resp)
	if active, _ := body["active"].(bool); !active {
		t.Errorf("active=%v want true", body["active"])
	}
}

// TestPreferJWT exercises the RFC 7231 §5.3.2 negotiation matrix the
// dispatcher relies on. Each entry maps an Accept header value to the
// expected JWT preference; the cases mirror the RFC 9701 §5 examples
// the spec calls out.
func TestPreferJWT(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		accept string
		want   bool
	}{
		{name: "explicit jwt", accept: "application/token-introspection+jwt", want: true},
		{name: "explicit json", accept: "application/json", want: false},
		{name: "empty", accept: "", want: false},
		{name: "wildcard only", accept: "*/*", want: false},
		{name: "both no q", accept: "application/json, application/token-introspection+jwt", want: true},
		{name: "json lower q", accept: "application/json;q=0.9, application/token-introspection+jwt;q=1.0", want: true},
		{name: "jwt lower q", accept: "application/token-introspection+jwt;q=0.5, application/json;q=1.0", want: false},
		{name: "jwt q=0", accept: "application/token-introspection+jwt;q=0", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := introspectendpoint.PreferJWTForTest(tc.accept)
			if got != tc.want {
				t.Errorf("PreferJWT(%q)=%v want %v", tc.accept, got, tc.want)
			}
		})
	}
}
