package scenarios_test

// Catalog: test/scenarios/catalog/{jwks,signatures,id_jag,dynamic_registration}.yaml
// Spec:
//   - RFC 7515 — JSON Web Signature
//   - RFC 7517 — JSON Web Key (kid lookup, alg)
//   - RFC 7518 §3.3, §6.3 — RS256, RSA key parameters
//   - OIDC Core 1.0 §3.1.3.6, §15.1 — hash claims, RS256 MTI
//   - OIDC Dynamic Client Registration 1.0 §2

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"strings"
	"testing"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/testkit"
	"github.com/libraz/go-oidc-provider/test/scenarios/internal/scenariokit"
)

const (
	sigAlgClientID = "rp-sigalg"
	sigAlgCallback = "https://rp.testkit.invalid/callback"
	//nolint:gosec // test fixture: not a real credential.
	sigAlgSecret = "rp-sigalg-secret"
)

// sigAlgBoth is the issuing-algorithm axis every scenario in this file
// runs on.
var sigAlgBoth = []op.SigningAlgorithm{op.AlgES256, op.AlgRS256}

// sigAlgFetchJWKS GETs the provider's JWKS and decodes it.
func sigAlgFetchJWKS(t *testing.T, tk *testkit.Provider) josev4.JSONWebKeySet {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, tk.Server.URL+"/oidc/jwks", http.NoBody)
	if err != nil {
		t.Fatalf("build jwks request: %v", err)
	}
	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("GET jwks: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var set josev4.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		t.Fatalf("decode jwks: %v", err)
	}
	return set
}

// sigAlgAssertIssued checks that token's header kid resolves to exactly
// one published JWKS entry, that the entry's alg, the header alg and want
// agree, and that the entry's public key verifies the signature.
func sigAlgAssertIssued(t *testing.T, tk *testkit.Provider, token string, want op.SigningAlgorithm) {
	t.Helper()
	if strings.Count(token, ".") != 2 {
		t.Fatalf("not a compact JWS: %q", token)
	}
	jws, err := josev4.ParseSignedCompact(token, []josev4.SignatureAlgorithm{josev4.SignatureAlgorithm(want)})
	if err != nil {
		t.Fatalf("ParseSigned as %s: %v", want, err)
	}
	hdr := jws.Signatures[0].Header
	if hdr.Algorithm != string(want) {
		t.Errorf("header alg = %q, want %q", hdr.Algorithm, want)
	}
	if hdr.KeyID == "" {
		t.Fatal("header kid missing")
	}
	set := sigAlgFetchJWKS(t, tk)
	entries := set.Key(hdr.KeyID)
	if len(entries) != 1 {
		t.Fatalf("kid %q matches %d JWKS entries, want 1", hdr.KeyID, len(entries))
	}
	if entries[0].Algorithm != string(want) {
		t.Errorf("JWKS entry alg = %q, want %q", entries[0].Algorithm, want)
	}
	if _, err := jws.Verify(entries[0].Public()); err != nil {
		t.Errorf("signature does not verify under the published key: %v", err)
	}
}

// sigAlgFlow is one authorization-code round trip on a provider signing
// with the chosen algorithm.
type sigAlgFlow struct {
	tk   *testkit.Provider
	code string
	tok  scenariokit.TokenResponse
}

func sigAlgRunFlow(t *testing.T, alg op.SigningAlgorithm) *sigAlgFlow {
	t.Helper()
	tk := testkit.NewProvider(t,
		testkit.WithSigningAlgorithm(alg),
		testkit.WithOptions(
			op.WithFeature(feature.Introspect),
			op.WithAccessTokenFormat(op.AccessTokenFormatJWT),
		),
	)
	hash, err := op.HashClientSecret(sigAlgSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      sigAlgClientID,
		SecretHash:              hash,
		RedirectURIs:            []string{sigAlgCallback},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{"authorization_code"},
	})
	tk.Store.PutUser(context.Background(), &store.User{Subject: scenariokit.DefaultSubject})
	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID: sigAlgClientID, RedirectURI: sigAlgCallback, Scope: "openid profile", PKCE: pkce,
	})
	if flow.Code == "" {
		t.Fatalf("authorize callback missing code: %+v", flow)
	}
	tok := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code: flow.Code, RedirectURI: sigAlgCallback, Verifier: pkce.Verifier,
		ClientID: sigAlgClientID, ClientSecret: sigAlgSecret,
	})
	if tok.StatusCode != http.StatusOK || tok.IDToken == "" || tok.AccessToken == "" {
		t.Fatalf("/token status=%d body=%v, want 200 with id_token and access_token", tok.StatusCode, tok.Raw)
	}
	return &sigAlgFlow{tk: tk, code: flow.Code, tok: tok}
}

func (f *sigAlgFlow) userinfoJWT(t *testing.T) string {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, f.tk.Server.URL+"/oidc/userinfo", http.NoBody)
	if err != nil {
		t.Fatalf("build userinfo request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+f.tok.AccessToken)
	req.Header.Set("Accept", "application/jwt")
	resp, err := f.tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("GET userinfo: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/jwt") {
		t.Fatalf("userinfo status=%d content-type=%q body=%s, want 200 application/jwt",
			resp.StatusCode, resp.Header.Get("Content-Type"), body)
	}
	return strings.TrimSpace(string(body))
}

func (f *sigAlgFlow) introspectionJWT(t *testing.T) string {
	t.Helper()
	resp := jintIntrospect(t, f.tk, sigAlgClientID, sigAlgSecret, f.tok.AccessToken, jintJWTAccept)
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != jintJWTAccept {
		t.Fatalf("introspect status=%d content-type=%q body=%s, want 200 %s",
			resp.StatusCode, resp.Header.Get("Content-Type"), body, jintJWTAccept)
	}
	return strings.TrimSpace(string(body))
}

// sigAlgJARMResponse runs a query.jwt authorization flow and returns the
// raw response JWT.
func sigAlgJARMResponse(t *testing.T, alg op.SigningAlgorithm) (*testkit.Provider, string) {
	t.Helper()
	tk, rp := newJARMProvider(t, testkit.WithSigningAlgorithm(alg))
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    rp.ID,
		RedirectURI: jarmTestRedirectURI,
		PKCE:        scenariokit.NewPKCEPair(""),
		Extra:       map[string][]string{"response_mode": {"query.jwt"}},
	})
	if flow.Error != "" {
		t.Fatalf("authorize error=%s desc=%s", flow.Error, flow.ErrorDesc)
	}
	raw := flow.Location.Query().Get("response")
	if raw == "" {
		t.Fatalf("'response' parameter missing from callback: %s", flow.Location.String())
	}
	return tk, raw
}

// sigAlgLogoutToken returns the Logout Token the OP delivered to a stub RP.
func sigAlgLogoutToken(t *testing.T, alg op.SigningAlgorithm) (*testkit.Provider, string) {
	t.Helper()
	tk := newBCLProvider(t, scenariokit.NewAuditCapture(), testkit.WithSigningAlgorithm(alg))
	rp := newBCLStubRP(t, http.StatusOK)
	const clientID = "rp-bcl-sigalg"
	redirectURI := "https://rp-bcl-sigalg.testkit.invalid/callback"
	registerBCLClient(t, tk, clientID, redirectURI, rp.uri())
	browser := newBCLBrowser(t, tk)
	hint := establishBCLGrant(t, tk, browser, clientID, redirectURI)
	endSessionAndDrain(t, tk, browser, hint)
	tokens := rp.received()
	if len(tokens) != 1 {
		t.Fatalf("logout tokens received = %d, want 1", len(tokens))
	}
	return tk, tokens[0]
}

// sigAlgSSFSETs returns the SETs a receiver polls after one credential-change
// event, for an OP signing with alg. The raw SETs are returned so the caller
// verifies them under the alg under test.
func sigAlgSSFSETs(t *testing.T, alg op.SigningAlgorithm) (*testkit.Provider, []string) {
	t.Helper()
	tk := newSSFProviderWith(t, true, []testkit.Option{
		testkit.WithSigningAlgorithm(alg),
		testkit.WithOptions(scenariokit.WithClientCredentials(), op.WithSharedSignals()),
	})
	token := ssfManageToken(t, tk, ssfRxA)
	id := ssfCreateStream(t, tk, token, map[string]any{"events_requested": []string{ssfEvCredentialChange}})
	ssfSeedGrant(t, tk, "carol", ssfRxA)
	ssfEmitCredentialChange(t, tk, "carol")

	status, resp := ssfDoJSON(t, tk, http.MethodPost, "/oidc/ssf/poll/"+id, token, map[string]any{"returnImmediately": true})
	if status != http.StatusOK {
		t.Fatalf("poll status=%d body=%v", status, resp)
	}
	sets, _ := resp["sets"].(map[string]any)
	out := make([]string, 0, len(sets))
	sawEvent := false
	for _, raw := range sets {
		set, _ := raw.(string)
		out = append(out, set)
		events, _ := scenariokit.DecodeJWSClaims(t, set)["events"].(map[string]any)
		if _, ok := events[ssfEvCredentialChange]; ok {
			sawEvent = true
		}
	}
	if !sawEvent {
		t.Fatalf("poll returned %d SETs without the credential-change event: %v", len(out), resp)
	}
	return tk, out
}

// TestSigningAlg_EveryIssuer asserts that each JWT-issuing path signs with
// the OP's configured algorithm: the header kid resolves to one JWKS entry
// whose alg equals the header alg and the expected alg, and that entry's
// key verifies the signature.
func TestSigningAlg_EveryIssuer(t *testing.T) {
	t.Parallel()

	for _, alg := range sigAlgBoth {
		t.Run(string(alg), func(t *testing.T) {
			t.Parallel()

			t.Run("code flow issuers", func(t *testing.T) {
				t.Parallel()
				f := sigAlgRunFlow(t, alg)
				for name, token := range map[string]func(*testing.T) string{
					"id_token":         func(*testing.T) string { return f.tok.IDToken },
					"access_token_jwt": func(*testing.T) string { return f.tok.AccessToken },
					"userinfo":         f.userinfoJWT,
					"introspection":    f.introspectionJWT,
				} {
					t.Run(name, func(t *testing.T) {
						t.Parallel()
						sigAlgAssertIssued(t, f.tk, token(t), alg)
					})
				}
			})

			t.Run("jarm", func(t *testing.T) {
				t.Parallel()
				tk, raw := sigAlgJARMResponse(t, alg)
				sigAlgAssertIssued(t, tk, raw, alg)
			})

			t.Run("logout_token", func(t *testing.T) {
				t.Parallel()
				tk, raw := sigAlgLogoutToken(t, alg)
				sigAlgAssertIssued(t, tk, raw, alg)
			})

			t.Run("ssf_set", func(t *testing.T) {
				t.Parallel()
				tk, sets := sigAlgSSFSETs(t, alg)
				for _, set := range sets {
					sigAlgAssertIssued(t, tk, set, alg)
				}
			})

			t.Run("id_jag", func(t *testing.T) {
				t.Parallel()
				idp := newIJGIdP(t, ijgIDPConfig{}, testkit.WithSigningAlgorithm(alg))
				token, _ := idp.issue(t, ijgDefaultExchange()).body["access_token"].(string)
				sigAlgAssertIssued(t, idp.tk, token, alg)
			})
		})
	}
}

// sigAlgAssertIDJAGRedeemed issues an ID-JAG from an IdP signing with alg
// and redeems it at a resource AS that trusts the IdP's published keys.
func sigAlgAssertIDJAGRedeemed(t *testing.T, alg op.SigningAlgorithm) {
	t.Helper()
	idp := newIJGIdP(t, ijgIDPConfig{}, testkit.WithSigningAlgorithm(alg))
	ras := newIJGRAS(t, idp, ijgRASIssuer, op.AssertionProfileIDJAG)

	x := ijgDefaultExchange()
	x.scope = "chat.read"
	x.resource = []string{ijgRASAPI}
	idjag, _ := idp.issue(t, x).body["access_token"].(string)

	if h := ijgHeader(t, idjag); h["typ"] != "oauth-id-jag+jwt" || h["alg"] != string(alg) {
		t.Errorf("header = %v, want typ oauth-id-jag+jwt, alg %s", h, alg)
	}
	sigAlgAssertIssued(t, idp.tk, idjag, alg)

	redeemed := ras.redeem(t, idjag, map[string][]string{"scope": {"chat.read"}})
	if redeemed.status != http.StatusOK {
		t.Fatalf("redemption status=%d body=%v, want 200", redeemed.status, redeemed.body)
	}
}

// sigAlgAssertHashClaims checks the at_hash and c_hash of a code-flow
// id_token: 22 base64url chars, the left half of SHA-256 of the access
// token and of the authorization code.
func sigAlgAssertHashClaims(t *testing.T, f *sigAlgFlow) {
	t.Helper()
	claims := scenariokit.DecodeJWSClaims(t, f.tok.IDToken)
	for claim, input := range map[string]string{"at_hash": f.tok.AccessToken, "c_hash": f.code} {
		got, _ := claims[claim].(string)
		if len(got) != 22 {
			t.Errorf("%s = %q, want 22 base64url chars", claim, got)
		}
		if want := idtLeftmostHalfSHA256(input); got != want {
			t.Errorf("%s = %q, want left half of SHA-256 %q", claim, got, want)
		}
	}
}

// sigAlgAssertRSAJWKS checks that the OP publishes its active RSA key as
// a public-only RS256 signing entry.
func sigAlgAssertRSAJWKS(t *testing.T) {
	t.Helper()
	tk := testkit.NewProvider(t, testkit.WithSigningAlgorithm(op.AlgRS256))
	_, _, body := fetchJWKS(t, tk.Server.URL)
	keys, _ := body["keys"].([]any)
	if len(keys) == 0 {
		t.Fatalf("JWKS has no keys: %v", body)
	}
	for i, raw := range keys {
		k, _ := raw.(map[string]any)
		if k["kty"] != "RSA" {
			t.Errorf("keys[%d] kty = %v, want RSA", i, k["kty"])
			continue
		}
		n, _ := k["n"].(string)
		e, _ := k["e"].(string)
		if n == "" || e == "" {
			t.Errorf("keys[%d] RSA key must publish n and e: %v", i, k)
			continue
		}
		nb, err := base64.RawURLEncoding.DecodeString(n)
		if err != nil {
			t.Errorf("keys[%d] n is not base64url: %v", i, err)
			continue
		}
		if bits := new(big.Int).SetBytes(nb).BitLen(); bits < 2048 {
			t.Errorf("keys[%d] modulus is %d bits, want at least 2048", i, bits)
		}
		if e != "AQAB" {
			t.Errorf("keys[%d] e = %q, want AQAB (65537)", i, e)
		}
		if k["alg"] != "RS256" || k["use"] != "sig" {
			t.Errorf("keys[%d] alg=%v use=%v, want RS256 / sig", i, k["alg"], k["use"])
		}
		for _, priv := range []string{"d", "p", "q", "dp", "dq", "qi", "oth"} {
			if _, present := k[priv]; present {
				t.Errorf("keys[%d] RSA key must not publish private member %q", i, priv)
			}
		}
	}
}

// sigAlgAssertDCRDefault registers a client that omits
// id_token_signed_response_alg and checks the OP fills in its own issuing
// algorithm, then that the other algorithm is refused.
func sigAlgAssertDCRDefault(t *testing.T, alg, other op.SigningAlgorithm) {
	t.Helper()
	tk := testkit.NewProvider(t,
		testkit.WithSigningAlgorithm(alg),
		testkit.WithOptions(op.WithDynamicRegistration(op.RegistrationOption{})),
	)
	f := &dcrFixture{tk: tk, endpoint: tk.Server.URL + "/oidc/register"}

	cid, _, _, body := f.register(t, nil)
	if got, _ := body["id_token_signed_response_alg"].(string); got != string(alg) {
		t.Errorf("id_token_signed_response_alg = %q, want %q", got, alg)
	}
	persisted, err := tk.Store.GetClient(context.Background(), cid)
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if persisted.IDTokenSignedResponseAlg != string(alg) {
		t.Errorf("stored IDTokenSignedResponseAlg = %q, want %q", persisted.IDTokenSignedResponseAlg, alg)
	}

	resp := f.post(t, f.mintIAT(t), "", map[string]any{
		"redirect_uris":                []string{"https://rp.test.invalid/cb"},
		"id_token_signed_response_alg": string(other),
	})
	defer func() { _ = resp.Body.Close() }()
	rej := scenariokit.DecodeJSON(t, resp)
	if resp.StatusCode != http.StatusBadRequest || rej["error"] != "invalid_client_metadata" {
		t.Errorf("requesting %s on a %s OP: status=%d body=%v, want 400 invalid_client_metadata",
			other, alg, resp.StatusCode, rej)
	}
}
