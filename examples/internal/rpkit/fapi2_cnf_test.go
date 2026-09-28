//go:build example

package rpkit_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/libraz/go-oidc-provider/examples/internal/rpkit"
)

// craftedCnfJKT is a value that can never coincidentally equal a real EC
// key's RFC 7638 thumbprint (a base64url SHA-256 digest), so a test
// asserting on it distinguishes "read from the token" from "recomputed
// locally" even though both produce a plausible-looking string.
const craftedCnfJKT = "server-issued-cnf-jkt-marker"

// fapi2FakeOP is a fake OP with the DPoP-shaped discovery surface
// FAPI2Flow needs, plus /par, /jwks, and /token — the parts fakeOP (in
// rpkit_stepup_test.go) deliberately stops short of, since the tests
// there never reach a real token exchange. /token always returns a
// signed id_token and a signed access_token carrying cnfJKT as its
// cnf.jkt (omitted entirely when cnfJKT is empty), regardless of what
// the request carries: this test is about what the RP does with the
// response, not about validating the request FAPI2Flow sent (that
// belongs to the OP's own test suite).
type fapi2FakeOP struct {
	issuer string

	mu    sync.Mutex
	state string // the "state" form field the RP pushed via PAR
}

func newFAPI2FakeOP(t *testing.T, cnfJKT string) *fapi2FakeOP {
	t.Helper()

	signKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	const kid = "op-sign-1"

	fake := &fapi2FakeOP{}
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	fake.issuer = srv.URL

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		doc := map[string]any{
			"issuer":                                         srv.URL,
			"authorization_endpoint":                         srv.URL + "/authorize",
			"token_endpoint":                                 srv.URL + "/token",
			"jwks_uri":                                       srv.URL + "/jwks",
			"pushed_authorization_request_endpoint":          srv.URL + "/par",
			"response_types_supported":                       []string{"code"},
			"subject_types_supported":                        []string{"public"},
			"id_token_signing_alg_values_supported":          []string{"ES256"},
			"code_challenge_methods_supported":               []string{"S256"},
			"authorization_response_iss_parameter_supported": true,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	})

	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key:       &signKey.PublicKey,
			KeyID:     kid,
			Algorithm: "ES256",
			Use:       "sig",
		}}}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	})

	mux.HandleFunc("/par", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "parse form: "+err.Error(), http.StatusBadRequest)
			return
		}
		fake.mu.Lock()
		fake.state = r.PostForm.Get("state")
		fake.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"request_uri": "urn:ietf:params:oauth:request_uri:fake-1",
			"expires_in":  60,
		})
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		now := time.Now()
		idToken, err := signTestJWT(signKey, kid, jwt.Claims{
			Issuer:   srv.URL,
			Subject:  "demo-user",
			Audience: jwt.Audience{"demo-fapi"},
			IssuedAt: jwt.NewNumericDate(now),
			Expiry:   jwt.NewNumericDate(now.Add(5 * time.Minute)),
		})
		if err != nil {
			http.Error(w, "sign id_token: "+err.Error(), http.StatusInternalServerError)
			return
		}
		atClaims := accessTokenClaims{
			Claims: jwt.Claims{
				Issuer:   srv.URL,
				Subject:  "demo-user",
				Audience: jwt.Audience{"https://api.example/"},
				IssuedAt: jwt.NewNumericDate(now),
				Expiry:   jwt.NewNumericDate(now.Add(5 * time.Minute)),
			},
		}
		if cnfJKT != "" {
			atClaims.Cnf = map[string]string{"jkt": cnfJKT}
		}
		accessToken, err := signTestJWT(signKey, kid, atClaims)
		if err != nil {
			http.Error(w, "sign access_token: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": accessToken,
			"id_token":     idToken,
			"token_type":   "DPoP",
			"expires_in":   300,
		})
	})

	return fake
}

// pushedState returns the "state" value the RP's PAR POST carried, once
// /login has run.
func (f *fapi2FakeOP) pushedState() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.state
}

// accessTokenClaims layers the DPoP confirmation claim (RFC 9449 §6.1)
// onto the registered JWT claims signTestJWT serialises.
type accessTokenClaims struct {
	jwt.Claims
	Cnf map[string]string `json:"cnf,omitempty"`
}

// signTestJWT signs claims with key using ES256, matching the alg the
// fake discovery document advertises.
func signTestJWT(key *ecdsa.PrivateKey, kid string, claims any) (string, error) {
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader(jose.HeaderKey("kid"), kid),
	)
	if err != nil {
		return "", err
	}
	return jwt.Signed(signer).Claims(claims).Serialize()
}

// driveFAPI2Login builds a FAPI2Flow against op, drives /login, and
// returns the handler plus the query a real OP redirect to /callback
// would carry: state resolved from what the RP actually pushed via PAR,
// a code, and the matching iss.
func driveFAPI2Login(t *testing.T, op *fapi2FakeOP) (http.Handler, url.Values) {
	t.Helper()

	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	f, err := rpkit.NewFAPI2(context.Background(), rpkit.FAPI2Options{
		Issuer:           op.issuer,
		ClientID:         "demo-fapi",
		RedirectURL:      "http://rp.example/callback",
		ClientPrivateKey: clientKey,
		ClientKeyID:      "fapi-client-1",
	})
	if err != nil {
		t.Fatalf("rpkit.NewFAPI2: %v", err)
	}
	h := f.Handler()

	// /login pushes the authorization request; state travels in the PAR
	// form body, not the redirect Location, unlike the plain CodeFlow.
	loginRec := httptest.NewRecorder()
	loginReq := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://rp.example/login", nil)
	h.ServeHTTP(loginRec, loginReq)
	if loginRec.Code != http.StatusFound {
		t.Fatalf("/login status = %d, want 302; body = %q", loginRec.Code, loginRec.Body.String())
	}
	state := op.pushedState()
	if state == "" {
		t.Fatal("the fake OP's /par never received a state form field")
	}
	return h, url.Values{"state": {state}, "code": {"fake-code"}, "iss": {op.issuer}}
}

// TestFAPI2Callback_AccessTokenCnfJKTComesFromTheIssuedToken pins the
// invariant rpkit depends on for its DPoP demonstration: the
// "_access_token_cnf_jkt" claim rendered on /me must be read from the
// actual access token's own cnf.jkt, not recomputed from the RP's own
// DPoP key. The fake OP's /token deliberately returns a cnf.jkt the RP's
// key could never produce; if the RP echoed its own key's thumbprint
// instead, the assertion below would still see a plausible-looking value
// and could not tell the two apart — so it compares against the
// specific marker the fake OP issued.
func TestFAPI2Callback_AccessTokenCnfJKTComesFromTheIssuedToken(t *testing.T) {
	t.Parallel()

	op := newFAPI2FakeOP(t, craftedCnfJKT)
	h, q := driveFAPI2Login(t, op)

	cbRec := httptest.NewRecorder()
	cbReq := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"http://rp.example/callback?"+q.Encode(), nil)
	h.ServeHTTP(cbRec, cbReq)
	if cbRec.Code != http.StatusFound {
		t.Fatalf("/callback status = %d, want 302; body = %q", cbRec.Code, cbRec.Body.String())
	}

	meRec := httptest.NewRecorder()
	meReq := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://rp.example/me", nil)
	h.ServeHTTP(meRec, meReq)
	if meRec.Code != http.StatusOK {
		t.Fatalf("/me status = %d, want 200; body = %q", meRec.Code, meRec.Body.String())
	}

	var claims map[string]any
	if err := json.Unmarshal(meRec.Body.Bytes(), &claims); err != nil {
		t.Fatalf("decode /me body: %v; body = %s", err, meRec.Body.String())
	}
	if got := claims["_access_token_cnf_jkt"]; got != craftedCnfJKT {
		t.Errorf("_access_token_cnf_jkt = %v, want the access token's own cnf.jkt %q "+
			"(a value equal to the RP's own DPoP key thumbprint would mean the claim "+
			"was recomputed locally instead of read from the issued token)", got, craftedCnfJKT)
	}
}

// TestFAPI2Callback_RejectsAccessTokenWithoutCnfJKT pins the other half
// of the invariant: an access token that carries no cnf.jkt at all must
// fail the callback rather than render a value anyway. FAPI 2.0's DPoP
// profile requires the confirmation claim on every sender-constrained
// access token (RFC 9449 §6.1); falling back to the RP's own key
// thumbprint here would hide an OP that stopped binding tokens instead
// of surfacing it.
func TestFAPI2Callback_RejectsAccessTokenWithoutCnfJKT(t *testing.T) {
	t.Parallel()

	op := newFAPI2FakeOP(t, "") // no cnf.jkt on the issued access token
	h, q := driveFAPI2Login(t, op)

	cbRec := httptest.NewRecorder()
	cbReq := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"http://rp.example/callback?"+q.Encode(), nil)
	h.ServeHTTP(cbRec, cbReq)

	if cbRec.Code != http.StatusBadGateway {
		t.Fatalf("/callback status = %d, want 502; body = %q", cbRec.Code, cbRec.Body.String())
	}
	if !strings.Contains(cbRec.Body.String(), "cnf.jkt") {
		t.Errorf("/callback body = %q, want it to name the missing cnf.jkt claim", cbRec.Body.String())
	}
}
