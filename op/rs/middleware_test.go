package rs_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/rs"
)

const wantAlgs = `algs="ES256 EdDSA PS256"`

// okHandler answers 200 with the verified subject, so a test can tell
// the request reached it with a token attached.
func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok, ok := rs.FromContext(r.Context())
		if !ok {
			http.Error(w, "no token in context", http.StatusInternalServerError)
			return
		}
		_, _ = io.WriteString(w, tok.Subject)
	})
}

func serve(t *testing.T, h http.Handler, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// wantRejected asserts a challenge response: status, an empty body, and
// the WWW-Authenticate value, which it returns.
func wantRejected(t *testing.T, rec *httptest.ResponseRecorder, status int) string {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("status = %d, want %d (WWW-Authenticate %q)", rec.Code, status, rec.Header().Get("WWW-Authenticate"))
	}
	if rec.Body.Len() != 0 {
		t.Errorf("body = %q, want empty", rec.Body.String())
	}
	values := rec.Header().Values("WWW-Authenticate")
	if len(values) != 1 {
		t.Fatalf("WWW-Authenticate has %d values, want exactly one header", len(values))
	}
	return values[0]
}

// TestMiddleware_WWWAuthenticate_UnauthenticatedOffersBothSchemes: under
// DPoPAllowed a request without credentials is offered both schemes, and
// neither carries an error attribute.
func TestMiddleware_WWWAuthenticate_UnauthenticatedOffersBothSchemes(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	h := f.verifier(t).Middleware()(okHandler())
	got := wantRejected(t, serve(t, h, newRequest(t, "", "")), http.StatusUnauthorized)
	want := `Bearer realm="` + testAudience + `", DPoP ` + wantAlgs
	if got != want {
		t.Fatalf("WWW-Authenticate = %q, want %q", got, want)
	}
}

// TestMiddleware_WWWAuthenticate_DPoPRequiredOffersDPoPOnly: under
// DPoPRequired the DPoP challenge is the only one, with or without an error.
func TestMiddleware_WWWAuthenticate_DPoPRequiredOffersDPoPOnly(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	h := f.verifier(t, func(c *rs.Config) { c.DPoP = rs.DPoPRequired }).Middleware()(okHandler())

	got := wantRejected(t, serve(t, h, newRequest(t, "", "")), http.StatusUnauthorized)
	if got != "DPoP "+wantAlgs {
		t.Errorf("unauthenticated WWW-Authenticate = %q, want %q", got, "DPoP "+wantAlgs)
	}

	got = wantRejected(t, serve(t, h, newRequest(t, "Bearer", f.token(t, nil))), http.StatusUnauthorized)
	if !strings.HasPrefix(got, "DPoP "+wantAlgs+`, error="invalid_token"`) || strings.Contains(got, "Bearer") {
		t.Errorf("bearer-token WWW-Authenticate = %q, want a lone DPoP challenge with invalid_token", got)
	}
}

// TestMiddleware_WWWAuthenticate_ErrorOnPresentedSchemeOnly: the error
// attributes ride on the challenge of the scheme the client used, and the
// other challenge keeps its scheme and parameters.
func TestMiddleware_WWWAuthenticate_ErrorOnPresentedSchemeOnly(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	h := f.verifier(t).Middleware()(okHandler())
	forged := f.token(t, func(c map[string]any) { c["iss"] = "https://attacker.example.com" })

	bearer, dpop := challenges(t, wantRejected(t, serve(t, h, newRequest(t, "Bearer", forged)), http.StatusUnauthorized))
	if !strings.Contains(bearer, `error="invalid_token"`) || !strings.Contains(bearer, `realm="`+testAudience+`"`) {
		t.Errorf("Bearer challenge = %q, want realm and invalid_token", bearer)
	}
	if dpop != "DPoP "+wantAlgs {
		t.Errorf("DPoP challenge = %q, want it free of error attributes", dpop)
	}

	bearer, dpop = challenges(t, wantRejected(t, serve(t, h, newRequest(t, "DPoP", forged)), http.StatusUnauthorized))
	if strings.Contains(bearer, "error=") {
		t.Errorf("Bearer challenge = %q, want no error attribute", bearer)
	}
	if !strings.HasPrefix(dpop, "DPoP "+wantAlgs+`, error="invalid_token"`) {
		t.Errorf("DPoP challenge = %q, want algs then invalid_token", dpop)
	}
}

// TestMiddleware_WWWAuthenticate_InvalidRequest: a malformed Authorization
// header is 400 with error="invalid_request".
func TestMiddleware_WWWAuthenticate_InvalidRequest(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	h := f.verifier(t).Middleware()(okHandler())
	bearer, _ := challenges(t, wantRejected(t, serve(t, h, newRequest(t, "Bearer", "a b")), http.StatusBadRequest))
	if !strings.Contains(bearer, `error="invalid_request"`) {
		t.Errorf("Bearer challenge = %q, want invalid_request", bearer)
	}
}

// TestMiddleware_WWWAuthenticate_InsufficientScope: 403 with the required
// scopes in the scope attribute (RFC 6750 §3.1).
func TestMiddleware_WWWAuthenticate_InsufficientScope(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	h := f.verifier(t).Middleware(rs.RequireScope("read", "admin"))(okHandler())
	bearer, _ := challenges(t, wantRejected(t, serve(t, h, newRequest(t, "Bearer", f.token(t, nil))), http.StatusForbidden))
	for _, want := range []string{`error="insufficient_scope"`, `scope="read admin"`} {
		if !strings.Contains(bearer, want) {
			t.Errorf("Bearer challenge = %q, want %s", bearer, want)
		}
	}

	h = f.verifier(t).Middleware(rs.RequireScope("read"))(okHandler())
	if rec := serve(t, h, newRequest(t, "Bearer", f.token(t, nil))); rec.Code != http.StatusOK {
		t.Errorf("status = %d for a token holding the scope, want 200", rec.Code)
	}
}

// TestMiddleware_WWWAuthenticate_InsufficientUserAuthentication: an unmet
// RequireACR or RequireMaxAge is 401 insufficient_user_authentication with
// acr_values / max_age (RFC 9470 §3).
func TestMiddleware_WWWAuthenticate_InsufficientUserAuthentication(t *testing.T) {
	t.Parallel()

	const mfa = "urn:example:mfa"
	levels := op.ACRLevels{mfa: op.AAL2}
	cases := []struct {
		name   string
		req    rs.Requirement
		claims func(map[string]any)
		want   string // empty: the request passes
	}{
		{"acr below the ladder", rs.RequireACR(levels, mfa), func(c map[string]any) { c["acr"] = op.AAL1.ACRURI() }, `acr_values="` + mfa + `"`},
		{"acr absent", rs.RequireACR(levels, mfa), nil, `acr_values="` + mfa + `"`},
		{"acr unknown to the ladder", rs.RequireACR(levels, mfa), func(c map[string]any) { c["acr"] = "urn:example:other" }, `acr_values="` + mfa + `"`},
		{"acr equal", rs.RequireACR(levels, mfa), func(c map[string]any) { c["acr"] = mfa }, ""},
		{"acr above on the ladder", rs.RequireACR(levels, mfa), func(c map[string]any) { c["acr"] = op.AAL3.ACRURI() }, ""},
		{"auth_time too old", rs.RequireMaxAge(5 * time.Minute), func(c map[string]any) { c["auth_time"] = testNow.Add(-10 * time.Minute).Unix() }, `max_age="300"`},
		{"auth_time absent", rs.RequireMaxAge(5 * time.Minute), nil, `max_age="300"`},
		{"auth_time at the limit", rs.RequireMaxAge(5 * time.Minute), func(c map[string]any) { c["auth_time"] = testNow.Add(-5 * time.Minute).Unix() }, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			h := f.verifier(t).Middleware(tc.req)(okHandler())
			rec := serve(t, h, newRequest(t, "Bearer", f.token(t, tc.claims)))
			if tc.want == "" {
				if rec.Code != http.StatusOK {
					t.Fatalf("status = %d, want 200 (WWW-Authenticate %q)", rec.Code, rec.Header().Get("WWW-Authenticate"))
				}
				return
			}
			bearer, _ := challenges(t, wantRejected(t, rec, http.StatusUnauthorized))
			for _, want := range []string{`error="insufficient_user_authentication"`, tc.want} {
				if !strings.Contains(bearer, want) {
					t.Errorf("Bearer challenge = %q, want %s", bearer, want)
				}
			}
		})
	}
}

// TestMiddleware_WWWAuthenticate_AlgsMatchDPoPVerifier: the algs the
// challenge advertises are exactly the proof algorithms the verifier
// accepts, checked by presenting a proof under each candidate.
func TestMiddleware_WWWAuthenticate_AlgsMatchDPoPVerifier(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	v := f.verifier(t)
	h := v.Middleware()(okHandler())
	_, dpop := challenges(t, wantRejected(t, serve(t, h, newRequest(t, "", "")), http.StatusUnauthorized))
	advertised := strings.Fields(strings.TrimSuffix(strings.TrimPrefix(dpop, `DPoP algs="`), `"`))

	var accepted []string
	for _, alg := range []josev4.SignatureAlgorithm{josev4.ES256, josev4.EdDSA, josev4.PS256, josev4.RS256} {
		key := newProofKey(t, alg)
		raw := f.token(t, func(c map[string]any) { c["cnf"] = map[string]string{"jkt": key.jkt} })
		req := newRequest(t, "DPoP", raw)
		req.Header.Set("DPoP", key.proof(t, http.MethodGet, resourceURL, testNow, raw))
		if serve(t, h, req).Code == http.StatusOK {
			accepted = append(accepted, string(alg))
		}
	}
	slices.Sort(advertised)
	slices.Sort(accepted)
	if !slices.Equal(advertised, accepted) {
		t.Fatalf("challenge advertises algs %v, verifier accepts %v", advertised, accepted)
	}
}

// TestMiddleware_WWWAuthenticate_AbsentOnSuccess: a passing request
// reaches the handler with the token in its context and no challenge.
func TestMiddleware_WWWAuthenticate_AbsentOnSuccess(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	h := f.verifier(t).Middleware(rs.RequireScope("read"))(okHandler())
	rec := serve(t, h, newRequest(t, "Bearer", f.token(t, nil)))
	if rec.Code != http.StatusOK || rec.Body.String() != "user-1" {
		t.Fatalf("status=%d body=%q, want 200 user-1", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("WWW-Authenticate"); got != "" {
		t.Errorf("WWW-Authenticate = %q on success", got)
	}
}

// TestMiddleware_WWWAuthenticate_ServerFaultHasNoChallenge: a 503 is not
// an authentication failure and carries no challenge.
func TestMiddleware_WWWAuthenticate_ServerFaultHasNoChallenge(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	v := f.verifier(t)
	f.ks.srv.Close()
	rec := serve(t, v.Middleware()(okHandler()), newRequest(t, "Bearer", f.token(t, nil)))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if got := rec.Header().Get("WWW-Authenticate"); got != "" {
		t.Errorf("WWW-Authenticate = %q on a server fault", got)
	}
}

func TestMiddleware_RejectsNilRequirement(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	v := f.verifier(t)
	if !panics(func() { v.Middleware(rs.RequireScope("read"), nil) }) {
		t.Fatal("Middleware accepted a nil Requirement")
	}
}
