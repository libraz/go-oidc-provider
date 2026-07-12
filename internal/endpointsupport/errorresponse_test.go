package endpointsupport_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
)

func TestBearerCredentialFromHeaderReportsCanonicalScheme(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		header     string
		wantToken  string
		wantScheme string
		wantOK     bool
	}{
		{name: "bearer", header: "bearer token-1", wantToken: "token-1", wantScheme: endpointsupport.BearerSchemeBearer, wantOK: true},
		{name: "dpop", header: "dPoP token-2", wantToken: "token-2", wantScheme: endpointsupport.BearerSchemeDPoP, wantOK: true},
		{name: "trim token", header: "DPoP   token-3  ", wantToken: "token-3", wantScheme: endpointsupport.BearerSchemeDPoP, wantOK: true},
		{name: "unknown", header: "Basic token", wantOK: false},
		{name: "empty token", header: "Bearer   ", wantOK: false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			token, scheme, ok := endpointsupport.BearerCredentialFromHeader(tc.header)
			if token != tc.wantToken || scheme != tc.wantScheme || ok != tc.wantOK {
				t.Fatalf("BearerCredentialFromHeader(%q) = (%q, %q, %v), want (%q, %q, %v)",
					tc.header, token, scheme, ok, tc.wantToken, tc.wantScheme, tc.wantOK)
			}
		})
	}
}

func TestLooksLikeJWTRequiresCompactJWSWithJSONObjectHeader(t *testing.T) {
	t.Parallel()

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"user"}`))
	signature := base64.RawURLEncoding.EncodeToString([]byte("sig"))
	if token := header + "." + payload + "." + signature; !endpointsupport.LooksLikeJWT(token) {
		t.Fatalf("LooksLikeJWT rejected valid compact JWS shape")
	}

	cases := []string{
		"",
		"opaque-token",
		header + "." + payload,
		"." + payload + "." + signature,
		base64.RawURLEncoding.EncodeToString([]byte(`[]`)) + "." + payload + "." + signature,
		"not-base64." + payload + "." + signature,
		base64.RawURLEncoding.EncodeToString([]byte(`{`)) + "." + payload + "." + signature,
	}
	for _, token := range cases {
		token := token
		t.Run(token, func(t *testing.T) {
			t.Parallel()
			if endpointsupport.LooksLikeJWT(token) {
				t.Fatalf("LooksLikeJWT(%q) = true, want false", token)
			}
		})
	}
}

func TestWriteAuthnErrorMapsSentinelsToOAuthEnvelopes(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name          string
		err           error
		usedBasic     bool
		wantStatus    int
		wantCode      string
		wantChallenge string
	}{
		{
			name:          "no credentials with basic challenge",
			err:           clientauth.ErrNoCredentials,
			usedBasic:     true,
			wantStatus:    http.StatusUnauthorized,
			wantCode:      endpointsupport.ErrInvalidClient,
			wantChallenge: `Basic realm="oidc"`,
		},
		{
			name:       "ambiguous credentials",
			err:        clientauth.ErrAmbiguousCredentials,
			wantStatus: http.StatusBadRequest,
			wantCode:   endpointsupport.ErrInvalidRequest,
		},
		{
			name:       "unsupported method",
			err:        clientauth.ErrUnsupportedMethod,
			wantStatus: http.StatusBadRequest,
			wantCode:   endpointsupport.ErrInvalidRequest,
		},
		{
			name:       "invalid credentials",
			err:        clientauth.ErrCredentialsInvalid,
			wantStatus: http.StatusUnauthorized,
			wantCode:   endpointsupport.ErrInvalidClient,
		},
		{
			name:       "assertion replayed",
			err:        clientauth.ErrAssertionReplayed,
			wantStatus: http.StatusUnauthorized,
			wantCode:   endpointsupport.ErrInvalidClient,
		},
		{
			name:       "unknown fault",
			err:        errors.New("database unavailable"),
			wantStatus: http.StatusInternalServerError,
			wantCode:   endpointsupport.ErrServerError,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rec := httptest.NewRecorder()
			endpointsupport.WriteAuthnError(rec, tc.err, tc.usedBasic)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if got := rec.Result().Header.Get("WWW-Authenticate"); got != tc.wantChallenge {
				t.Fatalf("WWW-Authenticate = %q, want %q", got, tc.wantChallenge)
			}
			assertNoStoreHeaders(t, rec.Result())
			var body struct {
				Error string `json:"error"`
			}
			if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
				t.Fatalf("decode body: %v", err)
			}
			if body.Error != tc.wantCode {
				t.Fatalf("error = %q, want %q", body.Error, tc.wantCode)
			}
		})
	}
}

func TestStampNoStore(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	endpointsupport.StampNoStore(rec)
	assertNoStoreHeaders(t, rec.Result())
}

func assertNoStoreHeaders(tb testing.TB, res *http.Response) {
	tb.Helper()
	if got := res.Header.Get("Cache-Control"); got != "no-store" {
		tb.Fatalf("Cache-Control = %q, want no-store", got)
	}
	if got := res.Header.Get("Pragma"); got != "no-cache" {
		tb.Fatalf("Pragma = %q, want no-cache", got)
	}
}
