package dpop_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/dpop"
)

func TestIsNonceErrorMatchesWrappedNonceSentinelsOnly(t *testing.T) {
	t.Parallel()

	if !dpop.IsNonceError(fmt.Errorf("wrapped: %w", dpop.ErrProofNonceMissing)) {
		t.Fatal("IsNonceError did not match wrapped ErrProofNonceMissing")
	}
	if !dpop.IsNonceError(fmt.Errorf("wrapped: %w", dpop.ErrProofNonceInvalid)) {
		t.Fatal("IsNonceError did not match wrapped ErrProofNonceInvalid")
	}
	if dpop.IsNonceError(dpop.ErrProofMalformed) {
		t.Fatal("IsNonceError matched non-nonce DPoP error")
	}
	if dpop.IsNonceError(errors.New("nonce missing")) {
		t.Fatal("IsNonceError matched unrelated error text")
	}
}

func TestNonceSourceFromIssuerAdaptsIssuer(t *testing.T) {
	t.Parallel()

	if got := dpop.NonceSourceFromIssuer(nil); got != nil {
		t.Fatalf("NonceSourceFromIssuer(nil) = %v, want nil", got)
	}
	src := dpop.NonceSourceFromIssuer(staticNonceIssuer("nonce-1"))
	if src == nil {
		t.Fatal("NonceSourceFromIssuer returned nil for non-nil issuer")
	}
	got, err := src.NextNonce(context.Background())
	if err != nil {
		t.Fatalf("NextNonce: %v", err)
	}
	if got != "nonce-1" {
		t.Fatalf("NextNonce = %q, want nonce-1", got)
	}
}

func TestWriteErrorNonceChallengeIncludesFreshNonceWhenAvailable(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	dpop.WriteError(context.Background(), rec, fmt.Errorf("verify: %w", dpop.ErrProofNonceInvalid), staticNonceSource("nonce-2"))

	assertOAuthBody(t, rec, http.StatusBadRequest, "use_dpop_nonce")
	if got := rec.Result().Header.Get("DPoP-Nonce"); got != "nonce-2" {
		t.Fatalf("DPoP-Nonce = %q, want nonce-2", got)
	}
	assertNoStore(t, rec.Result())
}

func TestWriteErrorNonceChallengeStillWritesBodyWhenNonceUnavailable(t *testing.T) {
	t.Parallel()

	for _, src := range []dpop.NonceSource{nil, staticNonceSource(""), failingNonceSource{}} {
		src := src
		t.Run(fmt.Sprintf("%T", src), func(t *testing.T) {
			t.Parallel()

			rec := httptest.NewRecorder()
			dpop.WriteError(context.Background(), rec, dpop.ErrProofNonceMissing, src)
			assertOAuthBody(t, rec, http.StatusBadRequest, "use_dpop_nonce")
			if got := rec.Result().Header.Get("DPoP-Nonce"); got != "" {
				t.Fatalf("DPoP-Nonce = %q, want absent", got)
			}
		})
	}
}

func TestWriteErrorMapsDPoPSentinelsToOAuthEnvelope(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		err        error
		status     int
		code       string
		wantHeader string
	}{
		{name: "malformed", err: dpop.ErrProofMalformed, status: http.StatusBadRequest, code: "invalid_request"},
		{name: "missing jti", err: dpop.ErrProofMissingJTI, status: http.StatusBadRequest, code: "invalid_request"},
		{name: "signature", err: dpop.ErrProofSignature, status: http.StatusBadRequest, code: "invalid_request"},
		{name: "iat window", err: dpop.ErrProofIatWindow, status: http.StatusBadRequest, code: "invalid_request"},
		{name: "replayed", err: dpop.ErrProofReplayed, status: http.StatusBadRequest, code: "invalid_request"},
		{name: "htu", err: dpop.ErrProofHTUMismatch, status: http.StatusBadRequest, code: "invalid_request"},
		{name: "htm", err: dpop.ErrProofHTMMismatch, status: http.StatusBadRequest, code: "invalid_request"},
		{name: "ath", err: dpop.ErrProofATHMismatch, status: http.StatusBadRequest, code: "invalid_request"},
		{name: "unknown", err: errors.New("transport fault"), status: http.StatusInternalServerError, code: "server_error"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rec := httptest.NewRecorder()
			dpop.WriteError(context.Background(), rec, fmt.Errorf("wrapped: %w", tc.err), staticNonceSource("unused"))
			assertOAuthBody(t, rec, tc.status, tc.code)
			if got := rec.Result().Header.Get("DPoP-Nonce"); got != "" {
				t.Fatalf("DPoP-Nonce = %q, want absent for non-nonce error", got)
			}
		})
	}
}

type staticNonceIssuer string

func (s staticNonceIssuer) IssueNonce() string { return string(s) }

type staticNonceSource string

func (s staticNonceSource) NextNonce(context.Context) (string, error) { return string(s), nil }

type failingNonceSource struct{}

func (failingNonceSource) NextNonce(context.Context) (string, error) {
	return "", errors.New("nonce issuer unavailable")
}

func assertOAuthBody(tb testing.TB, rec *httptest.ResponseRecorder, status int, code string) {
	tb.Helper()

	if rec.Code != status {
		tb.Fatalf("status = %d, want %d; body=%s", rec.Code, status, rec.Body.String())
	}
	var body struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		tb.Fatalf("decode body: %v", err)
	}
	if body.Error != code {
		tb.Fatalf("error = %q, want %q; body=%s", body.Error, code, rec.Body.String())
	}
}

func assertNoStore(tb testing.TB, res *http.Response) {
	tb.Helper()

	if got := res.Header.Get("Cache-Control"); got != "no-store" {
		tb.Fatalf("Cache-Control = %q, want no-store", got)
	}
	if got := res.Header.Get("Pragma"); got != "no-cache" {
		tb.Fatalf("Pragma = %q, want no-cache", got)
	}
}
