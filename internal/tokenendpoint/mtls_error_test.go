// White-box tests for the mTLS sentinel -> wire mapping. The mapper is
// package-private, so the tests live in-package to drive it directly.
//
//nolint:testpackage // intentional white-box test for unexported helpers.
package tokenendpoint

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/httpx"
	"github.com/libraz/go-oidc-provider/internal/mtls"
)

// TestWriteMTLSError_Mapping pins each mtls sentinel onto its RFC 6749
// §5.2 / RFC 8705 §3 wire form. The ErrCertUntrusted row is the
// regression guard: a cert that fails chain validation MUST surface as a
// 401 invalid_client rather than falling through to a 500 server_error.
func TestWriteMTLSError_Mapping(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
	}{
		{"no_client_cert", mtls.ErrNoClientCert, http.StatusBadRequest, errInvalidGrant},
		{"cert_malformed", mtls.ErrCertMalformed, http.StatusBadRequest, errInvalidRequest},
		{"cert_source_conflict", mtls.ErrCertSourceConflict, http.StatusBadRequest, errInvalidRequest},
		{"cert_untrusted", mtls.ErrCertUntrusted, http.StatusUnauthorized, "invalid_client"},
		{"thumbprint_mismatch", mtls.ErrThumbprintMismatch, http.StatusBadRequest, errInvalidGrant},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rec := httptest.NewRecorder()
			writeMTLSError(rec, tc.err)

			if rec.Code != tc.wantStatus {
				t.Errorf("status=%d want %d", rec.Code, tc.wantStatus)
			}
			var body httpx.ErrorBody
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode body: %v (%s)", err, rec.Body.String())
			}
			if body.Error != tc.wantCode {
				t.Errorf("error=%q want %q", body.Error, tc.wantCode)
			}
		})
	}
}

// TestWriteMTLSError_UntrustedNotServerError is the sharper form of the
// #18 guard: a cert-untrusted condition must not collapse onto the
// default server_error branch.
func TestWriteMTLSError_UntrustedNotServerError(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	writeMTLSError(rec, mtls.ErrCertUntrusted)

	if rec.Code == http.StatusInternalServerError {
		t.Fatal("ErrCertUntrusted fell through to 500 server_error")
	}
	var body httpx.ErrorBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.Error == errServerError {
		t.Errorf("error=%q want a client-facing code, not server_error", body.Error)
	}
}
