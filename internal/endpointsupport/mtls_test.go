package endpointsupport_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
	"github.com/libraz/go-oidc-provider/internal/mtls"
)

func TestWriteMTLSError_MapsSentinels(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		err        error
		wantStatus int
	}{
		{"malformed", mtls.ErrCertMalformed, http.StatusBadRequest},
		{"untrusted", mtls.ErrCertUntrusted, http.StatusUnauthorized},
		{"other", mtls.ErrCertSourceConflict, http.StatusInternalServerError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rec := httptest.NewRecorder()
			endpointsupport.WriteMTLSError(rec, tc.err)
			if rec.Code != tc.wantStatus {
				t.Errorf("status=%d want %d", rec.Code, tc.wantStatus)
			}
		})
	}
}

func TestExtractMTLSThumbprint_NilVerifierIsUnbound(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	thumb, ok := endpointsupport.ExtractMTLSThumbprint(rec, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/x", http.NoBody), nil)
	if !ok || thumb != "" {
		t.Fatalf("thumb=%q ok=%v want empty, true", thumb, ok)
	}
}
