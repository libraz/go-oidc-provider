package jar

import (
	"fmt"
	"net/http"
	"testing"
)

func TestWireError(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
	}{
		{"key source fault", fmt.Errorf("%w: down", ErrKeySourceUnavailable), http.StatusServiceUnavailable, CodeServerError},
		{"client_id mismatch", ErrClientIDMismatch, http.StatusBadRequest, CodeInvalidRequest},
		{"signature failure", ErrSigInvalid, http.StatusBadRequest, CodeInvalidRequestObject},
		{"unclassified", fmt.Errorf("other"), http.StatusBadRequest, CodeInvalidRequestObject},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			status, code := WireError(tc.err)
			if status != tc.wantStatus || code != tc.wantCode {
				t.Fatalf("WireError = (%d, %q), want (%d, %q)", status, code, tc.wantStatus, tc.wantCode)
			}
		})
	}
}
