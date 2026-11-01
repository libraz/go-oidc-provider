package jar_test

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/jar"
)

func TestWireError(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
	}{
		{"key source fault", fmt.Errorf("%w: down", jar.ErrKeySourceUnavailable), http.StatusServiceUnavailable, jar.CodeServerError},
		{"client_id mismatch", jar.ErrClientIDMismatch, http.StatusBadRequest, jar.CodeInvalidRequest},
		{"signature failure", jar.ErrSigInvalid, http.StatusBadRequest, jar.CodeInvalidRequestObject},
		{"unclassified", errors.New("other"), http.StatusBadRequest, jar.CodeInvalidRequestObject},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			status, code := jar.WireError(tc.err)
			if status != tc.wantStatus || code != tc.wantCode {
				t.Fatalf("WireError = (%d, %q), want (%d, %q)", status, code, tc.wantStatus, tc.wantCode)
			}
		})
	}
}
