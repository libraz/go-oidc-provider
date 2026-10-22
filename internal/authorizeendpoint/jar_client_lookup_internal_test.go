package authorizeendpoint

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/jar"
	"github.com/libraz/go-oidc-provider/op/store"
)

// TestResolveJARRequest_ClientLookupFaultIsServerError is the request
// object counterpart of the /authorize client lookup: only an unknown
// client is invalid_request, a store fault is 500 server_error.
func TestResolveJARRequest_ClientLookupFaultIsServerError(t *testing.T) {
	t.Parallel()

	rows := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
	}{
		{name: "unknown client", err: store.ErrNotFound, wantStatus: http.StatusBadRequest, wantCode: errInvalidRequest},
		{name: "backend fault", err: errors.New("connection refused"), wantStatus: http.StatusInternalServerError, wantCode: errServerError},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			deps := resolveDeps(Deps{JAR: &jar.Verifier{}, Clients: &stubClientStore{getErr: row.err}})
			rec := httptest.NewRecorder()
			values := url.Values{"client_id": {"rp-1"}, "request": {"eyJhbGciOiJub25lIn0.e30."}}
			_, handled, stop := resolveJARRequestIfNeeded(rec, jarFetchRequest(), deps, "rp-1", values)
			if !handled || !stop {
				t.Fatalf("handled=%v stop=%v, want the lookup failure answered", handled, stop)
			}
			if rec.Code != row.wantStatus {
				t.Fatalf("status=%d want %d", rec.Code, row.wantStatus)
			}
			if code, _ := decodeWireError(t, rec); code != row.wantCode {
				t.Errorf("error=%q want %q", code, row.wantCode)
			}
		})
	}
}
