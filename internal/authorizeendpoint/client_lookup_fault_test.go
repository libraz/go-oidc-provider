package authorizeendpoint_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/authorizeendpoint"
	"github.com/libraz/go-oidc-provider/op/store"
)

// faultingClients answers every lookup with err.
type faultingClients struct {
	store.ClientStore
	err error
}

func (f faultingClients) GetClient(context.Context, string) (*store.Client, error) {
	return nil, f.err
}

// TestAuthorize_ClientLookupFaultIsServerError pins that only an unknown
// client is reported as an unregistered client_id: a client store that
// could not answer yields a pre-redirect 500 server_error.
func TestAuthorize_ClientLookupFaultIsServerError(t *testing.T) {
	t.Parallel()

	rows := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
	}{
		{name: "unknown client", err: store.ErrNotFound, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "backend fault", err: errors.New("connection refused"), wantStatus: http.StatusInternalServerError, wantCode: "server_error"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, func(d *authorizeendpoint.Deps) {
				d.Clients = faultingClients{ClientStore: d.Clients, err: row.err}
			})
			resp := doAuthorizeGET(t, h, goodAuthorizeValues())
			defer resp.Body.Close()
			if resp.StatusCode != row.wantStatus {
				t.Fatalf("status=%d want %d", resp.StatusCode, row.wantStatus)
			}
			var body map[string]any
			if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
				t.Fatalf("decode body: %v", err)
			}
			if got, _ := body["error"].(string); got != row.wantCode {
				t.Errorf("error=%q want %q", got, row.wantCode)
			}
		})
	}
}
