package parendpoint_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// TestEndToEnd_PAR_RequestURIBoundToPushingClient pushes a request as
// client A, then presents A's request_uri at /authorize under client B's
// client_id. The OP must answer 400 invalid_request, issue no redirect or
// code, and leave the record unconsumed so the rightful client can still
// redeem it.
//
// Tracks: GHSA-mxv6-xwqj-ww2p (Duende IdentityServer — a pushed request was not bound to the client that authenticated at the PAR endpoint)
func TestEndToEnd_PAR_RequestURIBoundToPushingClient(t *testing.T) {
	t.Parallel()

	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	tk := testkit.NewProvider(t,
		testkit.WithClock(clock),
		testkit.WithOptions(op.WithFeature(feature.PAR)),
	)
	const secret = "rp-bound-secret"
	hasher := clientauth.Argon2id{}
	hash, err := hasher.Hash(secret)
	if err != nil {
		t.Fatalf("Argon2id.Hash: %v", err)
	}
	clientA := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      "rp-bound-a",
		SecretHash:              hash,
		TokenEndpointAuthMethod: "client_secret_basic",
	})
	clientB := tk.RegisterClient(t, testkit.ClientFixture{ID: "rp-bound-b"})

	_, challenge := pkcePair()
	parForm := url.Values{
		"client_id":             {clientA.ID},
		"response_type":         {"code"},
		"redirect_uri":          {clientA.RedirectURIs[0]},
		"scope":                 {"openid"},
		"state":                 {"bound-state"},
		"nonce":                 {"bound-nonce"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	parReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/par", strings.NewReader(parForm.Encode()))
	if err != nil {
		t.Fatalf("NewRequest /par: %v", err)
	}
	parReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	parReq.SetBasicAuth(clientA.ID, secret)
	parResp, err := tk.HTTPClient(nil).Do(parReq)
	if err != nil {
		t.Fatalf("Do /par: %v", err)
	}
	defer parResp.Body.Close()
	if parResp.StatusCode != http.StatusCreated {
		t.Fatalf("/par status=%d want 201", parResp.StatusCode)
	}
	requestURI, _ := decodeJSON(t, parResp)["request_uri"].(string)
	if requestURI == "" {
		t.Fatal("request_uri missing")
	}

	stolen := getAuthorize(t, tk, clientB.ID, requestURI)
	defer stolen.Body.Close()
	if stolen.StatusCode != http.StatusBadRequest {
		t.Fatalf("cross-client /authorize status=%d want 400", stolen.StatusCode)
	}
	if loc := stolen.Header.Get("Location"); loc != "" {
		t.Errorf("cross-client /authorize redirected to %q", loc)
	}
	body := decodeJSON(t, stolen)
	if body["error"] != "invalid_request" {
		t.Errorf("error=%v want invalid_request", body["error"])
	}
	if desc, _ := body["error_description"].(string); !strings.Contains(desc, "client_id does not match") {
		t.Errorf("error_description=%q, want the client-mismatch refusal", desc)
	}

	rec, err := tk.Store.PushedAuthRequests().Find(context.Background(), requestURI)
	if err != nil {
		t.Fatalf("PushedAuthRequests.Find: %v", err)
	}
	if rec.ClientID != clientA.ID || rec.ConsumedAt != nil {
		t.Errorf("record clientID=%q consumedAt=%v, want %q unconsumed", rec.ClientID, rec.ConsumedAt, clientA.ID)
	}

	own := getAuthorize(t, tk, clientA.ID, requestURI)
	defer own.Body.Close()
	if own.StatusCode != http.StatusFound {
		t.Fatalf("owner /authorize status=%d want 302", own.StatusCode)
	}
	// An error redirect to the RP is also a 302; only the interaction
	// hop shows the request was accepted.
	if loc := own.Header.Get("Location"); !strings.HasPrefix(loc, "/oidc/interaction/") {
		t.Errorf("owner /authorize Location=%q, want the interaction hop", loc)
	}
}
