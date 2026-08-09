package authorizeendpoint_test

// The consent ceremony's Origin gate must not inherit the CORS
// allowlist. That list carries the origin of every registered client's
// redirect_uri — correct for CORS, where an SPA relying party calls
// /token from its callback page — but at /interaction the same entry
// means a page belonging to one client can drive another client's
// consent. This test drives the wire endpoint through the real op.New
// wiring so it measures what the deployment actually enforces.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// otherClientOrigin is the origin of a redirect_uri registered by a
// DIFFERENT client than the one whose interaction is in flight.
const otherClientOrigin = "https://client-b.example.net"

// postInteractionFrom submits a subject factor to interactionURL with
// the supplied Origin header. The state_ref and CSRF token come from a
// prompt the caller already fetched, so the only variable between calls
// is the origin.
func postInteractionFrom(
	t *testing.T,
	f *e2eFlow,
	interactionURL, origin, stateRef string,
	csrfCookie *http.Cookie,
) *http.Response {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"state_ref": stateRef,
		"values":    map[string]string{"subject": "user-origin-gate"},
	})
	if err != nil {
		t.Fatalf("marshal submission: %v", err)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		interactionURL, bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", origin)
	req.Header.Set("X-CSRF-Token", csrfCookie.Value)
	req.AddCookie(csrfCookie)
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatalf("POST interaction: %v", err)
	}
	return resp
}

func TestInteraction_RejectsOriginRegisteredByAnotherClient(t *testing.T) {
	t.Parallel()

	// client-b is seeded through the static-client surface, which is
	// what feeds redirect origins into the CORS allowlist. The
	// interaction in flight below belongs to a different client.
	f := newE2EFlow(t, "rp-origin-gate", testkit.WithOptions(
		op.WithStaticClients(op.PublicClient{
			ID:           "client-b",
			RedirectURIs: []string{otherClientOrigin + "/callback"},
			Scopes:       []string{"openid"},
		}),
	))

	loc := f.authorize(t, f.values())
	interactionURL := f.interactionURL(loc)

	stepResp, err := newGet(interactionURL).Do(f.client)
	if err != nil {
		t.Fatalf("GET interaction: %v", err)
	}
	defer stepResp.Body.Close()
	if stepResp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(stepResp.Body)
		t.Fatalf("interaction GET status=%d body=%s", stepResp.StatusCode, string(dump))
	}
	step := decodeMap(t, stepResp)
	stateRef, _ := step["state_ref"].(string)
	if stateRef == "" {
		t.Fatalf("state_ref missing from interaction step: %v", step)
	}
	csrfCookie := findCookie(stepResp.Cookies(), cookie.CSRFProfile.Name)
	if csrfCookie == nil {
		t.Fatal("csrf cookie missing from interaction step")
	}

	crossClient := postInteractionFrom(t, f, interactionURL, otherClientOrigin, stateRef, csrfCookie)
	defer crossClient.Body.Close()
	if crossClient.StatusCode != http.StatusForbidden {
		dump, _ := io.ReadAll(crossClient.Body)
		t.Fatalf("status=%d want 403 for an origin registered by another client; body=%s",
			crossClient.StatusCode, string(dump))
	}

	// Control: the OP's own origin — where the interaction UI is served
	// from — still passes, so the rejection above is attributable to the
	// origin and not to the request's shape.
	sameOrigin := postInteractionFrom(t, f, interactionURL, f.tk.Issuer, stateRef, csrfCookie)
	defer sameOrigin.Body.Close()
	if sameOrigin.StatusCode == http.StatusForbidden {
		dump, _ := io.ReadAll(sameOrigin.Body)
		t.Fatalf("status=403 for the OP's own origin; body=%s", string(dump))
	}
}
