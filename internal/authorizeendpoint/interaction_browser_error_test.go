package authorizeendpoint_test

import (
	"context"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// interactionCSRFMismatchJSON is the exact envelope an /interaction/{uid}
// CSRF rejection puts on the wire for a client that asked for JSON. It is
// compared byte for byte: the endpoint gained HTML content negotiation,
// and a SPA whose fetch() parses this response must not have to change a
// single character because of it. The trailing newline is what
// [json.Encoder] appends.
const interactionCSRFMismatchJSON = `{"error":"invalid_request","error_description":"csrf token mismatch"}` + "\n"

// TestEndToEnd_InteractionFailureNegotiatesHTMLAndJSON covers the
// /interaction/{uid} failure surface under a server-rendered Driver.
//
// The interaction endpoint is not a SPA-only surface: with an HTML
// Driver the browser navigates to it and posts ordinary forms, so a
// failure answered with a raw JSON envelope surfaces to the user as
// unstyled text where a page should be. Both shapes are pinned in one
// test because the requirement is a pair — HTML for the browser, and the
// unchanged envelope for everything that asks for JSON.
func TestEndToEnd_InteractionFailureNegotiatesHTMLAndJSON(t *testing.T) {
	t.Parallel()

	clock := fakeClock{now: time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)}
	tk := testkit.NewProvider(t,
		testkit.WithClock(clock),
		testkit.WithOptions(op.WithInteractionDriver(interaction.HTMLDriver{})),
	)

	const secret = "rp-secret"
	hasher := clientauth.Argon2id{}
	hash, err := hasher.Hash(secret)
	if err != nil {
		t.Fatalf("Argon2id.Hash: %v", err)
	}
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      "rp-interaction-negotiation",
		SecretHash:              hash,
		RedirectURIs:            []string{"https://rp.testkit.invalid/callback"},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	client := tk.HTTPClient(jar)
	ctx := context.Background()

	authResp, err := newGet(tk.Server.URL + "/oidc/auth?" + e2eAuthorizeValues(rp.ID, rp.RedirectURIs[0]).Encode()).
		Do(client)
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	t.Cleanup(func() { _ = authResp.Body.Close() })
	if authResp.StatusCode != http.StatusFound {
		t.Fatalf("authorize status=%d, want 302", authResp.StatusCode)
	}
	location, err := authResp.Location()
	if err != nil {
		t.Fatalf("Location: %v", err)
	}
	interactionURL := tk.Server.URL + location.Path
	interactionCookie := findCookie(authResp.Cookies(), cookie.InteractionProfile.Name)
	if interactionCookie == nil {
		t.Fatal("__Host-oidc_interaction cookie missing on authorize 302")
	}

	stepResp, err := doGetWithCookies(ctx, client, interactionURL, interactionCookie)
	if err != nil {
		t.Fatalf("GET interaction: %v", err)
	}
	t.Cleanup(func() { _ = stepResp.Body.Close() })
	if stepResp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(stepResp.Body)
		t.Fatalf("interaction GET status=%d body=%s", stepResp.StatusCode, string(dump))
	}
	csrfCookie := findCookie(stepResp.Cookies(), cookie.CSRFProfile.Name)
	if csrfCookie == nil {
		t.Fatal("csrf cookie missing on the first prompt")
	}

	// postWithMismatchedCSRF drives one deterministic failure branch of
	// POST /interaction/{uid}: the submitted token does not match the
	// cookie, so the handler answers 403 before touching the body or the
	// orchestrator. The branch is reached identically on every call, which
	// is what lets the two Accept headers be compared against each other.
	postWithMismatchedCSRF := func(t *testing.T, accept string) *http.Response {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, interactionURL, http.NoBody)
		if err != nil {
			t.Fatalf("NewRequest POST interaction: %v", err)
		}
		req.Header.Set("Origin", tk.Issuer)
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		req.Header.Set("X-CSRF-Token", "not-the-cookie-value")
		req.AddCookie(interactionCookie)
		req.AddCookie(csrfCookie)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("POST interaction: %v", err)
		}
		return resp
	}

	t.Run("a navigating browser gets an HTML document", func(t *testing.T) {
		t.Parallel()
		resp := postWithMismatchedCSRF(t, "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("status=%d, want 403", resp.StatusCode)
		}
		if got := resp.Header.Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
			t.Errorf("Content-Type=%q, want a text/html prefix", got)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		text := string(body)
		if !strings.Contains(text, `data-code="invalid_request"`) {
			t.Errorf("body carries no rendered error markup:\n%s", text)
		}
		if strings.HasPrefix(strings.TrimSpace(text), "{") {
			t.Errorf("body is a JSON envelope, not a document:\n%s", text)
		}
	})

	t.Run("a JSON client gets the byte-identical envelope", func(t *testing.T) {
		t.Parallel()
		resp := postWithMismatchedCSRF(t, "application/json")
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("status=%d, want 403", resp.StatusCode)
		}
		if got := resp.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type=%q, want application/json", got)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		if string(body) != interactionCSRFMismatchJSON {
			t.Errorf("body=%q, want %q (the envelope must be unchanged byte for byte)",
				string(body), interactionCSRFMismatchJSON)
		}
	})

	t.Run("a client that sends no Accept keeps the envelope", func(t *testing.T) {
		t.Parallel()
		// XHR and cURL usually send no Accept at all. The default has to
		// stay JSON or the negotiation would silently reshape the
		// responses of clients that never asked for anything.
		resp := postWithMismatchedCSRF(t, "")
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		if string(body) != interactionCSRFMismatchJSON {
			t.Errorf("body=%q, want %q", string(body), interactionCSRFMismatchJSON)
		}
	})
}
